use crate::{
    simulate::{
        engine::{EngineDefinition, InitContext},
        processed::ProcessedHeight,
        reporter::MonitorReporter,
    },
    stateful::{
        db::{
            qmdb::resolver as qmdb_resolver, DatabaseSet, Merkleized as _, SyncEngineConfig,
            Unmerkleized as _,
        },
        Application, Config as StatefulConfig, Startup, StateSyncConfig, Stateful as StatefulActor,
    },
};
use commonware_broadcast::buffered;
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    marshal::{
        self,
        ancestry::{AncestorStream, BlockProvider},
        core::Actor as MarshalActor,
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
        Identifier as MarshalIdentifier,
    },
    simplex::{
        self,
        config::ForwardingPolicy,
        elector::RoundRobin,
        mocks::scheme::{self as scheme_mocks, Scheme as MockScheme},
        types::Context,
    },
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    Block as ConsensusBlock, CertifiableBlock, Heightable,
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, ConstantProvider, Scheme as _},
    ed25519, sha256, Digest as _, Digestible, Hasher, Sha256, Signer as _,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, Buf, BufMut, Clock, Handle, Metrics, Quota, Spawner, Storage,
};
use commonware_storage::{
    archive::immutable,
    mmr::Location,
    qmdb::{
        any::{unordered::fixed, FixedConfig},
        sync::Target,
    },
    translator::TwoCap,
};
use commonware_utils::{
    sync::{AsyncRwLock, Mutex},
    test_rng, NZUsize, NZU16, NZU64,
};
use rand::Rng;
use std::{
    collections::{BTreeMap, HashMap},
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

const EPOCH_LENGTH: NonZeroU64 = NZU64!(u64::MAX);
const NAMESPACE: &[u8] = b"stateful_e2e_test";
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);
const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

/// The QMDB database type used by the e2e tests.
type Qmdb<E> = fixed::Db<E, sha256::Digest, sha256::Digest, Sha256, TwoCap>;

pub(crate) type MockDatabaseSet<E> = Arc<AsyncRwLock<Qmdb<E>>>;
type MarshalMailbox = marshal::core::Mailbox<MockScheme<ed25519::PublicKey>, Standard<Block>>;

#[derive(Clone)]
pub(crate) struct MockValidatorState {
    marshal: MarshalMailbox,
    startup_sync_height: Option<u64>,
}

impl MockValidatorState {
    pub(crate) async fn digest_at_height(&self, height: u64) -> Option<sha256::Digest> {
        self.marshal
            .get_info(marshal::Identifier::Height(Height::new(height)))
            .await
            .map(|(_, digest)| digest)
    }

    pub(crate) const fn startup_sync_height(&self) -> Option<u64> {
        self.startup_sync_height
    }
}

impl ProcessedHeight for MockValidatorState {
    async fn processed_height(&self) -> u64 {
        self.marshal
            .get_processed_height()
            .await
            .map_or(0, |height| height.get())
    }
}

/// Deterministic key for the block counter.
fn counter_key() -> sha256::Digest {
    Sha256::hash(b"counter")
}

/// Deterministic key for a height marker.
fn height_key(height: u64) -> sha256::Digest {
    Sha256::hash(&height.to_be_bytes())
}

/// Encode a u64 as a digest (zero-padded).
fn u64_to_digest(v: u64) -> sha256::Digest {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_be_bytes());
    sha256::Digest::from(bytes)
}

/// Decode a u64 from a digest (first 8 bytes).
fn digest_to_u64(d: &sha256::Digest) -> u64 {
    let bytes: &[u8] = d.as_ref();
    u64::from_be_bytes(bytes[..8].try_into().unwrap())
}

/// A block carrying key-value mutations with embedded consensus context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block {
    context: Context<sha256::Digest, ed25519::PublicKey>,
    parent: sha256::Digest,
    height: Height,
    digest: sha256::Digest,
    state_root: sha256::Digest,
    inactivity_floor: Location,
    op_count: Location,
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.digest.write(buf);
        self.state_root.write(buf);
        self.inactivity_floor.write(buf);
        self.op_count.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.digest.encode_size()
            + self.state_root.encode_size()
            + self.inactivity_floor.encode_size()
            + self.op_count.encode_size()
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let context = Context::read(buf)?;
        let parent = sha256::Digest::read(buf)?;
        let height = Height::read(buf)?;
        let digest = sha256::Digest::read(buf)?;
        let state_root = sha256::Digest::read(buf)?;
        let inactivity_floor = Location::read(buf)?;
        let op_count = Location::read(buf)?;
        Ok(Self {
            context,
            parent,
            height,
            digest,
            state_root,
            inactivity_floor,
            op_count,
        })
    }
}

impl Digestible for Block {
    type Digest = sha256::Digest;

    fn digest(&self) -> sha256::Digest {
        self.digest
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for Block {
    fn parent(&self) -> sha256::Digest {
        self.parent
    }
}

impl CertifiableBlock for Block {
    type Context = Context<sha256::Digest, ed25519::PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl Block {
    fn genesis() -> Self {
        let digest = Sha256::hash(b"genesis");
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::zero(), sha256::Digest::EMPTY),
            },
            parent: sha256::Digest::EMPTY,
            height: Height::zero(),
            digest,
            state_root: sha256::Digest::EMPTY,
            inactivity_floor: Location::new(0),
            op_count: Location::new(1),
        }
    }
}

/// A stateful application that increments a counter each block.
#[derive(Clone)]
struct App {
    genesis: Block,
}

impl App {
    fn new() -> Self {
        Self {
            genesis: Block::genesis(),
        }
    }

    /// Execute a block: increment "counter" and write `height -> height_val`.
    async fn execute<E: Rng + Spawner + Metrics + Clock + Storage>(
        height: Height,
        mut batches: <MockDatabaseSet<E> as DatabaseSet<E>>::Unmerkleized,
    ) -> <MockDatabaseSet<E> as DatabaseSet<E>>::Merkleized {
        // Read current counter
        let current: u64 = batches
            .get(&counter_key())
            .await
            .unwrap()
            .map_or(0, |v| digest_to_u64(&v));
        let next = current + 1;
        batches = batches.write(counter_key(), Some(u64_to_digest(next)));

        // Write height marker
        batches = batches.write(height_key(height.get()), Some(u64_to_digest(height.get())));

        batches.merkleize().await.unwrap()
    }
}

impl<E: Rng + Spawner + Metrics + Clock + Storage> Application<E> for App {
    type SigningScheme = MockScheme<ed25519::PublicKey>;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block;
    type Databases = MockDatabaseSet<E>;
    type InputProvider = ();

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        _input: &mut Self::InputProvider,
    ) -> Option<(Self::Block, <Self::Databases as DatabaseSet<E>>::Merkleized)> {
        let parent = ancestry.peek()?;
        let parent_digest = parent.digest();
        let height = Height::new(parent.height().get() + 1);
        let (_, ctx) = &context;

        let merkleized = Self::execute(height, batches).await;
        let state_root = merkleized.root();
        let inactivity_floor = merkleized.inactivity_floor();
        let op_count = merkleized.size();

        let mut hasher = Sha256::new();
        hasher.update(b"e2e_block");
        hasher.update(&ctx.encode());
        hasher.update(parent_digest.as_ref());
        hasher.update(&height.get().to_be_bytes());
        hasher.update(state_root.as_ref());
        hasher.update(&(*inactivity_floor).to_be_bytes());
        hasher.update(&(*op_count).to_be_bytes());
        let digest = hasher.finalize();

        let block = Block {
            context: ctx.clone(),
            parent: parent_digest,
            height,
            digest,
            state_root,
            inactivity_floor,
            op_count,
        };
        Some((block, merkleized))
    }

    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        _context: (E, Self::Context),
        ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let tip = ancestry.peek()?;
        let height = tip.height();

        let merkleized = Self::execute(height, batches).await;
        let computed_root = merkleized.root();
        let computed_inactivity_floor = merkleized.inactivity_floor();
        let computed_op_count = merkleized.size();

        if computed_root != tip.state_root
            || computed_inactivity_floor != tip.inactivity_floor
            || computed_op_count != tip.op_count
        {
            return None;
        }

        Some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        Self::execute(block.height(), batches).await
    }

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        Target {
            root: block.state_root,
            range: block.inactivity_floor..block.op_count,
        }
    }
}

/// Engine definition implementing `EngineDefinition` for the simulation harness.
#[derive(Clone)]
pub(crate) struct ConsensusEngine {
    participants: Vec<ed25519::PublicKey>,
    schemes: Vec<MockScheme<ed25519::PublicKey>>,
    enable_late_join_state_sync: bool,
    marshal_mailboxes: Arc<Mutex<BTreeMap<ed25519::PublicKey, MarshalMailbox>>>,
}

impl ConsensusEngine {
    pub(crate) fn new(n: u32) -> Self {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, n);

        Self {
            participants,
            schemes,
            enable_late_join_state_sync: false,
            marshal_mailboxes: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(crate) fn with_late_join_state_sync(mut self) -> Self {
        self.enable_late_join_state_sync = true;
        self
    }

    async fn fetch_majority_sync_target(
        &self,
        context: &impl Clock,
        me: &ed25519::PublicKey,
    ) -> Option<Block> {
        for _ in 0..20 {
            let mailboxes = {
                let guard = self.marshal_mailboxes.lock();
                guard
                    .iter()
                    .filter(|(peer, _)| *peer != me)
                    .map(|(peer, mailbox)| (peer.clone(), mailbox.clone()))
                    .collect::<Vec<_>>()
            };

            if mailboxes.is_empty() {
                context.sleep(Duration::from_millis(100)).await;
                continue;
            }

            let mut latest_heights = Vec::new();
            for (_peer, mailbox) in mailboxes {
                if let Some((height, _)) = mailbox.get_info(MarshalIdentifier::Latest).await {
                    latest_heights.push((mailbox, height));
                }
            }

            if latest_heights.is_empty() {
                context.sleep(Duration::from_millis(100)).await;
                continue;
            }

            let required = latest_heights.len() / 2 + 1;

            // Pick a height that at least `required` peers have reached.
            let mut heights: Vec<Height> = latest_heights.iter().map(|(_, h)| *h).collect();
            heights.sort();
            let quorum_height = heights[heights.len() - required];

            let mut digest_counts: HashMap<sha256::Digest, usize> = HashMap::new();
            let mut digest_candidates: HashMap<sha256::Digest, Vec<MarshalMailbox>> =
                HashMap::new();
            for (mailbox, latest_height) in latest_heights {
                if latest_height < quorum_height {
                    continue;
                }
                if let Some((_, digest)) = mailbox
                    .get_info(MarshalIdentifier::Height(quorum_height))
                    .await
                {
                    *digest_counts.entry(digest).or_insert(0) += 1;
                    digest_candidates.entry(digest).or_default().push(mailbox);
                }
            }

            let majority_digest = digest_counts
                .into_iter()
                .filter(|(_, count)| *count >= required)
                .max_by_key(|(_, count)| *count)
                .map(|(digest, _)| digest);

            if let Some(digest) = majority_digest {
                if let Some(mailboxes) = digest_candidates.get(&digest) {
                    for mailbox in mailboxes {
                        if let Some(block) =
                            mailbox.get_block(MarshalIdentifier::Digest(digest)).await
                        {
                            return Some(block);
                        }
                    }
                }
            }

            context.sleep(Duration::from_millis(100)).await;
        }

        None
    }
}

impl EngineDefinition for ConsensusEngine {
    type PublicKey = ed25519::PublicKey;
    type Engine = Handle<()>;
    type State = MockValidatorState;

    fn participants(&self) -> Vec<Self::PublicKey> {
        self.participants.clone()
    }

    fn channels(&self) -> Vec<(u64, Quota)> {
        vec![
            (0, TEST_QUOTA), // votes
            (1, TEST_QUOTA), // certificates
            (2, TEST_QUOTA), // resolver
            (3, TEST_QUOTA), // backfill
            (4, TEST_QUOTA), // broadcast
            (5, TEST_QUOTA), // qmdb sync resolver
        ]
    }

    async fn init(&self, ctx: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            public_key,
            oracle,
            channels,
            participants: _,
            monitor,
        } = ctx;

        let scheme = self.schemes[index].clone();

        let partition_prefix = format!("validator-{index}");
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

        // QMDB database config (created by Stateful::start)
        let db_config = FixedConfig {
            mmr_journal_partition: format!("{partition_prefix}-qmdb-mmr-journal"),
            mmr_metadata_partition: format!("{partition_prefix}-qmdb-mmr-metadata"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: IO_BUFFER_SIZE,
            log_journal_partition: format!("{partition_prefix}-qmdb-log-journal"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: IO_BUFFER_SIZE,
            translator: TwoCap,
            thread_pool: None,
            page_cache: page_cache.clone(),
        };

        // Destructure the 6 channels.
        let mut channels = channels.into_iter();
        let vote_network = channels.next().unwrap();
        let certificate_network = channels.next().unwrap();
        let resolver_network = channels.next().unwrap();
        let backfill_network = channels.next().unwrap();
        let broadcast_network = channels.next().unwrap();
        let qmdb_resolver_network = channels.next().unwrap();

        // Marshal resolver
        let resolver_cfg = marshal_resolver::Config {
            public_key: public_key.clone(),
            peer_provider: oracle.manager(),
            blocker: oracle.control(public_key.clone()),
            mailbox_size: 100,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = marshal_resolver::init(&context, resolver_cfg, backfill_network);

        // Buffered broadcast engine
        let broadcast_config = buffered::Config {
            public_key: public_key.clone(),
            mailbox_size: 100,
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        };
        let (broadcast_engine, buffer) = buffered::Engine::new(context.clone(), broadcast_config);
        broadcast_engine.start(broadcast_network);

        // Immutable archives
        let finalizations_by_height = immutable::Archive::init(
            context.with_label("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalizations-metadata"),
                freezer_table_partition: format!("{partition_prefix}-finalizations-freezer-table"),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-finalizations-freezer-key"),
                freezer_key_page_cache: page_cache.clone(),
                freezer_value_partition: format!("{partition_prefix}-finalizations-freezer-value"),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalizations-ordinal"),
                items_per_section: NZU64!(10),
                codec_config: MockScheme::<ed25519::PublicKey>::certificate_codec_config_unbounded(
                ),
                replay_buffer: IO_BUFFER_SIZE,
                freezer_key_write_buffer: IO_BUFFER_SIZE,
                freezer_value_write_buffer: IO_BUFFER_SIZE,
                ordinal_write_buffer: IO_BUFFER_SIZE,
            },
        )
        .await
        .expect("failed to initialize finalizations archive");

        let finalized_blocks = immutable::Archive::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-blocks-metadata"),
                freezer_table_partition: format!("{partition_prefix}-blocks-freezer-table"),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-blocks-freezer-key"),
                freezer_key_page_cache: page_cache.clone(),
                freezer_value_partition: format!("{partition_prefix}-blocks-freezer-value"),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-blocks-ordinal"),
                items_per_section: NZU64!(10),
                codec_config: (),
                replay_buffer: IO_BUFFER_SIZE,
                freezer_key_write_buffer: IO_BUFFER_SIZE,
                freezer_value_write_buffer: IO_BUFFER_SIZE,
                ordinal_write_buffer: IO_BUFFER_SIZE,
            },
        )
        .await
        .expect("failed to initialize blocks archive");

        // Marshal actor
        let provider = ConstantProvider::new(scheme.clone());
        let marshal_config = marshal::Config {
            provider,
            epocher: FixedEpocher::new(EPOCH_LENGTH),
            partition_prefix: partition_prefix.clone(),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            prunable_items_per_section: NZU64!(10),
            page_cache: page_cache.clone(),
            replay_buffer: IO_BUFFER_SIZE,
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            block_codec_config: (),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        };
        let (marshal_actor, marshal_mailbox, _last_height) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                context.clone(),
                finalizations_by_height,
                finalized_blocks,
                marshal_config,
            )
            .await;
        self.marshal_mailboxes
            .lock()
            .insert(public_key.clone(), marshal_mailbox.clone());

        // QMDB state-sync resolver.
        let qmdb_resolver_actor =
            qmdb_resolver::Actor::<_, ed25519::PublicKey, _, _, Qmdb<_>, _, _>::new(
                context.clone().with_label("qmdb_resolver"),
                qmdb_resolver::Config {
                    peer_provider: oracle.manager(),
                    blocker: oracle.control(public_key.clone()),
                    database: None,
                    mailbox_size: 100,
                    me: Some(public_key.clone()),
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                    fetch_retry_timeout: Duration::from_millis(100),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
        let (_qmdb_resolver_handle, qmdb_sync_resolver) =
            qmdb_resolver_actor.start(qmdb_resolver_network);

        let (startup, startup_sync_height) = if self.enable_late_join_state_sync {
            self.fetch_majority_sync_target(&context, public_key)
                .await
                .map_or((Startup::Fresh, None), |block| {
                    let height = block.height().get();
                    (Startup::Sync { block }, Some(height))
                })
        } else {
            (Startup::Fresh, None)
        };

        // Stateful actor
        let app = App::new();
        let (stateful_actor, stateful_mailbox) = StatefulActor::init(
            context.clone(),
            StatefulConfig {
                app,
                db_config,
                input_provider: (),
                marshal: marshal_mailbox.clone(),
                mailbox_size: 100,
                state_sync: StateSyncConfig {
                    partition_prefix: partition_prefix.clone(),
                    startup,
                    resolvers: qmdb_sync_resolver.clone(),
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(16),
                        apply_batch_size: 64,
                        max_outstanding_requests: 8,
                        update_channel_size: NZUsize!(256),
                    },
                },
            },
        );

        // Deferred wrapper
        let deferred = Deferred::new(
            context.clone(),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );

        // Marshal reporter: stateful mailbox, wrapped by monitor.
        let marshal_reporters = MonitorReporter::new(public_key.clone(), monitor, stateful_mailbox);

        // Start marshal actor with monitored reporters.
        marshal_actor.start(marshal_reporters, buffer, resolver);

        // Initialize stateful from marshal's processed frontier.
        stateful_actor.start();

        // Simplex engine
        let simplex_config = simplex::Config {
            scheme,
            elector: RoundRobin::<Sha256>::default(),
            blocker: oracle.control(public_key.clone()),
            automaton: deferred.clone(),
            relay: deferred,
            reporter: marshal_mailbox.clone(),
            strategy: Sequential,
            partition: format!("{partition_prefix}-simplex"),
            mailbox_size: 100,
            epoch: Epoch::zero(),
            replay_buffer: IO_BUFFER_SIZE,
            write_buffer: IO_BUFFER_SIZE,
            page_cache,
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_millis(500),
            activity_timeout: ViewDelta::new(10),
            skip_timeout: ViewDelta::new(5),
            fetch_timeout: Duration::from_secs(2),
            fetch_concurrent: 3,
            forwarding: ForwardingPolicy::Disabled,
        };

        let engine = simplex::Engine::new(context, simplex_config);
        let handle = engine.start(vote_network, certificate_network, resolver_network);

        (
            handle,
            MockValidatorState {
                marshal: marshal_mailbox,
                startup_sync_height,
            },
        )
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        engine
    }
}
