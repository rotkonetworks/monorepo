use crate::{
    simulate::{
        engine::{EngineDefinition, InitContext},
        processed::ProcessedHeight,
        reporter::MonitorReporter,
    },
    stateful::{
        db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
        Application, Config as StatefulConfig, Stateful as StatefulActor,
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
    buffer::paged::CacheRef, deterministic, Buf, BufMut, Clock, Handle, Metrics, Quota, Spawner,
};
use commonware_storage::{
    archive::immutable,
    qmdb::any::{unordered::fixed, FixedConfig},
    translator::TwoCap,
};
use commonware_utils::{sync::AsyncRwLock, test_rng, NZUsize, NZU16, NZU64};
use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

const EPOCH_LENGTH: NonZeroU64 = NZU64!(u64::MAX);
const NAMESPACE: &[u8] = b"stateful_e2e_test";
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

/// The QMDB database type used by the e2e tests.
type Qmdb = fixed::Db<deterministic::Context, sha256::Digest, sha256::Digest, Sha256, TwoCap>;

pub(crate) type MockDatabaseSet = Arc<AsyncRwLock<Qmdb>>;
type MarshalMailbox = marshal::core::Mailbox<MockScheme<ed25519::PublicKey>, Standard<Block>>;

#[derive(Clone)]
pub(crate) struct MockValidatorState {
    _db: MockDatabaseSet,
    marshal: MarshalMailbox,
}

impl MockValidatorState {
    pub(crate) async fn digest_at_height(&self, height: u64) -> Option<sha256::Digest> {
        self.marshal
            .get_info(marshal::Identifier::Height(Height::new(height)))
            .await
            .map(|(_, digest)| digest)
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
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.digest.write(buf);
        self.state_root.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.digest.encode_size()
            + self.state_root.encode_size()
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
        Ok(Self {
            context,
            parent,
            height,
            digest,
            state_root,
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
    async fn execute(
        height: Height,
        mut batches: <MockDatabaseSet as DatabaseSet>::Unmerkleized,
    ) -> <MockDatabaseSet as DatabaseSet>::Merkleized {
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

impl<E> Application<E> for App
where
    E: rand::Rng + Spawner + Metrics + Clock,
{
    type SigningScheme = MockScheme<ed25519::PublicKey>;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block;
    type Databases = MockDatabaseSet;
    type InputProvider = ();

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized,
        _input: &mut Self::InputProvider,
    ) -> Option<(Self::Block, <Self::Databases as DatabaseSet>::Merkleized)> {
        let parent = ancestry.peek()?;
        let parent_digest = parent.digest();
        let height = Height::new(parent.height().get() + 1);
        let (_, ctx) = &context;

        let merkleized = Self::execute(height, batches).await;
        let state_root = merkleized.root();

        let mut hasher = Sha256::new();
        hasher.update(b"e2e_block");
        hasher.update(&ctx.encode());
        hasher.update(parent_digest.as_ref());
        hasher.update(&height.get().to_be_bytes());
        hasher.update(state_root.as_ref());
        let digest = hasher.finalize();

        let block = Block {
            context: ctx.clone(),
            parent: parent_digest,
            height,
            digest,
            state_root,
        };
        Some((block, merkleized))
    }

    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        _context: (E, Self::Context),
        ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet>::Merkleized> {
        let tip = ancestry.peek()?;
        let height = tip.height();

        let merkleized = Self::execute(height, batches).await;
        let computed_root = merkleized.root();

        if computed_root != tip.state_root {
            return None;
        }

        Some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet>::Merkleized {
        Self::execute(block.height(), batches).await
    }
}

/// Engine definition implementing `EngineDefinition` for the simulation harness.
#[derive(Clone)]
pub(crate) struct ConsensusEngine {
    participants: Vec<ed25519::PublicKey>,
    schemes: Vec<MockScheme<ed25519::PublicKey>>,
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
        }
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

        // Initialize QMDB database
        let qmdb = Qmdb::init(
            context.clone(),
            FixedConfig {
                mmr_journal_partition: format!("{partition_prefix}-qmdb-mmr-journal"),
                mmr_metadata_partition: format!("{partition_prefix}-qmdb-mmr-metadata"),
                mmr_items_per_blob: NZU64!(11),
                mmr_write_buffer: NZUsize!(1024),
                log_journal_partition: format!("{partition_prefix}-qmdb-log-journal"),
                log_items_per_blob: NZU64!(7),
                log_write_buffer: NZUsize!(1024),
                translator: TwoCap::default(),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
        )
        .await
        .expect("failed to initialize QMDB");
        let db: MockDatabaseSet = Arc::new(AsyncRwLock::new(qmdb));
        // Destructure the 5 channels
        let mut channels = channels.into_iter();
        let vote_network = channels.next().unwrap();
        let certificate_network = channels.next().unwrap();
        let resolver_network = channels.next().unwrap();
        let backfill_network = channels.next().unwrap();
        let broadcast_network = channels.next().unwrap();

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
                replay_buffer: NZUsize!(1024),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
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
                replay_buffer: NZUsize!(1024),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
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
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
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

        // Stateful actor
        let app = App::new();
        let (stateful_actor, stateful_mailbox) = StatefulActor::init(
            context.clone(),
            StatefulConfig {
                app,
                databases: db.clone(),
                input_provider: (),
                marshal: marshal_mailbox.clone(),
                mailbox_size: 100,
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
        stateful_actor.start().await;

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
            replay_buffer: NZUsize!(1024),
            write_buffer: NZUsize!(1024),
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
                _db: db,
                marshal: marshal_mailbox,
            },
        )
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        engine
    }
}
