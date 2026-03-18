//! Consensus-facing wrapper that manages pending state on behalf of a
//! stateful application.
//!
//! `Stateful` implements the consensus application and verifying traits by
//! delegating execution to the inner application while managing the
//! pending-tip DAG of merkleized batches:
//!
//! - Before each `propose` or `verify`, the wrapper forks unmerkleized
//!   batches from the parent block's pending state (or from the committed
//!   database state if the parent has been finalized).
//! - After execution, the wrapper stores the resulting merkleized batches
//!   as a new pending tip keyed by the block's digest.
//! - On finalization, the wrapper applies the winning tip's changesets to
//!   the underlying databases and prunes dead forks.
//!
//! # Lazy Recovery
//!
//! Pending state lives entirely in memory. After a restart the map is empty,
//! but the wrapper recovers lazily: when a parent's state is missing, it
//! walks back through the block DAG via a [`BlockProvider`] to the nearest
//! known ancestor, then replays forward via [`Application::apply`]. Each
//! replayed block is inserted into the pending map immediately so that
//! partial progress survives timeouts.
//!
//! Propose/verify paths are cancellation-aware: if the caller drops the
//! response channel, long-running operations stop at await points that
//! preserve local consistency.

use crate::stateful::{
    actor::{
        bootstrap::{bootstrap, BootstrapConfig, Startup as BootstrapStartup, SyncTip},
        mailbox::{ErasedAncestorStream, Message},
        Mailbox,
    },
    db::{qmdb::resolver::AttachableResolverSet, DatabaseSet, StateSyncSet},
    Application,
};
use commonware_consensus::{
    marshal::{self, ancestry::BlockProvider},
    types::{Height, Round},
    Block, CertifiableBlock, Epochable, Heightable, Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_macros::{select, select_loop};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, mpsc, oneshot},
    Acknowledgement,
};
use rand::Rng;
use std::{collections::HashMap, future::Future};
use tracing::{debug, info};

type PendingDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type PendingBatches<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Merkleized;
type PendingEntry<A, E> = (Round, PendingBatches<A, E>);
type PendingSyncTip<A, E> = SyncTip<
    <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets,
    <<A as Application<E>>::Block as Digestible>::Digest,
>;
type RunningState<'a, A, E> = (
    &'a mut <A as Application<E>>::Databases,
    &'a mut Pending<A, E>,
    &'a mut <<A as Application<E>>::Block as Digestible>::Digest,
);

const STATE_SYNC_METADATA_SUFFIX: &str = "_state_sync_metadata";

/// Startup mode for the one-time state-sync bootstrap.
pub enum Startup<B> {
    /// Initialize fresh databases and let marshal backfill.
    Fresh,
    /// Run one-time state sync from a user-supplied finalization target.
    Sync { block: B },
}

/// Startup configuration for one-time state sync.
pub struct StateSyncConfig<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Partition prefix used to derive the durable state-sync metadata partition.
    pub partition_prefix: String,

    /// Explicit startup mode.
    pub startup: Startup<A::Block>,

    /// Resolver(s) for startup sync fetches and post-bootstrap serving.
    pub resolvers: R,

    /// Sync engine tuning knobs.
    pub sync_config: crate::stateful::db::SyncEngineConfig,
}

/// Errors while preparing parent-relative batches for propose/verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrepareBatchesError {
    /// Parent ancestry is provably invalid.
    Invalid,
    /// Caller dropped the response while waiting.
    Cancelled,
}

/// Wait for `future` unless the response receiver is dropped.
async fn await_or_cancel<R, T, F>(response: &mut oneshot::Sender<R>, future: F) -> Option<T>
where
    F: Future<Output = T>,
{
    select! {
        _ = response.closed() => None,
        output = future => Some(output),
    }
}

/// Pending merkleized batches keyed by block digest.
struct Pending<A, E>
where
    A: Application<E>,
    E: Rng + Spawner + Metrics + Clock,
{
    entries: HashMap<PendingDigest<A, E>, PendingEntry<A, E>>,
}

impl<A, E> Pending<A, E>
where
    A: Application<E>,
    E: Rng + Spawner + Metrics + Clock,
{
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn contains(&self, digest: &PendingDigest<A, E>) -> bool {
        self.entries.contains_key(digest)
    }

    fn get_merkleized(&self, digest: &PendingDigest<A, E>) -> Option<&PendingBatches<A, E>> {
        self.entries.get(digest).map(|(_, merkleized)| merkleized)
    }

    fn insert(
        &mut self,
        digest: PendingDigest<A, E>,
        round: Round,
        merkleized: PendingBatches<A, E>,
    ) {
        self.entries.insert(digest, (round, merkleized));
    }

    fn remove(&mut self, digest: &PendingDigest<A, E>) -> Option<PendingEntry<A, E>> {
        self.entries.remove(digest)
    }

    fn retain_newer_than(&mut self, finalized_round: Round) {
        self.entries
            .retain(|_, (round, _)| *round > finalized_round);
    }
}

/// Startup lifecycle for one actor instance.
enum StartupState<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Configuration has not been consumed by [`Stateful::start`] yet.
    Pending {
        db_config: <A::Databases as DatabaseSet<E>>::Config,
        state_sync: StateSyncConfig<E, A, R>,
        tip_updates: mpsc::Receiver<PendingSyncTip<A, E>>,
    },

    /// Startup completed and resolver attachment is available.
    Started { sync_resolvers: R },

    /// Temporary sentinel while consuming [`Pending`](Self::Pending) in `start`.
    Consumed,
}

/// Operating mode of the [`Stateful`] actor.
///
/// Instances are initialized in [`Syncing`](Mode::Syncing) and transition to
/// [`Running`](Mode::Running) when startup bootstrap calls
/// [`Mailbox::sync_complete`].
enum Mode<A, E>
where
    A: Application<E>,
    E: Rng + Spawner + Metrics + Clock,
{
    /// State-sync mode: databases are not yet available.
    ///
    /// Proposals are rejected. Verify response channels are held without
    /// responding so upstream verification requests time out naturally.
    /// Finalization acknowledgements are held so marshal does not advance
    /// past our sync target.
    Syncing {
        /// Verify response channels received while syncing.
        ///
        /// We never respond to these requests while syncing to avoid voting
        /// against potentially-valid blocks. Closed channels are pruned as
        /// new verify requests arrive.
        held_verify_responses: Vec<oneshot::Sender<bool>>,

        /// Finalization acknowledgements held during sync. Dropping them
        /// without acknowledging prevents marshal from advancing past our
        /// sync target. They are discarded on [`Message::SyncComplete`]
        /// after `set_floor` has made them irrelevant.
        held_acks: Vec<Exact>,

        /// Channel to forward sync tips to the background sync
        /// orchestrator. Each tip bundles the finalized block's height,
        /// digest, and per-database sync targets.
        tip_sender: mpsc::Sender<PendingSyncTip<A, E>>,
    },

    /// Normal consensus operation.
    Running {
        /// The set of databases whose batch lifecycle is managed by this wrapper.
        databases: A::Databases,

        /// Pending merkleized batches keyed by block digest, tagged with the
        /// round in which they were produced.
        pending: Pending<A, E>,

        /// The latest observed finalized block digest.
        ///
        /// TODO: Rename "processed_digest" or "finalized_tip_digest" or
        /// something less ambiguous, since this isn't the latest finalized
        /// digest. Just the latest that we've processed locally.
        finalized_digest: <A::Block as Digestible>::Digest,
    },
}

impl<A, E> Mode<A, E>
where
    A: Application<E>,
    E: Rng + Spawner + Metrics + Clock,
{
    /// Returns mutable references to `Running` state, panicking if syncing.
    fn running(&mut self) -> RunningState<'_, A, E> {
        match self {
            Self::Running {
                databases,
                pending,
                finalized_digest,
            } => (databases, pending, finalized_digest),
            Self::Syncing { .. } => {
                panic!("stateful actor called in syncing mode")
            }
        }
    }
}

/// Configuration for constructing a [`Stateful`] wrapper.
pub struct Config<E, A, P, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The inner application that drives state transitions.
    pub app: A,

    /// Configuration used to construct the database set during [`Stateful::start`].
    pub db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Source of input (e.g. transactions) passed to the application on
    /// propose.
    pub input_provider: A::InputProvider,

    /// Marshal mailbox used for startup anchoring and lazy recovery.
    pub marshal: P,

    /// Capacity of the stateful actor mailbox channel.
    pub mailbox_size: usize,

    /// Startup state-sync configuration.
    pub state_sync: StateSyncConfig<E, A, R>,
}

/// Wraps an [`Application`] and manages the pending-tip DAG of merkleized
/// batches on its behalf, implementing the consensus
/// application and verifying traits.
///
/// When a parent block's pending state is missing (e.g. after a restart),
/// the wrapper lazily rebuilds it by walking back through the block DAG
/// via the [`BlockProvider`] and replaying forward via
/// [`Application::apply`].
pub struct Stateful<E, A, P, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Sender half of the actor mailbox channel.
    sender: mpsc::Sender<Message<E, A>>,

    /// Runtime context providing RNG, task spawning, metrics, and clock.
    context: ContextCell<E>,

    /// The receiver for messages.
    mailbox: mpsc::Receiver<Message<E, A>>,

    /// The inner application that drives state transitions.
    inner: A,

    /// Source of input (e.g. transactions) passed to the application on propose.
    input_provider: A::InputProvider,

    /// Marshal mailbox used for startup anchoring and lazy recovery.
    marshal: P,

    /// One-time startup lifecycle.
    startup: StartupState<E, A, R>,

    /// Current operating mode (syncing or running).
    mode: Mode<A, E>,
}

impl<E, A, P, R> Stateful<E, A, P, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    /// Construct a [`Stateful`] actor and its [`Mailbox`].
    ///
    /// This only wires dependencies and allocates the mailbox. The actor does
    /// not process messages until [`Stateful::start`] is called.
    pub fn init(context: E, config: Config<E, A, P, R>) -> (Self, Mailbox<E, A>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        let (tip_sender, tip_updates) =
            mpsc::channel(config.state_sync.sync_config.update_channel_size.get());
        (
            Self {
                sender: sender.clone(),
                context: ContextCell::new(context),
                mailbox,
                inner: config.app,
                input_provider: config.input_provider,
                marshal: config.marshal,
                startup: StartupState::Pending {
                    db_config: config.db_config,
                    state_sync: config.state_sync,
                    tip_updates,
                },
                mode: Mode::Syncing {
                    held_verify_responses: Vec::new(),
                    held_acks: Vec::new(),
                    tip_sender,
                },
            },
            Mailbox::new(sender),
        )
    }

    /// Start the actor and run startup bootstrap in the background.
    ///
    /// This is the single startup entrypoint for both modes:
    /// - [`Startup::Fresh`]: initialize fresh databases and backfill from marshal.
    /// - [`Startup::Sync`]: run one-time startup state sync.
    pub fn start<S, V>(mut self) -> Handle<()>
    where
        E: Rng + Spawner + Metrics + Clock + Storage,
        A: Application<E>,
        A::Context: Send,
        A::Databases: StateSyncSet<E, R>,
        S: Scheme,
        V: marshal::core::Variant<ApplicationBlock = A::Block>,
        P: Into<marshal::core::Mailbox<S, V>>,
        R: Clone + Send + AttachableResolverSet<A::Databases> + 'static,
    {
        let startup = std::mem::replace(&mut self.startup, StartupState::Consumed);
        let StartupState::Pending {
            db_config,
            state_sync: config,
            tip_updates,
        } = startup
        else {
            panic!("start called more than once");
        };

        let StateSyncConfig {
            partition_prefix,
            startup,
            resolvers,
            sync_config,
        } = config;
        let metadata_partition = format!("{partition_prefix}{STATE_SYNC_METADATA_SUFFIX}");

        let bootstrap_startup = match startup {
            Startup::Fresh => BootstrapStartup::Fresh,
            Startup::Sync { block } => BootstrapStartup::Sync {
                initial_tip: SyncTip {
                    height: block.height(),
                    digest: block.digest(),
                    targets: A::sync_targets(&block),
                },
                tip_updates,
                resolvers: resolvers.clone(),
            },
        };
        self.startup = StartupState::Started {
            sync_resolvers: resolvers,
        };

        let context = self.context.clone().into_present();
        let bootstrap_config = BootstrapConfig {
            context: context.with_label("state_sync"),
            db_config,
            metadata_partition,
            sync_config,
            startup: bootstrap_startup,
        };
        let marshal: marshal::core::Mailbox<S, V> = self.marshal.clone().into();
        let mailbox = Mailbox::new(self.sender.clone());
        context
            .with_label("state_sync_bootstrap")
            .spawn(move |_| async move {
                bootstrap(marshal, mailbox, bootstrap_config).await;
            });

        spawn_cell!(self.context, self.run().await)
    }

    /// Main actor loop.
    ///
    /// Processes mailbox messages serially until either:
    /// - the runtime context is stopped, or
    /// - all mailbox senders are dropped.
    async fn run(mut self)
    where
        R: AttachableResolverSet<A::Databases>,
    {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping stateful application");
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                break;
            } => {
                match message {
                    Message::Genesis { response } => self.handle_genesis(response).await,
                    Message::Propose { context, ancestry, response } => {
                        self.handle_propose(context, ancestry, response).await;
                    },
                    Message::Verify { context, ancestry, response } => {
                        self.handle_verify(context, ancestry, response).await;
                    },
                    Message::Finalized { block, acknowledgement } => {
                        self.handle_finalized(block, acknowledgement).await;
                    },
                    Message::Tip { height, digest } => {
                        self.handle_tip(height, digest).await;
                    },
                    Message::SyncComplete { databases, finalized_digest } => {
                        self.handle_sync_complete(databases, finalized_digest).await;
                    }
                }
            }
        }
    }

    /// Handles a [`Message::Genesis`].
    async fn handle_genesis(&mut self, response: oneshot::Sender<A::Block>) {
        let block = self.inner.genesis().await;
        response.send_lossy(block);
    }

    /// Handles a [`Message::Propose`].
    async fn handle_propose(
        &mut self,
        (runtime_context, consensus_context): (E, A::Context),
        ancestry: ErasedAncestorStream<A::Block>,
        mut response: oneshot::Sender<Option<A::Block>>,
    ) {
        if matches!(self.mode, Mode::Syncing { .. }) {
            debug!("proposal rejected: state sync in progress");
            response.send_lossy(None);
            return;
        }

        // The ancestry stream starts from the parent block.
        let Some(parent) = ancestry.peek() else {
            response.send_lossy(None);
            return;
        };
        let parent_digest = parent.digest();

        // Prepare the intermediate state to build on top of.
        let round = Round::new(consensus_context.epoch(), consensus_context.view());
        let batches = match self.prepare_batches(parent_digest, &mut response).await {
            Ok(batches) => batches,
            Err(PrepareBatchesError::Invalid) => {
                response.send_lossy(None);
                return;
            }
            Err(PrepareBatchesError::Cancelled) => {
                debug!(
                    ?parent_digest,
                    "proposal request cancelled during prepare_batches"
                );
                return;
            }
        };

        // Dispatch the proposal build job.
        let proposed = match await_or_cancel(
            &mut response,
            self.inner.propose(
                (runtime_context, consensus_context),
                ancestry,
                batches,
                &mut self.input_provider,
            ),
        )
        .await
        {
            Some(result) => result,
            None => {
                debug!(?parent_digest, "proposal request cancelled during propose");
                return;
            }
        };

        // Cache the built block's pending state for later verification jobs
        // and finalization.
        let Some((block, merkleized)) = proposed else {
            response.send_lossy(None);
            return;
        };
        let (_, pending, _) = self.mode.running();
        pending.insert(block.digest(), round, merkleized);

        // Send the built block back to the application.
        response.send_lossy(Some(block));
    }

    /// Handles a [`Message::Verify`].
    async fn handle_verify(
        &mut self,
        (runtime_context, consensus_context): (E, A::Context),
        ancestry: ErasedAncestorStream<A::Block>,
        mut response: oneshot::Sender<bool>,
    ) {
        if let Mode::Syncing {
            held_verify_responses,
            ..
        } = &mut self.mode
        {
            held_verify_responses.retain(|response| !response.is_closed());
            held_verify_responses.push(response);
            debug!(
                held_verify_responses = held_verify_responses.len(),
                "verify held: state sync in progress"
            );
            return;
        }

        let Some(block) = ancestry.peek() else {
            response.send_lossy(false);
            return;
        };
        let block_digest = block.digest();
        let parent_digest = block.parent();

        // Prepare the intermediate state to build on top of.
        let round = Round::new(consensus_context.epoch(), consensus_context.view());
        let batches = match self.prepare_batches(parent_digest, &mut response).await {
            Ok(batches) => batches,
            Err(PrepareBatchesError::Invalid) => {
                response.send_lossy(false);
                return;
            }
            Err(PrepareBatchesError::Cancelled) => {
                debug!(
                    ?parent_digest,
                    "verification request cancelled during prepare_batches"
                );
                return;
            }
        };

        // Dispatch the verification job.
        let verified = match await_or_cancel(
            &mut response,
            self.inner
                .verify((runtime_context, consensus_context), ancestry, batches),
        )
        .await
        {
            Some(result) => result,
            None => {
                debug!(
                    ?parent_digest,
                    "verification request cancelled during verify"
                );
                return;
            }
        };

        // Cache the verified block's pending state for later verification jobs
        // and finalization.
        let Some(merkleized) = verified else {
            response.send_lossy(false);
            return;
        };
        let (_, pending, _) = self.mode.running();
        pending.insert(block_digest, round, merkleized);

        // Inform the application that the block is valid.
        response.send_lossy(true);
    }

    /// Handles a [`Message::Finalized`].
    async fn handle_finalized(&mut self, block: A::Block, acknowledgement: Exact) {
        if let Mode::Syncing { held_acks, .. } = &mut self.mode {
            debug!(
                height = block.height().get(),
                "finalization held during sync (not yet acknowledged)"
            );
            held_acks.push(acknowledgement);
            return;
        }

        let (databases, pending, finalized_digest) = self.mode.running();

        // Duplicate finalization reports are benign. A node may
        // observe the same finalization certificate multiple times
        // from replay or the network.
        if *finalized_digest == block.digest() {
            acknowledgement.acknowledge();
            return;
        }

        // Try to use existing pending state from propose/verify, otherwise
        // apply the block on top of the finalized state database.
        let batch = match pending.remove(&block.digest()) {
            Some((_, merkleized)) => merkleized,
            None => {
                let batches = databases.new_batches().await;
                let replay_context = self.context.clone().into_present();
                self.inner
                    .apply((replay_context, block.context()), &block, batches)
                    .await
            }
        };

        // Persist the finalized state, update the finalized anchor, prune dead
        // chains, and acknowledge that the application has processed the finalized
        // block.
        let round = Round::new(block.context().epoch(), block.context().view());
        databases.finalize(batch).await;
        pending.retain_newer_than(round);
        *finalized_digest = block.digest();
        acknowledgement.acknowledge();

        info!(
            height = block.height().get(),
            "persisted finalized database batch"
        );
    }

    /// Handles a [`Message::Tip`].
    ///
    /// In [`Mode::Syncing`], fetches the block from marshal, extracts
    /// per-database sync targets via [`Application::sync_targets`], and
    /// forwards them to the background sync engines.
    ///
    /// In [`Mode::Running`], this is a no-op.
    async fn handle_tip(&mut self, height: Height, digest: <A::Block as Digestible>::Digest) {
        let Mode::Syncing { tip_sender, .. } = &self.mode else {
            return;
        };

        let Some(block) = self.marshal.clone().fetch_block(digest).await else {
            debug!(
                height = height.get(),
                "tip block not available from provider, skipping target update"
            );
            return;
        };

        let targets = A::sync_targets(&block);
        if tip_sender
            .try_send(SyncTip {
                height,
                digest,
                targets,
            })
            .is_err()
        {
            debug!(
                height = height.get(),
                "tip update channel unavailable, keeping existing sync target"
            );
        }
    }

    /// Handles a [`Message::SyncComplete`].
    ///
    /// Transitions from [`Mode::Syncing`] to [`Mode::Running`].
    ///
    /// Any held verify response channels are dropped without sending a
    /// response so their callers can time out naturally.
    async fn handle_sync_complete(
        &mut self,
        databases: A::Databases,
        finalized_digest: <A::Block as Digestible>::Digest,
    ) where
        R: AttachableResolverSet<A::Databases>,
    {
        let (held_verify_responses, held_acks) = match &mut self.mode {
            Mode::Syncing {
                held_verify_responses,
                held_acks,
                ..
            } => (
                std::mem::take(held_verify_responses),
                std::mem::take(held_acks),
            ),
            Mode::Running { .. } => {
                panic!("SyncComplete received while already in Running mode");
            }
        };
        let sync_resolvers = match &self.startup {
            StartupState::Started { sync_resolvers } => sync_resolvers,
            StartupState::Pending { .. } | StartupState::Consumed => {
                panic!("SyncComplete received before startup reached Started state");
            }
        };
        sync_resolvers.attach_databases(databases.clone()).await;

        self.mode = Mode::Running {
            databases,
            pending: Pending::new(),
            finalized_digest,
        };

        let held_verifies = held_verify_responses.len();
        let dropped_open_verifies = held_verify_responses
            .iter()
            .filter(|response| !response.is_closed())
            .count();
        let dropped_acks = held_acks.len();
        drop(held_verify_responses);
        drop(held_acks);
        info!(
            held_verifies,
            dropped_open_verifies, dropped_acks, "sync complete, transitioning to running mode"
        );
    }

    /// Ensure parent state exists, then prepare unmerkleized batches for execution.
    ///
    /// Rebuilds parent pending state when needed, then forks from known parent
    /// state (pending parent or finalized tip).
    ///
    /// Returns:
    /// - `Ok(batches)` when parent state is available and batches are ready.
    /// - `Err(PrepareBatchesError::Invalid)` when rebuild cannot safely anchor.
    /// - `Err(PrepareBatchesError::Cancelled)` when caller drops the response while waiting.
    async fn prepare_batches<Response>(
        &mut self,
        parent: <A::Block as Digestible>::Digest,
        response: &mut oneshot::Sender<Response>,
    ) -> Result<<A::Databases as DatabaseSet<E>>::Unmerkleized, PrepareBatchesError> {
        let (_, pending, finalized_digest) = self.mode.running();
        let needs_rebuild = finalized_digest != &parent && !pending.contains(&parent);
        if needs_rebuild {
            self.rebuild_pending(parent, response).await?;
        }

        await_or_cancel(response, self.fork_batches(&parent))
            .await
            .unwrap_or_else(|| Err(PrepareBatchesError::Cancelled))
    }

    /// Fork unmerkleized batches from parent state.
    ///
    /// If `parent` exists in `pending`, this forks from its merkleized state.
    /// If `parent` matches the finalized tip, this starts from committed state.
    /// Otherwise, the parent is not a known safe anchor.
    async fn fork_batches(
        &mut self,
        parent: &<A::Block as Digestible>::Digest,
    ) -> Result<<A::Databases as DatabaseSet<E>>::Unmerkleized, PrepareBatchesError> {
        let (databases, pending, finalized_digest) = self.mode.running();
        if let Some(merkleized) = pending.get_merkleized(parent) {
            return Ok(<A::Databases as DatabaseSet<E>>::fork_batches(merkleized));
        }
        if finalized_digest == parent {
            return Ok(databases.new_batches().await);
        }
        Err(PrepareBatchesError::Invalid)
    }

    /// Walk back from `target` to the nearest known ancestor (either in
    /// the pending map or the finalized tip), then replay forward to
    /// populate the pending map with the missing chain segment.
    ///
    /// Each replayed block's merkleized state is inserted into the pending
    /// map immediately so that partial progress survives timeouts.
    ///
    /// Returns:
    /// - `Ok(())` if replay succeeds.
    /// - `Err(PrepareBatchesError::Invalid)` if we cannot anchor the walk.
    /// - `Err(PrepareBatchesError::Cancelled)` if caller drops the response.
    async fn rebuild_pending<Response>(
        &mut self,
        target: <A::Block as Digestible>::Digest,
        response: &mut oneshot::Sender<Response>,
    ) -> Result<(), PrepareBatchesError> {
        let (_, pending, finalized_digest) = self.mode.running();
        let finalized_digest = *finalized_digest;

        // Walk back, collecting blocks whose pending state is missing.
        let mut to_replay = Vec::new();
        let mut current = target;
        while current != finalized_digest {
            // If we already have pending state for this digest, we have a safe
            // replay anchor and should not depend on provider availability.
            if pending.contains(&current) {
                break;
            }

            let fetched =
                match await_or_cancel(response, self.marshal.clone().fetch_block(current)).await {
                    Some(block) => block,
                    None => return Err(PrepareBatchesError::Cancelled),
                };
            let Some(block) = fetched else {
                // `fetch_block` subscribes under the hood. A dropped subscription
                // is not proof of invalidity, so we retry.
                debug!(
                    ?target,
                    ?current,
                    "ancestor subscription ended before delivery, retrying"
                );
                continue;
            };

            // Marshal ancestry fetches cannot step past height 1 because
            // the genesis block is not served. If the proposal's chain is
            // not anchored on genesis, it is guaranteed to be invalid.
            if block.height() <= Height::new(1) {
                debug!(
                    ?target,
                    reached_height = %block.height(),
                    "rebuild reached ancestry boundary without known anchor"
                );
                return Err(PrepareBatchesError::Invalid);
            }

            let parent_digest = block.parent();
            to_replay.push(block);
            current = parent_digest;
        }

        // Replay in ascending order, inserting into the pending
        // map after each block for incremental progress.
        for block in to_replay.into_iter().rev() {
            let digest = block.digest();
            let parent_digest = block.parent();
            let consensus_context = block.context();
            let round = Round::new(consensus_context.epoch(), consensus_context.view());

            let batches = match await_or_cancel(response, self.fork_batches(&parent_digest)).await {
                Some(Ok(batches)) => batches,
                Some(Err(err)) => return Err(err),
                None => return Err(PrepareBatchesError::Cancelled),
            };
            let replay_context = self.context.clone().into_present();
            let merkleized = match await_or_cancel(
                response,
                self.inner
                    .apply((replay_context, consensus_context), &block, batches),
            )
            .await
            {
                Some(merkleized) => merkleized,
                None => return Err(PrepareBatchesError::Cancelled),
            };

            let (_, pending, _) = self.mode.running();
            pending.insert(digest, round, merkleized);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Mode, Pending, PendingSyncTip, PrepareBatchesError, Startup, StartupState, StateSyncConfig,
        Stateful,
    };
    use crate::stateful::{
        db::{qmdb::resolver::AttachableResolverSet, DatabaseSet, Merkleized, Unmerkleized},
        Application, Config as StatefulConfig,
    };
    use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
    use commonware_consensus::{
        marshal::ancestry::{AncestorStream, BlockProvider},
        simplex::{mocks::scheme::Scheme as MockScheme, types::Context as ConsensusContext},
        types::{Epoch, Height, Round, View},
        Block as ConsensusBlock, CertifiableBlock, Heightable,
    };
    use commonware_cryptography::{
        ed25519, sha256::Digest, Digest as _, Digestible, Hasher, Sha256, Signer as _,
    };
    use commonware_runtime::{deterministic, Clock, Metrics, Runner as _, Spawner};
    use commonware_storage::{mmr::Location, qmdb::sync::Target};
    use commonware_utils::{
        channel::{mpsc, oneshot},
        NZUsize,
    };
    use std::{
        collections::BTreeMap,
        convert::Infallible,
        num::NonZeroU64,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    type TestContext = ConsensusContext<Digest, ed25519::PublicKey>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBlock {
        context: TestContext,
        parent: Digest,
        height: Height,
        digest: Digest,
    }

    impl Write for TestBlock {
        fn write(&self, buf: &mut impl commonware_runtime::BufMut) {
            self.context.write(buf);
            self.parent.write(buf);
            self.height.write(buf);
            self.digest.write(buf);
        }
    }

    impl EncodeSize for TestBlock {
        fn encode_size(&self) -> usize {
            self.context.encode_size()
                + self.parent.encode_size()
                + self.height.encode_size()
                + self.digest.encode_size()
        }
    }

    impl Read for TestBlock {
        type Cfg = ();

        fn read_cfg(
            buf: &mut impl commonware_runtime::Buf,
            _: &Self::Cfg,
        ) -> Result<Self, CodecError> {
            let context = TestContext::read(buf)?;
            let parent = Digest::read(buf)?;
            let height = Height::read(buf)?;
            let digest = Digest::read(buf)?;
            Ok(Self {
                context,
                parent,
                height,
                digest,
            })
        }
    }

    impl Digestible for TestBlock {
        type Digest = Digest;

        fn digest(&self) -> Digest {
            self.digest
        }
    }

    impl Heightable for TestBlock {
        fn height(&self) -> Height {
            self.height
        }
    }

    impl ConsensusBlock for TestBlock {
        fn parent(&self) -> Digest {
            self.parent
        }
    }

    impl CertifiableBlock for TestBlock {
        type Context = TestContext;

        fn context(&self) -> Self::Context {
            self.context.clone()
        }
    }

    #[derive(Clone, Copy)]
    struct TestUnmerkleized;

    #[derive(Clone, Copy)]
    struct TestMerkleized;

    impl Unmerkleized for TestUnmerkleized {
        type Key = ();
        type Value = ();
        type Merkleized = TestMerkleized;
        type Error = Infallible;

        async fn get(&self, _key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
            Ok(None)
        }

        fn write(self, _key: Self::Key, _value: Option<Self::Value>) -> Self {
            self
        }

        async fn merkleize(self) -> Result<Self::Merkleized, Self::Error> {
            Ok(TestMerkleized)
        }
    }

    impl Merkleized for TestMerkleized {
        type Digest = Digest;
        type Unmerkleized = TestUnmerkleized;

        fn root(&self) -> Self::Digest {
            Digest::EMPTY
        }

        fn new_batch(&self) -> Self::Unmerkleized {
            TestUnmerkleized
        }
    }

    #[derive(Clone, Copy)]
    struct TestDatabases;

    impl<E: Send> DatabaseSet<E> for TestDatabases {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Config = ();
        type SyncTargets = Vec<Target<Digest>>;

        async fn init(_context: E, _config: Self::Config) -> Self {
            Self
        }

        async fn new_batches(&self) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn fork_batches(_parent: &Self::Merkleized) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&self, _batches: Self::Merkleized) {}
    }

    #[derive(Clone)]
    struct TestApp;

    impl Application<deterministic::Context> for TestApp {
        type SigningScheme = MockScheme<ed25519::PublicKey>;
        type Context = TestContext;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type InputProvider = ();

        async fn genesis(&mut self) -> Self::Block {
            make_block(Height::zero(), Digest::EMPTY, View::zero())
        }

        async fn propose<A: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: AncestorStream<A, Self::Block>,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: &mut Self::InputProvider,
        ) -> Option<(
            Self::Block,
            <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized,
        )> {
            None
        }

        async fn verify<A: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: AncestorStream<A, Self::Block>,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            Some(TestMerkleized)
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
            TestMerkleized
        }

        fn sync_targets(
            _block: &Self::Block,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
            Vec::new()
        }
    }

    #[derive(Clone)]
    struct SlowReplayApp {
        started: Arc<AtomicBool>,
    }

    impl Application<deterministic::Context> for SlowReplayApp {
        type SigningScheme = MockScheme<ed25519::PublicKey>;
        type Context = TestContext;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type InputProvider = ();

        async fn genesis(&mut self) -> Self::Block {
            make_block(Height::zero(), Digest::EMPTY, View::zero())
        }

        async fn propose<A: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: AncestorStream<A, Self::Block>,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: &mut Self::InputProvider,
        ) -> Option<(
            Self::Block,
            <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized,
        )> {
            None
        }

        async fn verify<A: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: AncestorStream<A, Self::Block>,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            Some(TestMerkleized)
        }

        async fn apply(
            &mut self,
            (runtime_context, _): (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
            self.started.store(true, Ordering::SeqCst);
            runtime_context.sleep(Duration::from_secs(1)).await;
            TestMerkleized
        }

        fn sync_targets(
            _block: &Self::Block,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
            Vec::new()
        }
    }

    #[derive(Clone)]
    struct PanicOnGenesisProvider {
        blocks: Arc<BTreeMap<Digest, TestBlock>>,
        genesis_digest: Digest,
    }

    impl BlockProvider for PanicOnGenesisProvider {
        type Block = TestBlock;

        async fn fetch_block(self, digest: Digest) -> Option<Self::Block> {
            assert_ne!(
                digest, self.genesis_digest,
                "stateful rebuild requested genesis digest from block provider"
            );
            self.blocks.get(&digest).cloned()
        }
    }

    #[derive(Clone)]
    struct RetryOnceProvider {
        blocks: Arc<BTreeMap<Digest, TestBlock>>,
        flaky_digest: Digest,
        first_miss: Arc<AtomicBool>,
        attempts: Arc<AtomicUsize>,
    }

    impl BlockProvider for RetryOnceProvider {
        type Block = TestBlock;

        async fn fetch_block(self, digest: Digest) -> Option<Self::Block> {
            if digest == self.flaky_digest {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                if self.first_miss.swap(false, Ordering::SeqCst) {
                    return None;
                }
            }
            self.blocks.get(&digest).cloned()
        }
    }

    #[derive(Clone)]
    struct AlwaysMissingProvider;

    impl BlockProvider for AlwaysMissingProvider {
        type Block = TestBlock;

        async fn fetch_block(self, _digest: Digest) -> Option<Self::Block> {
            None
        }
    }

    #[derive(Clone)]
    struct PanicOnFetchProvider;

    impl BlockProvider for PanicOnFetchProvider {
        type Block = TestBlock;

        async fn fetch_block(self, _digest: Digest) -> Option<Self::Block> {
            panic!("provider should not be queried when current digest is already pending");
        }
    }

    fn make_block(height: Height, parent: Digest, view: View) -> TestBlock {
        let context = TestContext {
            round: Round::new(Epoch::zero(), view),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (
                if view.is_zero() {
                    View::zero()
                } else {
                    View::new(view.get() - 1)
                },
                parent,
            ),
        };
        let mut hasher = Sha256::new();
        hasher.update(parent.as_ref());
        hasher.update(&height.get().to_be_bytes());
        hasher.update(&context.encode());
        let digest = hasher.finalize();
        TestBlock {
            context,
            parent,
            height,
            digest,
        }
    }

    fn test_state_sync_config<A>() -> StateSyncConfig<deterministic::Context, A, ()>
    where
        A: Application<deterministic::Context>,
    {
        StateSyncConfig {
            partition_prefix: "test".to_string(),
            startup: Startup::Fresh,
            resolvers: (),
            sync_config: crate::stateful::db::SyncEngineConfig {
                fetch_batch_size: NonZeroU64::new(1).expect("fetch batch size must be non-zero"),
                apply_batch_size: 1,
                max_outstanding_requests: 1,
                update_channel_size: NZUsize!(1),
            },
        }
    }

    #[derive(Clone)]
    struct LifecycleResolver {
        attached: Arc<AtomicBool>,
    }

    impl LifecycleResolver {
        fn new() -> Self {
            Self {
                attached: Arc::new(AtomicBool::new(false)),
            }
        }

        fn get_operations(&self) -> Result<(), &'static str> {
            if self.attached.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err("resolver not attached")
            }
        }
    }

    impl AttachableResolverSet<TestDatabases> for LifecycleResolver {
        async fn attach_databases(&self, _databases: TestDatabases) {
            self.attached.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn rebuild_pending_never_requests_genesis_from_provider() {
        deterministic::Runner::default().start(|context| async move {
            let genesis_digest = Sha256::hash(b"genesis");
            let block1 = make_block(Height::new(1), genesis_digest, View::new(1));
            let block2 = make_block(Height::new(2), block1.digest(), View::new(2));

            let provider = PanicOnGenesisProvider {
                blocks: Arc::new(BTreeMap::from([
                    (block1.digest(), block1.clone()),
                    (block2.digest(), block2.clone()),
                ])),
                genesis_digest,
            };

            let (mut actor, _mailbox) = Stateful::init(
                context.clone(),
                StatefulConfig {
                    app: TestApp,
                    db_config: (),
                    input_provider: (),
                    marshal: provider,
                    mailbox_size: 16,
                    state_sync: test_state_sync_config::<TestApp>(),
                },
            );

            actor.mode = Mode::Running {
                databases: TestDatabases,
                pending: Pending::new(),
                finalized_digest: Sha256::hash(b"other-finalized-tip"),
            };
            let (mut response, _rx) = oneshot::channel::<bool>();
            let rebuilt = actor.rebuild_pending(block2.digest(), &mut response).await;
            assert_eq!(
                rebuilt,
                Err(PrepareBatchesError::Invalid),
                "stale fork should fail to rebuild safely"
            );
        });
    }

    #[test]
    fn rebuild_pending_retries_transient_fetch_none() {
        deterministic::Runner::default().start(|context| async move {
            let genesis_digest = Sha256::hash(b"genesis");
            let block1 = make_block(Height::new(1), genesis_digest, View::new(1));
            let block2 = make_block(Height::new(2), block1.digest(), View::new(2));
            let attempts = Arc::new(AtomicUsize::new(0));

            let provider = RetryOnceProvider {
                blocks: Arc::new(BTreeMap::from([
                    (block1.digest(), block1.clone()),
                    (block2.digest(), block2.clone()),
                ])),
                flaky_digest: block2.digest(),
                first_miss: Arc::new(AtomicBool::new(true)),
                attempts: attempts.clone(),
            };

            let (mut actor, _mailbox) = Stateful::init(
                context.clone(),
                StatefulConfig {
                    app: TestApp,
                    db_config: (),
                    input_provider: (),
                    marshal: provider,
                    mailbox_size: 16,
                    state_sync: test_state_sync_config::<TestApp>(),
                },
            );

            actor.mode = Mode::Running {
                databases: TestDatabases,
                pending: Pending::new(),
                finalized_digest: block1.digest(),
            };
            let (mut response, _rx) = oneshot::channel::<bool>();
            let rebuilt = actor.rebuild_pending(block2.digest(), &mut response).await;
            assert_eq!(
                rebuilt,
                Ok(()),
                "rebuild should succeed after retrying transient miss"
            );
            assert!(
                attempts.load(Ordering::SeqCst) >= 2,
                "expected at least two fetch attempts for flaky digest"
            );
        });
    }

    #[test]
    fn rebuild_pending_stops_on_cancellation() {
        deterministic::Runner::default().start(|context| async move {
            let genesis_digest = Sha256::hash(b"genesis");
            let block1 = make_block(Height::new(1), genesis_digest, View::new(1));
            let block2 = make_block(Height::new(2), block1.digest(), View::new(2));

            let (mut actor, _mailbox) = Stateful::init(
                context.clone(),
                StatefulConfig {
                    app: TestApp,
                    db_config: (),
                    input_provider: (),
                    marshal: AlwaysMissingProvider,
                    mailbox_size: 16,
                    state_sync: test_state_sync_config::<TestApp>(),
                },
            );
            actor.mode = Mode::Running {
                databases: TestDatabases,
                pending: Pending::new(),
                finalized_digest: block1.digest(),
            };

            let (mut response, rx) = oneshot::channel::<bool>();
            drop(rx);
            let rebuilt = actor.rebuild_pending(block2.digest(), &mut response).await;
            assert_eq!(
                rebuilt,
                Err(PrepareBatchesError::Cancelled),
                "rebuild should stop when verification/proposal request is cancelled"
            );
        });
    }

    #[test]
    fn rebuild_pending_cancels_during_replay() {
        deterministic::Runner::default().start(|context| async move {
            let genesis_digest = Sha256::hash(b"genesis");
            let block1 = make_block(Height::new(1), genesis_digest, View::new(1));
            let block2 = make_block(Height::new(2), block1.digest(), View::new(2));

            let started = Arc::new(AtomicBool::new(false));
            let provider = PanicOnGenesisProvider {
                blocks: Arc::new(BTreeMap::from([
                    (block1.digest(), block1.clone()),
                    (block2.digest(), block2.clone()),
                ])),
                genesis_digest,
            };

            let (mut actor, _mailbox) = Stateful::init(
                context.clone(),
                StatefulConfig {
                    app: SlowReplayApp {
                        started: started.clone(),
                    },
                    db_config: (),
                    input_provider: (),
                    marshal: provider,
                    mailbox_size: 16,
                    state_sync: test_state_sync_config::<SlowReplayApp>(),
                },
            );
            actor.mode = Mode::Running {
                databases: TestDatabases,
                pending: Pending::new(),
                finalized_digest: block1.digest(),
            };

            let (mut response, rx) = oneshot::channel::<bool>();
            let rebuild = context
                .with_label("rebuild_pending")
                .spawn(move |_| async move {
                    actor.rebuild_pending(block2.digest(), &mut response).await
                });

            while !started.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }
            drop(rx);

            let status = rebuild.await.expect("rebuild task should not fail");
            assert_eq!(
                status,
                Err(PrepareBatchesError::Cancelled),
                "rebuild should stop when cancelled mid-replay"
            );
        });
    }

    #[derive(Clone)]
    struct SyncTargetApp;

    impl Application<deterministic::Context> for SyncTargetApp {
        type SigningScheme = MockScheme<ed25519::PublicKey>;
        type Context = TestContext;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type InputProvider = ();

        async fn genesis(&mut self) -> Self::Block {
            make_block(Height::zero(), Digest::EMPTY, View::zero())
        }

        async fn propose<A: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: AncestorStream<A, Self::Block>,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: &mut Self::InputProvider,
        ) -> Option<(
            Self::Block,
            <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized,
        )> {
            None
        }

        async fn verify<A: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: AncestorStream<A, Self::Block>,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            Some(TestMerkleized)
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
            TestMerkleized
        }

        fn sync_targets(
            block: &Self::Block,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
            vec![Target {
                root: block.digest(),
                range: Location::new(0)..Location::new(100),
            }]
        }
    }

    #[test]
    fn tip_in_syncing_mode_forwards_targets() {
        deterministic::Runner::default().start(|context| async move {
            let genesis_digest = Sha256::hash(b"genesis");
            let block1 = make_block(Height::new(1), genesis_digest, View::new(1));

            let provider = PanicOnGenesisProvider {
                blocks: Arc::new(BTreeMap::from([(block1.digest(), block1.clone())])),
                genesis_digest,
            };

            let (target_tx, mut target_rx) =
                mpsc::channel::<PendingSyncTip<SyncTargetApp, deterministic::Context>>(1);

            let (mut actor, _mailbox) = Stateful::init(
                context.clone(),
                StatefulConfig {
                    app: SyncTargetApp,
                    db_config: (),
                    input_provider: (),
                    marshal: provider,
                    mailbox_size: 16,
                    state_sync: test_state_sync_config::<SyncTargetApp>(),
                },
            );
            if let Mode::Syncing { tip_sender, .. } = &mut actor.mode {
                *tip_sender = target_tx;
            }

            actor.handle_tip(block1.height(), block1.digest()).await;

            let received = target_rx.try_recv().expect("tip should be forwarded");
            assert_eq!(received.height, block1.height());
            assert_eq!(received.digest, block1.digest());
            assert_eq!(received.targets.len(), 1);
            assert_eq!(received.targets[0].root, block1.digest());
            assert_eq!(
                received.targets[0].range,
                Location::new(0)..Location::new(100),
            );
        });
    }

    #[test]
    fn tip_in_running_mode_is_noop() {
        deterministic::Runner::default().start(|context| async move {
            let genesis_digest = Sha256::hash(b"genesis");
            let block1 = make_block(Height::new(1), genesis_digest, View::new(1));

            let (_target_tx, mut target_rx) =
                mpsc::channel::<PendingSyncTip<SyncTargetApp, deterministic::Context>>(1);

            let (mut actor, _mailbox) = Stateful::init(
                context.clone(),
                StatefulConfig {
                    app: SyncTargetApp,
                    db_config: (),
                    input_provider: (),
                    marshal: PanicOnFetchProvider,
                    mailbox_size: 16,
                    state_sync: test_state_sync_config::<SyncTargetApp>(),
                },
            );

            actor.mode = Mode::Running {
                databases: TestDatabases,
                pending: Pending::new(),
                finalized_digest: genesis_digest,
            };

            actor.handle_tip(block1.height(), block1.digest()).await;

            assert!(
                target_rx.try_recv().is_err(),
                "no target should be sent in running mode"
            );
        });
    }

    #[test]
    fn resolver_denies_pre_sync_complete() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = LifecycleResolver::new();
            let (_actor, _mailbox) = Stateful::init(
                context.clone(),
                StatefulConfig {
                    app: TestApp,
                    db_config: (),
                    input_provider: (),
                    marshal: AlwaysMissingProvider,
                    mailbox_size: 16,
                    state_sync: StateSyncConfig::<_, _, LifecycleResolver> {
                        partition_prefix: "test".to_string(),
                        startup: Startup::Fresh,
                        resolvers: resolver.clone(),
                        sync_config: crate::stateful::db::SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: 1,
                            max_outstanding_requests: 1,
                            update_channel_size: NZUsize!(1),
                        },
                    },
                },
            );

            assert_eq!(resolver.get_operations(), Err("resolver not attached"));
        });
    }

    #[test]
    fn resolver_serves_post_sync_complete() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = LifecycleResolver::new();
            let (mut actor, _mailbox) = Stateful::init(
                context.clone(),
                StatefulConfig {
                    app: TestApp,
                    db_config: (),
                    input_provider: (),
                    marshal: AlwaysMissingProvider,
                    mailbox_size: 16,
                    state_sync: StateSyncConfig::<_, _, LifecycleResolver> {
                        partition_prefix: "test".to_string(),
                        startup: Startup::Fresh,
                        resolvers: resolver.clone(),
                        sync_config: crate::stateful::db::SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: 1,
                            max_outstanding_requests: 1,
                            update_channel_size: NZUsize!(1),
                        },
                    },
                },
            );
            actor.startup = StartupState::Started {
                sync_resolvers: resolver.clone(),
            };

            actor
                .handle_sync_complete(
                    TestDatabases,
                    make_block(Height::zero(), Digest::EMPTY, View::zero()).digest(),
                )
                .await;

            assert_eq!(resolver.get_operations(), Ok(()));
        });
    }

    #[test]
    fn rebuild_pending_prefers_local_pending_anchor_before_fetch() {
        deterministic::Runner::default().start(|context| async move {
            let genesis_digest = Sha256::hash(b"genesis");
            let block1 = make_block(Height::new(1), genesis_digest, View::new(1));
            let block2 = make_block(Height::new(2), block1.digest(), View::new(2));

            let (mut actor, _mailbox) = Stateful::init(
                context.clone(),
                StatefulConfig {
                    app: TestApp,
                    db_config: (),
                    input_provider: (),
                    marshal: PanicOnFetchProvider,
                    mailbox_size: 16,
                    state_sync: test_state_sync_config::<TestApp>(),
                },
            );
            let mut pending = Pending::new();
            pending.insert(
                block2.digest(),
                Round::new(Epoch::zero(), View::new(2)),
                TestMerkleized,
            );
            actor.mode = Mode::Running {
                databases: TestDatabases,
                pending,
                finalized_digest: block1.digest(),
            };

            let (mut response, _rx) = oneshot::channel::<bool>();
            let rebuilt = actor.rebuild_pending(block2.digest(), &mut response).await;
            assert_eq!(
                rebuilt,
                Ok(()),
                "rebuild should anchor on existing pending state without provider fetch"
            );
        });
    }
}
