//! Consensus-facing wrapper that manages pending state on behalf of a
//! stateful application.
//!
//! [`Stateful`] implements the consensus [`Application`](ConsensusApplication)
//! and [`VerifyingApplication`](ConsensusVerifyingApplication) traits by
//! delegating execution to the inner [`Application`] while managing the
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
//! known ancestor, then replays forward via [`Application::replay`]. Each
//! replayed block is inserted into the pending map immediately so that
//! partial progress survives timeouts.
//!
//! TODO:
//! - Ensure cancellation safety of all async operations, to support the
//!   consensus timeout.

use crate::stateful::{
    actor::{mailbox::Message, ErasedAncestorStream, Mailbox},
    db::DatabaseSet,
    Application,
};
use commonware_consensus::{
    marshal::ancestry::BlockProvider, types::Round, Block, CertifiableBlock, Epochable, Viewable,
};
use commonware_cryptography::Digestible;
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::channel::{fallible::OneshotExt, mpsc, oneshot};
use rand::Rng;
use std::collections::HashMap;
use tracing::debug;

type PendingDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type PendingBatches<A, E> = <<A as Application<E>>::Databases as DatabaseSet>::Merkleized;
type PendingEntry<A, E> = (Round, PendingBatches<A, E>);

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

/// Configuration for constructing a [`Stateful`] wrapper.
pub struct Config<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    /// The inner application that drives state transitions.
    pub app: A,

    /// The set of databases whose batch lifecycle is managed by the wrapper.
    pub databases: A::Databases,

    /// Source of input (e.g. transactions) passed to the application on
    /// propose.
    pub input_provider: A::InputProvider,

    /// Provider for fetching blocks during lazy recovery.
    pub block_provider: P,
}

/// Wraps an [`Application`] and manages the pending-tip DAG of merkleized
/// batches on its behalf, implementing the consensus
/// [`Application`](ConsensusApplication) and
/// [`VerifyingApplication`](ConsensusVerifyingApplication) traits.
///
/// When a parent block's pending state is missing (e.g. after a restart),
/// the wrapper lazily rebuilds it by walking back through the block DAG
/// via the [`BlockProvider`] and replaying forward via
/// [`Application::replay`].
pub struct Stateful<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    /// Runtime context providing RNG, task spawning, metrics, and clock.
    context: ContextCell<E>,

    /// The receiver for messages.
    mailbox: mpsc::Receiver<Message<E, A>>,

    /// The inner application that drives state transitions.
    inner: A,

    /// The set of databases whose batch lifecycle is managed by this wrapper.
    databases: A::Databases,

    /// Source of input (e.g. transactions) passed to the application on propose.
    input_provider: A::InputProvider,

    /// Provider for fetching blocks during lazy recovery.
    block_provider: P,

    /// The latest observed finalized block digest.
    finalized_digest: Option<<A::Block as Digestible>::Digest>,

    /// Pending merkleized batches keyed by block digest, tagged with the round
    /// in which they were produced.
    pending: Pending<A, E>,
}

impl<E, A, P> Stateful<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    pub fn init(context: E, config: Config<E, A, P>) -> (Self, Mailbox<E, A>) {
        // TODO: Config channel size.
        let (sender, mailbox) = mpsc::channel(16);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                inner: config.app,
                databases: config.databases,
                input_provider: config.input_provider,
                block_provider: config.block_provider,
                finalized_digest: None,
                pending: Pending::new(),
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
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
                    Message::Finalized { round, digest } => {
                        self.handle_finalized(round, digest).await;
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
        context: (E, A::Context),
        ancestry: ErasedAncestorStream<A::Block>,
        response: oneshot::Sender<Option<A::Block>>,
    ) {
        // TODO: Return `None` immediately if we are currently state syncing.

        // The ancestry stream starts from the parent block.
        let Some(parent) = ancestry.peek() else {
            response.send_lossy(None);
            return;
        };
        let parent_digest = parent.digest();

        // Ensure we have the pending state necessary to verify
        // this block, rebuilding it if necessary.
        self.ensure_pending(parent_digest).await;

        // Build the block and persist the pending state.
        let round = Round::new(context.1.epoch(), context.1.view());
        let batches = self.start_batches(&parent_digest).await;
        let Some((block, merkleized)) = self
            .inner
            .propose(context, ancestry, batches, &mut self.input_provider)
            .await
        else {
            response.send_lossy(None);
            return;
        };
        self.pending.insert(block.digest(), round, merkleized);

        // Send the built block back to the application.
        response.send_lossy(Some(block));
    }

    /// Handles a [`Message::Verify`].
    async fn handle_verify(
        &mut self,
        (runtime_context, consensus_context): (E, A::Context),
        ancestry: ErasedAncestorStream<A::Block>,
        response: oneshot::Sender<bool>,
    ) {
        // TODO: Wait until state sync has completed, or the response is dropped,
        // if state sync is active.

        let Some(block) = ancestry.peek() else {
            response.send_lossy(false);
            return;
        };
        let block_digest = block.digest();
        let parent_digest = block.parent();

        // Ensure we have the pending state necessary to verify
        // this block, rebuilding it if necessary.
        self.ensure_pending(parent_digest).await;

        // Execute the block and persist the pending state.
        let round = Round::new(consensus_context.epoch(), consensus_context.view());
        let batches = self.start_batches(&parent_digest).await;
        let Some(merkleized) = self
            .inner
            .verify((runtime_context, consensus_context), ancestry, batches)
            .await
        else {
            response.send_lossy(false);
            return;
        };
        self.pending.insert(block_digest, round, merkleized);

        // Inform the application that the block is valid.
        response.send_lossy(true);
    }

    /// Handles a [`Message::Finalized`].
    async fn handle_finalized(&mut self, round: Round, digest: <A::Block as Digestible>::Digest) {
        // TODO: Forward sync target.

        // Duplicate finalization reports are benign. A node may
        // observe the same finalization certificate multiple times
        // from replay or the network.
        if self.finalized_digest == Some(digest) {
            return;
        }

        let mut batch = self.pending.remove(&digest);
        if batch.is_none() {
            self.rebuild_pending(digest).await;
            batch = self.pending.remove(&digest);
        }

        let Some((_, batch)) = batch else {
            debug!(
                "finalized digest {} is missing pending state, skipping",
                digest
            );
            return;
        };
        self.databases.finalize(batch).await;

        self.finalized_digest = Some(digest);
        self.pending.retain_newer_than(round);
    }

    /// Fork unmerkleized batches for building on top of `parent`.
    ///
    /// If the parent's merkleized state is in the pending map, creates
    /// child batches from it. Otherwise (parent is the finalized tip),
    /// creates batches from the committed database state.
    async fn start_batches(
        &mut self,
        parent: &<A::Block as Digestible>::Digest,
    ) -> <A::Databases as DatabaseSet>::Unmerkleized {
        let forked = self
            .pending
            .get_merkleized(parent)
            .map(<A::Databases as DatabaseSet>::fork_batches);
        match forked {
            Some(batches) => batches,
            None => self.databases.new_batches().await,
        }
    }

    /// Lazily rebuild pending state for `parent` if needed.
    ///
    /// Rebuilds when at least one finalization has occurred, the parent is
    /// not the finalized tip, and its pending state is missing.
    async fn ensure_pending(&mut self, parent: <A::Block as Digestible>::Digest) {
        let needs_rebuild = {
            self.finalized_digest.is_some_and(|fd| fd != parent) && !self.pending.contains(&parent)
        };
        if needs_rebuild {
            self.rebuild_pending(parent).await;
        }
    }

    /// Walk back from `target` to the nearest known ancestor (either in
    /// the pending map or the finalized tip), then replay forward to
    /// populate the pending map with the missing chain segment.
    ///
    /// Each replayed block's merkleized state is inserted into the pending
    /// map immediately so that partial progress survives timeouts.
    async fn rebuild_pending(&mut self, target: <A::Block as Digestible>::Digest) {
        // Walk back, collecting blocks whose pending state is missing.
        let mut to_replay = Vec::new();
        let mut current = target;

        loop {
            // Stop if we have reached the finalized tip. Its state is
            // already committed to the database, so there is nothing to
            // replay and the block provider (marshal) cannot serve the
            // genesis block that lies beyond it.
            {
                if let Some(fd) = &self.finalized_digest {
                    if current == *fd {
                        break;
                    }
                }
            }

            let Some(block) = self.block_provider.clone().fetch_block(current).await else {
                // Reached end of chain (e.g. genesis parent).
                break;
            };

            if self.pending.contains(&block.digest()) {
                break;
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

            let batches = self.start_batches(&parent_digest).await;
            let replay_context = self.context.clone().into_present();
            let merkleized = self
                .inner
                .replay((replay_context, consensus_context), &block, batches)
                .await;

            self.pending.insert(digest, round, merkleized);
        }
    }
}
