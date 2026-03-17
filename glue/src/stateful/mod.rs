//! Manage QMDB database instances on behalf of a stateful application.
//!
//! A stateful application built on consensus must maintain speculative state for
//! every pending chain built on top of the finalized tip. This module provides
//! the [`Application`] trait and a [`Stateful`] wrapper that automate
//! that bookkeeping:
//!
//! 1. Before each `propose` or `verify` call, the wrapper forks
//!    unmerkleized batches from the parent block's pending state (or from the
//!    committed database state if the parent has already been finalized).
//! 2. The application executes against those batches and returns merkleized
//!    results, which the wrapper stores as a new pending tip keyed by the
//!    block's digest.
//! 3. On finalization, the wrapper applies the winning tip's changesets to the
//!    underlying databases and prunes pending entries from dead forks.
//!
//! The [`db`] module defines the batch lifecycle traits ([`db::Unmerkleized`],
//! [`db::Merkleized`], [`db::ManagedDb`]) and a [`db::DatabaseSet`] trait that
//! extends this to tuples of databases, so applications can work with multiple
//! QMDB instances without manual plumbing.
//!
//! # Lazy Recovery
//!
//! Pending state is kept entirely in memory to avoid disk writes on the
//! consensus hot path. After a restart the map is empty, but the wrapper
//! recovers lazily: when `propose` or `verify` encounters a parent whose
//! state is missing, the wrapper walks back through the block DAG (via a
//! [`BlockProvider`]) to the nearest known ancestor or the finalized tip,
//! then replays forward via [`Application::replay`] to fill the gap. Each
//! replayed block is inserted into the pending map immediately so that
//! partial progress survives timeouts.

use commonware_consensus::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    CertifiableBlock, Epochable, Viewable,
};
use commonware_cryptography::certificate::Scheme;
use commonware_runtime::{Clock, Metrics, Spawner};
use db::DatabaseSet;
use rand::Rng;
use std::future::Future;

mod actor;
pub use actor::{Config, Mailbox, Stateful};

pub mod db;

#[cfg(test)]
mod tests;

/// A stateful application whose storage is managed by a [`DatabaseSet`].
///
/// Implementors receive [`DatabaseSet::Unmerkleized`] batches and
/// return [`DatabaseSet::Merkleized`] batches after execution. The surrounding
/// wrapper handles persistence: storing merkleized batches as pending tips on
/// the block tree and applying changesets to the underlying databases on
/// finalization.
pub trait Application<E>: Clone + Send + 'static
where
    E: Rng + Spawner + Metrics + Clock,
{
    /// The signing scheme used by the application.
    type SigningScheme: Scheme;

    /// Metadata provided by the consensus engine for a given block.
    ///
    /// This often includes things like the proposer, view number, height, or
    /// epoch. Must be [`Epochable`] and [`Viewable`] so the wrapper can
    /// construct a [`Round`](commonware_consensus::types::Round) for
    /// pending-state pruning.
    type Context: Epochable + Viewable + Send;

    /// The block type produced by the application.
    ///
    /// Must implement [`CertifiableBlock`] so the wrapper can extract
    /// the consensus context during lazy recovery (see
    /// [`apply`](Self::apply)).
    type Block: CertifiableBlock<Context = Self::Context>;

    /// The set of databases managed on behalf of this application.
    type Databases: DatabaseSet;

    /// A provider of input to the application.
    ///
    /// This may be a mempool that serves transactions, a stream of
    /// certificates, or any other source of input that drives state
    /// transitions.
    type InputProvider: Clone + Send;

    /// Block used to initialize the consensus engine in the first epoch.
    fn genesis(&mut self) -> impl Future<Output = Self::Block> + Send;

    /// Build a new block on top of the provided parent ancestry.
    ///
    /// Returns [`None`] if the build fails.
    ///
    /// This future may be cancelled by consensus if the caller drops its
    /// response receiver. Implementations should be cancellation-safe: dropping
    /// and retrying must not violate invariants or lose durable progress.
    fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> impl Future<Output = Option<(Self::Block, <Self::Databases as DatabaseSet>::Merkleized)>> + Send;

    /// Verify a block received from a peer, relative to its ancestry.
    ///
    /// Called before voting. The implementation should execute the block
    /// against the provided batches and merkleize them. Returns [`None`]
    /// only when the block is permanently invalid; if validity may still
    /// change as additional information arrives, continue waiting.
    ///
    /// This future may be cancelled by consensus if the caller drops its
    /// response receiver. Implementations should be cancellation-safe: dropping
    /// and retrying must not violate invariants or lose durable progress.
    fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized,
    ) -> impl Future<Output = Option<<Self::Databases as DatabaseSet>::Merkleized>> + Send;

    /// Apply a previously certified block to reconstruct its merkleized state.
    ///
    /// Called by the wrapper during lazy recovery when pending state for
    /// an ancestor block is missing (e.g. after a restart). The block is
    /// known-good (it was previously certified), so the implementation
    /// should unconditionally execute the block's state transitions.
    ///
    /// This future may be cancelled if the originating propose/verify request
    /// is dropped. Implementations should be cancellation-safe: dropping and
    /// retrying must not violate invariants or lose durable progress.
    ///
    /// # Panics
    ///
    /// Implementations should panic if execution fails, as this indicates
    /// data corruption or non-determinism.
    fn apply(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized,
    ) -> impl Future<Output = <Self::Databases as DatabaseSet>::Merkleized> + Send;
}
