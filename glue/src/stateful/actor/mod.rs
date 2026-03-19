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
//! walks back through the block DAG via `BlockProvider` to the nearest
//! known ancestor, then replays forward via `Application::apply`. Each
//! replayed block is inserted into the pending map immediately so that
//! partial progress survives timeouts.

mod mailbox;
pub use mailbox::Mailbox;

mod core;
pub use core::{Config, Startup, StateSyncConfig, Stateful};

mod bootstrap;
