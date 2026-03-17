//! Database batch lifecycle and sync orchestration traits for stateful applications.
//!
//! This module defines the traits that bridge the [`Stateful`](super::Stateful)
//! wrapper with the underlying storage layer (QMDB). The batch lifecycle has
//! three stages:
//!
//! 1. [`Unmerkleized`]: an in-progress batch of reads and writes.
//! 2. [`Merkleized`]: a sealed batch whose state root has been computed.
//! 3. Finalization: applying a merkleized batch's changeset to the
//!    database via [`ManagedDb::finalize`].
//!
//! [`DatabaseSet`] composes one or more [`ManagedDb`] instances into a single
//! unit that the wrapper manages as a group.

use commonware_cryptography::Digest;
use commonware_utils::sync::AsyncRwLock;
use futures::join;
use std::{fmt::Debug, future::Future, sync::Arc};

mod any;

/// An in-progress batch of mutations that has not yet been merkleized.
///
/// The application reads state via [`get`](Self::get), writes mutations via
/// [`write`](Self::write), and seals the batch by calling
/// [`merkleize`](Self::merkleize) at the end of execution.
pub trait Unmerkleized: Sized + Send {
    /// The key type for this database.
    type Key: Send;

    /// The value type for this database.
    type Value: Send;

    /// The merkleized batch produced by [`merkleize`](Self::merkleize).
    type Merkleized: Merkleized;

    /// The error type returned by fallible operations.
    type Error: Send;

    /// Read a value by key.
    ///
    /// Returns the most recent mutation in this batch's chain, falling back
    /// to the committed database state.
    fn get(
        &self,
        key: &Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Self::Error>> + Send;

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    fn write(self, key: Self::Key, value: Option<Self::Value>) -> Self;

    /// Resolve all mutations, compute the new state root, and produce a
    /// merkleized batch.
    fn merkleize(self) -> impl Future<Output = Result<Self::Merkleized, Self::Error>> + Send;
}

/// A sealed batch whose state root has been computed.
///
/// The application inspects the [`root`](Self::root) to embed in a block
/// header. The wrapper stores the batch as pending and later finalizes it.
pub trait Merkleized: Sized + Send + Sync {
    /// The digest type used for the state root.
    type Digest: Digest;

    /// The unmerkleized batch type produced by [`new_batch`](Self::new_batch).
    type Unmerkleized: Unmerkleized;

    /// The committed state root after merkleization.
    fn root(&self) -> Self::Digest;

    /// Create a child unmerkleized batch that reads through this batch's
    /// pending changes before falling back to the committed database state.
    ///
    /// In QMDB, this maps to `merkleized_batch.new_batch()`.
    fn new_batch(&self) -> Self::Unmerkleized;
}

/// A single database whose batch lifecycle is managed by the
/// [`Stateful`](super::Stateful) wrapper.
///
/// Each instance wraps a QMDB database and knows how to create
/// unmerkleized batches from committed state and how to persist a
/// finalized changeset. Child batches (forked from pending state) are
/// created via [`Merkleized::new_batch`] instead.
///
/// [`new_batch`](Self::new_batch) receives the outer
/// `Arc<AsyncRwLock<Self>>` so that implementations whose batch types
/// need read-through access to committed state (e.g. QMDB) can
/// capture the reference.
pub trait ManagedDb: Send + Sync {
    /// An in-progress batch of mutations that has not yet been merkleized.
    type Unmerkleized: Unmerkleized;

    /// A batch whose root has been computed but has not yet been applied to
    /// the underlying database.
    ///
    /// Constrained so that [`Merkleized::new_batch`] produces the same
    /// [`Unmerkleized`] type as [`ManagedDb::new_batch`](Self::new_batch).
    type Merkleized: Merkleized<Unmerkleized = Self::Unmerkleized>;

    /// The error type returned by fallible operations.
    type Error: Debug + Send;

    /// Create a new unmerkleized batch rooted at the database's committed
    /// state.
    ///
    /// The `db` parameter is the `Arc<AsyncRwLock<Self>>` that wraps this
    /// database, allowing batch types to capture a shared reference for
    /// read-through to committed state.
    fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> impl Future<Output = Self::Unmerkleized> + Send;

    /// Apply a merkleized batch's changeset to the underlying database.
    ///
    /// In QMDB, this encapsulates calling `merkleized.finalize()` to produce
    /// a `Changeset`, then `db.apply_batch(changeset)` and `db.commit()`.
    fn finalize(
        &mut self,
        batch: Self::Merkleized,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// A collection of individually-locked [`ManagedDb`] instances.
///
/// Each database is wrapped in `Arc<AsyncRwLock<...>>` so that the set can be
/// cheaply cloned (for consensus) and individual databases can be shared with
/// external services (RPC, state sync) without a global lock.
pub trait DatabaseSet: Clone + Send + Sync + 'static {
    /// Tuple of [`ManagedDb::Unmerkleized`] for every database in the set.
    type Unmerkleized: Send;

    /// Tuple of [`ManagedDb::Merkleized`] for every database in the set.
    type Merkleized: Send + Sync;

    /// Create unmerkleized batches from each database's committed state.
    ///
    /// Acquires a read lock on each database.
    fn new_batches(&self) -> impl Future<Output = Self::Unmerkleized> + Send;

    /// Create child unmerkleized batches from a pending merkleized parent.
    ///
    /// No lock is needed; reads come from the in-memory merkleized state.
    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized;

    /// Apply each merkleized batch's changeset to its underlying database.
    ///
    /// Acquires a write lock on each database.
    fn finalize(&self, batches: Self::Merkleized) -> impl Future<Output = ()> + Send;
}

async fn finalize_or_panic<T: ManagedDb>(
    database: &mut T,
    batch: T::Merkleized,
    index: Option<usize>,
) {
    // Mutable finalize failures are fatal by design because other databases in
    // the same set may already have committed, leaving partially applied state.
    if let Err(err) = database.finalize(batch).await {
        match index {
            Some(index) => panic!(
                "database finalize failed (index {index}, type {}): {err:?}",
                core::any::type_name::<T>(),
            ),
            None => panic!(
                "database finalize failed (type {}): {err:?}",
                core::any::type_name::<T>(),
            ),
        }
    }
}

/// Implement [`DatabaseSet`] for a single [`ManagedDb`] behind a lock.
impl<T: ManagedDb + 'static> DatabaseSet for Arc<AsyncRwLock<T>> {
    type Unmerkleized = T::Unmerkleized;
    type Merkleized = T::Merkleized;

    async fn new_batches(&self) -> Self::Unmerkleized {
        T::new_batch(self).await
    }

    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
        parent.new_batch()
    }

    async fn finalize(&self, batches: Self::Merkleized) {
        let mut database = self.write().await;
        finalize_or_panic(&mut *database, batches, None).await;
    }
}

/// Implement [`DatabaseSet`] for a tuple of individually-locked
/// [`ManagedDb`] instances.
macro_rules! impl_database_set {
    ($($T:ident : $idx:tt),+) => {
        impl<$($T: ManagedDb + 'static),+> DatabaseSet
            for ($(Arc<AsyncRwLock<$T>>,)+)
        {
            type Unmerkleized = ($($T::Unmerkleized,)+);
            type Merkleized = ($($T::Merkleized,)+);

            async fn new_batches(&self) -> Self::Unmerkleized {
                join!($($T::new_batch(&self.$idx),)+)
            }

            fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
                ($(parent.$idx.new_batch(),)+)
            }

            async fn finalize(&self, batches: Self::Merkleized) {
                join!($(
                    async {
                        let mut database = self.$idx.write().await;
                        finalize_or_panic(&mut *database, batches.$idx, Some($idx)).await;
                    },
                )+);
            }
        }
    };
}

impl_database_set!(DB1: 0);
impl_database_set!(DB1: 0, DB2: 1);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4, DB6: 5);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4, DB6: 5, DB7: 6);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4, DB6: 5, DB7: 6, DB8: 7);

#[cfg(test)]
mod tests {
    use super::{DatabaseSet, ManagedDb, Merkleized, Unmerkleized};
    use commonware_cryptography::sha256;
    use commonware_utils::{channel::oneshot, sync::AsyncRwLock};
    use futures::{pin_mut, FutureExt};
    use std::{convert::Infallible, sync::Arc};

    #[derive(Clone, Copy)]
    struct TestUnmerkleized;

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
        type Digest = sha256::Digest;
        type Unmerkleized = TestUnmerkleized;

        fn root(&self) -> Self::Digest {
            sha256::Digest::from([0; 32])
        }

        fn new_batch(&self) -> Self::Unmerkleized {
            TestUnmerkleized
        }
    }

    #[derive(Default)]
    struct TestDb;

    impl ManagedDb for TestDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;

        async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            let _guard = db.read().await;
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct BlockingFinalizeDb {
        started: Option<oneshot::Sender<()>>,
        release: Option<oneshot::Receiver<()>>,
    }

    impl BlockingFinalizeDb {
        fn new(started: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
            Self {
                started: Some(started),
                release: Some(release),
            }
        }
    }

    #[derive(Debug)]
    struct TestFinalizeError;

    struct FailingFinalizeDb;

    impl ManagedDb for FailingFinalizeDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = TestFinalizeError;

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Err(TestFinalizeError)
        }
    }

    impl ManagedDb for BlockingFinalizeDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            if let Some(release) = self.release.take() {
                let _ = release.await;
            }
            Ok(())
        }
    }

    #[test]
    fn tuple_new_batches_queues_reads_concurrently() {
        futures::executor::block_on(async move {
            let db1 = Arc::new(AsyncRwLock::new(TestDb));
            let db2 = Arc::new(AsyncRwLock::new(TestDb));
            let databases = (db1.clone(), db2.clone());

            let writer1 = db1.write().await;
            let writer2 = db2.write().await;

            let new_batches = databases.new_batches();
            pin_mut!(new_batches);
            assert!(new_batches.as_mut().now_or_never().is_none());

            drop(writer2);
            let writer2_again = db2.write();
            pin_mut!(writer2_again);
            assert!(
                writer2_again.as_mut().now_or_never().is_none(),
                "tuple new_batches should queue reads for all databases concurrently"
            );

            drop(writer1);
            drop(writer2_again);
            let _ = new_batches.await;
        });
    }

    #[test]
    fn tuple_finalize_runs_databases_in_parallel() {
        futures::executor::block_on(async move {
            let (started1_tx, started1_rx) = oneshot::channel();
            let (started2_tx, started2_rx) = oneshot::channel();
            let (release1_tx, release1_rx) = oneshot::channel();
            let (release2_tx, release2_rx) = oneshot::channel();

            let databases = (
                Arc::new(AsyncRwLock::new(BlockingFinalizeDb::new(
                    started1_tx,
                    release1_rx,
                ))),
                Arc::new(AsyncRwLock::new(BlockingFinalizeDb::new(
                    started2_tx,
                    release2_rx,
                ))),
            );

            let finalize = databases.finalize((TestMerkleized, TestMerkleized));
            pin_mut!(finalize);
            assert!(finalize.as_mut().now_or_never().is_none());

            let started1 = started1_rx;
            let started2 = started2_rx;
            pin_mut!(started1);
            pin_mut!(started2);
            assert!(matches!(started1.as_mut().now_or_never(), Some(Ok(()))));
            assert!(
                matches!(started2.as_mut().now_or_never(), Some(Ok(()))),
                "tuple finalize should start all database finalizations concurrently"
            );

            let _ = release1_tx.send(());
            let _ = release2_tx.send(());
            finalize.await;
        });
    }

    #[test]
    fn tuple_finalize_panic_identifies_failing_database() {
        let panic = std::panic::catch_unwind(|| {
            futures::executor::block_on(async move {
                let databases = (
                    Arc::new(AsyncRwLock::new(TestDb)),
                    Arc::new(AsyncRwLock::new(FailingFinalizeDb)),
                );
                databases.finalize((TestMerkleized, TestMerkleized)).await;
            });
        })
        .expect_err("tuple finalize should panic when a database finalize fails");

        let panic = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&'static str>().copied())
            .expect("panic should be a string");
        assert!(
            panic.contains("index 1"),
            "panic should identify the failing database index: {panic}"
        );
        assert!(
            panic.contains("FailingFinalizeDb"),
            "panic should identify the failing database type: {panic}"
        );
    }
}
