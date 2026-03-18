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
use commonware_runtime::{Metrics, Spawner};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc},
    sync::AsyncRwLock,
};
use futures::join;
use std::{
    fmt::Debug,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

pub mod qmdb;

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
///
/// The context parameter `E` is a generic on the trait (not an
/// associated type) so that a single database type can be used with
/// any runtime that satisfies the bounds.
pub trait ManagedDb<E>: Send + Sync + Sized {
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

    /// Configuration needed to construct a new database instance.
    type Config: Clone + Send;

    /// Sync target type for state sync of this database.
    ///
    /// Typically [`Target<Digest>`](commonware_storage::qmdb::sync::Target).
    type SyncTarget: Clone + Send + Sync;

    /// Construct a new database from its configuration.
    fn init(
        context: E,
        config: Self::Config,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;

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
///
/// The context parameter `E` is a generic on the trait (not an
/// associated type) so that a single set type can be used with any
/// runtime that satisfies the bounds.
pub trait DatabaseSet<E>: Clone + Send + Sync + 'static {
    /// Tuple of [`ManagedDb::Unmerkleized`] for every database in the set.
    type Unmerkleized: Send;

    /// Tuple of [`ManagedDb::Merkleized`] for every database in the set.
    type Merkleized: Send + Sync;

    /// Configuration needed to construct every database in the set.
    ///
    /// - Single database sets use that database's [`ManagedDb::Config`].
    /// - Multi-database tuple sets use a tuple of per-database configs
    ///   `(Db1::Config, Db2::Config, ...)`.
    type Config: Clone + Send;

    /// Per-database sync targets extracted from a finalized block.
    ///
    /// For a single-database set this is typically
    /// [`Target<Digest>`](commonware_storage::qmdb::sync::Target). For
    /// multi-database sets it is a tuple of targets, one per database.
    type SyncTargets: Clone + Send + Sync;

    /// Construct the database set from its configuration.
    fn init(context: E, config: Self::Config) -> impl Future<Output = Self> + Send;

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

/// Parameters for a one-time state-sync pass.
#[derive(Clone, Copy, Debug)]
pub struct SyncEngineConfig {
    /// Maximum operations fetched per resolver request.
    pub fetch_batch_size: NonZeroU64,

    /// Number of operations applied per local apply step.
    pub apply_batch_size: usize,

    /// Maximum number of outstanding resolver requests.
    pub max_outstanding_requests: usize,

    /// Capacity of per-database target-update channels.
    pub update_channel_size: NonZeroUsize,
}

/// A [`ManagedDb`] that can be initialized by state-sync.
///
/// This trait is only used during startup to build the initial database state.
/// Normal consensus operation uses [`ManagedDb`] and [`DatabaseSet`].
pub trait StateSyncDb<E, R>: ManagedDb<E> {
    /// Error returned by the state-sync engine for this database.
    type SyncError: Debug + Send;

    /// Run state-sync for this database and return a fully-initialized instance.
    fn sync_db(
        context: E,
        config: Self::Config,
        resolver: R,
        target: Self::SyncTarget,
        tip_updates: Option<mpsc::Receiver<Self::SyncTarget>>,
        sync_config: SyncEngineConfig,
    ) -> impl Future<Output = Result<Self, Self::SyncError>> + Send;
}

/// A [`DatabaseSet`] that can perform one-time startup state-sync.
///
/// `R` is the resolver shape for this set:
/// - single database: a single resolver instance
/// - tuple database set: a tuple of resolver instances, one per database
pub trait StateSyncSet<E, R>: DatabaseSet<E> {
    /// Error returned if any database in the set fails startup state-sync.
    type Error: Debug + Send;

    /// Run one-time startup state-sync and return the initialized set.
    fn sync(
        context: E,
        config: Self::Config,
        resolvers: R,
        targets: Self::SyncTargets,
        tip_updates: Option<mpsc::Receiver<Self::SyncTargets>>,
        sync_config: SyncEngineConfig,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;
}

/// Implement [`DatabaseSet`] for a single [`ManagedDb`] behind a lock.
impl<E: Clone + Send + Sync, T: ManagedDb<E> + 'static> DatabaseSet<E> for Arc<AsyncRwLock<T>> {
    type Unmerkleized = T::Unmerkleized;
    type Merkleized = T::Merkleized;
    type Config = T::Config;
    type SyncTargets = T::SyncTarget;

    async fn init(context: E, config: Self::Config) -> Self {
        let db = T::init(context, config)
            .await
            .expect("database init failed");
        Self::new(AsyncRwLock::new(db))
    }

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

impl<E, T, R> StateSyncSet<E, R> for Arc<AsyncRwLock<T>>
where
    E: Clone + Send + Sync,
    T: StateSyncDb<E, R> + 'static,
    R: Clone + Send + 'static,
{
    type Error = T::SyncError;

    async fn sync(
        context: E,
        config: Self::Config,
        resolver: R,
        target: Self::SyncTargets,
        tip_updates: Option<mpsc::Receiver<Self::SyncTargets>>,
        sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::Error> {
        let database =
            T::sync_db(context, config, resolver, target, tip_updates, sync_config).await?;
        Ok(Self::new(AsyncRwLock::new(database)))
    }
}

/// Implement [`DatabaseSet`] for a tuple of individually-locked
/// [`ManagedDb`] instances.
macro_rules! impl_database_set {
    ($($T:ident : $idx:tt),+) => {
        impl<E: Clone + Send + Sync, $($T: ManagedDb<E> + 'static),+> DatabaseSet<E>
            for ($(Arc<AsyncRwLock<$T>>,)+)
        {
            type Unmerkleized = ($($T::Unmerkleized,)+);
            type Merkleized = ($($T::Merkleized,)+);
            type Config = ($($T::Config,)+);
            type SyncTargets = ($($T::SyncTarget,)+);

            async fn init(context: E, config: Self::Config) -> Self {
                let result = join!($(
                    async {
                        let db = $T::init(context.clone(), config.$idx)
                            .await
                            .expect(concat!(
                                "database init failed (index ",
                                stringify!($idx),
                                ", type ",
                                stringify!($T),
                                ")",
                            ));
                        Arc::new(AsyncRwLock::new(db))
                    },
                )+);
                result
            }

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

macro_rules! impl_state_sync_set {
    ($($T:ident : $R:ident : $idx:tt),+) => {
        impl<E, $($T, $R),+> StateSyncSet<E, ($($R,)+)> for ($(Arc<AsyncRwLock<$T>>,)+)
        where
            E: Clone + Send + Sync + Spawner + Metrics,
            $(
                $T: StateSyncDb<E, $R> + 'static,
                $R: Clone + Send + 'static,
            )+
        {
            type Error = String;

            async fn sync(
                context: E,
                config: Self::Config,
                resolvers: ($($R,)+),
                targets: Self::SyncTargets,
                mut tip_updates: Option<mpsc::Receiver<Self::SyncTargets>>,
                sync_config: SyncEngineConfig,
            ) -> Result<Self, Self::Error> {
                let channels = ($({
                    let _ = $idx;
                    mpsc::channel(sync_config.update_channel_size.get())
                },)+);

                let fanout_handle = tip_updates.take().map(|mut tip_updates| {
                    let senders = ($(channels.$idx.0.clone(),)+);
                    context
                        .clone()
                        .with_label("state_sync_target_fanout")
                        .spawn(move |_| async move {
                            while let Some(targets) = tip_updates.recv().await {
                                $(
                                    if !senders.$idx.send_lossy(targets.$idx).await {
                                        return;
                                    }
                                )+
                            }
                        })
                });

                let synced = join!(
                    $(
                        async {
                            $T::sync_db(
                                context.clone(),
                                config.$idx,
                                resolvers.$idx,
                                targets.$idx,
                                Some(channels.$idx.1),
                                sync_config,
                            )
                            .await
                            .map(|database| Arc::new(AsyncRwLock::new(database)))
                            .map_err(|err| {
                                format!(
                                    "state sync failed (index {}, db {}): {err:?}",
                                    $idx,
                                    core::any::type_name::<$T>(),
                                )
                            })
                        },
                    )+
                );

                if let Some(handle) = fanout_handle {
                    handle.abort();
                }

                Ok(($(synced.$idx?,)+))
            }
        }
    };
}

impl_state_sync_set!(DB1: R1: 0, DB2: R2: 1);
impl_state_sync_set!(DB1: R1: 0, DB2: R2: 1, DB3: R3: 2);
impl_state_sync_set!(DB1: R1: 0, DB2: R2: 1, DB3: R3: 2, DB4: R4: 3);
impl_state_sync_set!(DB1: R1: 0, DB2: R2: 1, DB3: R3: 2, DB4: R4: 3, DB5: R5: 4);
impl_state_sync_set!(DB1: R1: 0, DB2: R2: 1, DB3: R3: 2, DB4: R4: 3, DB5: R5: 4, DB6: R6: 5);
impl_state_sync_set!(
    DB1: R1: 0,
    DB2: R2: 1,
    DB3: R3: 2,
    DB4: R4: 3,
    DB5: R5: 4,
    DB6: R6: 5,
    DB7: R7: 6
);
impl_state_sync_set!(
    DB1: R1: 0,
    DB2: R2: 1,
    DB3: R3: 2,
    DB4: R4: 3,
    DB5: R5: 4,
    DB6: R6: 5,
    DB7: R7: 6,
    DB8: R8: 7
);

async fn finalize_or_panic<E, T: ManagedDb<E>>(
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

    impl<E: Send> ManagedDb<E> for TestDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = ();

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self)
        }

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

    impl<E: Send> ManagedDb<E> for FailingFinalizeDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = TestFinalizeError;
        type Config = ();
        type SyncTarget = ();

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Err(TestFinalizeError)
        }
    }

    impl<E: Send> ManagedDb<E> for BlockingFinalizeDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = ();

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("BlockingFinalizeDb is constructed directly in tests")
        }

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

            let new_batches =
                <(Arc<AsyncRwLock<TestDb>>, Arc<AsyncRwLock<TestDb>>) as DatabaseSet<()>>::new_batches(&databases);
            pin_mut!(new_batches);
            assert!(new_batches.as_mut().now_or_never().is_none());

            drop(writer2);
            {
                let writer2_again = db2.write();
                pin_mut!(writer2_again);
                assert!(
                    writer2_again.as_mut().now_or_never().is_none(),
                    "tuple new_batches should queue reads for all databases concurrently"
                );
            }

            drop(writer1);
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

            let finalize = <(
                Arc<AsyncRwLock<BlockingFinalizeDb>>,
                Arc<AsyncRwLock<BlockingFinalizeDb>>,
            ) as DatabaseSet<()>>::finalize(
                &databases, (TestMerkleized, TestMerkleized)
            );
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
                <(
                    Arc<AsyncRwLock<TestDb>>,
                    Arc<AsyncRwLock<FailingFinalizeDb>>,
                ) as DatabaseSet<()>>::finalize(
                    &databases, (TestMerkleized, TestMerkleized)
                )
                .await;
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
