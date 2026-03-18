//! QMDB sync resolver service backed by `commonware-resolver` P2P.
//!
//! This module provides:
//! - [`Mailbox`]: a client-facing resolver that implements
//!   [`commonware_storage::qmdb::sync::resolver::Resolver`]
//! - [`Actor`]: a service actor that runs [`commonware_resolver::p2p::Engine`]
//!   to fetch from peers and serve local operations
//! - [`SyncableDb`]: a trait for [`ManagedDb`]
//!   implementations that can serve sync operation requests.

mod actor;
mod mailbox;

use crate::stateful::db::ManagedDb;
pub use actor::{Actor, Config};
use commonware_storage::qmdb::sync::resolver::{FetchResult, Resolver as SyncResolver};
use commonware_utils::sync::AsyncRwLock;
pub use mailbox::{Error, Mailbox, Request};
use std::{future::Future, num::NonZeroU64, sync::Arc};

/// Runtime serving state for a resolver actor.
pub enum State<DB> {
    /// Database is not attached yet.
    NoDb,
    /// Database is attached and can serve incoming requests.
    HasDb(Arc<AsyncRwLock<DB>>),
}

/// A resolver mailbox that can attach a database at runtime.
pub trait AttachableResolver<DB>: Clone + Send + Sync + 'static {
    /// Attach a database for serving incoming requests.
    fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) -> impl Future<Output = ()> + Send;
}

/// Attach a database set to a resolver set with matching shape.
pub trait AttachableResolverSet<DBs>: Clone + Send + Sync + 'static {
    /// Attach all databases to their corresponding resolvers.
    fn attach_databases(&self, databases: DBs) -> impl Future<Output = ()> + Send;
}

impl<R, DB> AttachableResolverSet<Arc<AsyncRwLock<DB>>> for R
where
    R: AttachableResolver<DB>,
    DB: Send + Sync + 'static,
{
    async fn attach_databases(&self, db: Arc<AsyncRwLock<DB>>) {
        self.attach_database(db).await;
    }
}

macro_rules! impl_attachable_resolver_set {
    ($($R:ident : $DB:ident : $idx:tt),+) => {
        impl<$($R, $DB),+> AttachableResolverSet<($(Arc<AsyncRwLock<$DB>>,)+)> for ($($R,)+)
        where
            $(
                $R: AttachableResolver<$DB>,
                $DB: Send + Sync + 'static,
            )+
        {
            async fn attach_databases(&self, databases: ($(Arc<AsyncRwLock<$DB>>,)+)) {
                futures::join!($(
                    self.$idx.attach_database(databases.$idx),
                )+);
            }
        }
    };
}

impl_attachable_resolver_set!(R1: DB1: 0, R2: DB2: 1);
impl_attachable_resolver_set!(R1: DB1: 0, R2: DB2: 1, R3: DB3: 2);
impl_attachable_resolver_set!(R1: DB1: 0, R2: DB2: 1, R3: DB3: 2, R4: DB4: 3);
impl_attachable_resolver_set!(R1: DB1: 0, R2: DB2: 1, R3: DB3: 2, R4: DB4: 3, R5: DB5: 4);
impl_attachable_resolver_set!(
    R1: DB1: 0,
    R2: DB2: 1,
    R3: DB3: 2,
    R4: DB4: 3,
    R5: DB5: 4,
    R6: DB6: 5
);
impl_attachable_resolver_set!(
    R1: DB1: 0,
    R2: DB2: 1,
    R3: DB3: 2,
    R4: DB4: 3,
    R5: DB5: 4,
    R6: DB6: 5,
    R7: DB7: 6
);
impl_attachable_resolver_set!(
    R1: DB1: 0,
    R2: DB2: 1,
    R3: DB3: 2,
    R4: DB4: 3,
    R5: DB5: 4,
    R6: DB6: 5,
    R7: DB7: 6,
    R8: DB8: 7
);

/// A [`ManagedDb`] that can serve QMDB sync operations.
pub trait SyncableDb<E>: ManagedDb<E> + Send + Sync + 'static {
    /// The digest type used in MMR proofs.
    type SyncDigest: commonware_cryptography::Digest;

    /// The operation type returned by sync fetches.
    type SyncOp;

    /// Error returned while serving sync requests.
    type SyncError: std::error::Error + Send + 'static;

    /// Serve a sync operation fetch request against this database.
    fn get_operations(
        db: &Arc<AsyncRwLock<Self>>,
        op_count: commonware_storage::mmr::Location,
        start_loc: commonware_storage::mmr::Location,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
    ) -> impl Future<Output = Result<FetchResult<Self::SyncOp, Self::SyncDigest>, Self::SyncError>> + Send;
}

impl<E, DB> SyncableDb<E> for DB
where
    DB: ManagedDb<E> + Send + Sync + 'static,
    Arc<AsyncRwLock<DB>>: SyncResolver,
    <Arc<AsyncRwLock<DB>> as SyncResolver>::Error: std::error::Error + Send + 'static,
{
    type SyncDigest = <Arc<AsyncRwLock<DB>> as SyncResolver>::Digest;
    type SyncOp = <Arc<AsyncRwLock<DB>> as SyncResolver>::Op;
    type SyncError = <Arc<AsyncRwLock<DB>> as SyncResolver>::Error;

    async fn get_operations(
        db: &Arc<AsyncRwLock<Self>>,
        op_count: commonware_storage::mmr::Location,
        start_loc: commonware_storage::mmr::Location,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
    ) -> Result<FetchResult<Self::SyncOp, Self::SyncDigest>, Self::SyncError> {
        db.get_operations(op_count, start_loc, max_ops, include_pinned_nodes)
            .await
    }
}

impl<P, Op, D, DB> AttachableResolver<DB> for Mailbox<P, Op, D, DB>
where
    P: commonware_cryptography::PublicKey,
    Op: commonware_codec::Read<Cfg = ()> + Send + Sync + Clone + 'static,
    D: commonware_cryptography::Digest,
    DB: Send + Sync + 'static,
{
    async fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) {
        self.attach_database(db).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{AttachableResolver, AttachableResolverSet};
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::sync::{AsyncRwLock, Mutex};
    use std::sync::Arc;

    #[derive(Default)]
    struct Db1;

    #[derive(Default)]
    struct Db2;

    #[derive(Clone)]
    struct RecordingResolver {
        id: &'static str,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RecordingResolver {
        fn new(id: &'static str, log: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self { id, log }
        }
    }

    impl<DB: Send + Sync + 'static> AttachableResolver<DB> for RecordingResolver {
        async fn attach_database(&self, _db: Arc<AsyncRwLock<DB>>) {
            self.log.lock().push(self.id);
        }
    }

    #[test]
    fn single_db_attach_calls_single_resolver() {
        deterministic::Runner::default().start(|_| async move {
            let log = Arc::new(Mutex::new(Vec::new()));
            let resolver = RecordingResolver::new("db1", log.clone());
            let db = Arc::new(AsyncRwLock::new(Db1));

            resolver.attach_databases(db).await;
            assert_eq!(&*log.lock(), &["db1"]);
        });
    }

    #[test]
    fn tuple_attach_is_index_stable() {
        deterministic::Runner::default().start(|_| async move {
            let log = Arc::new(Mutex::new(Vec::new()));
            let resolvers = (
                RecordingResolver::new("resolver_0", log.clone()),
                RecordingResolver::new("resolver_1", log.clone()),
            );
            let databases = (
                Arc::new(AsyncRwLock::new(Db1)),
                Arc::new(AsyncRwLock::new(Db2)),
            );

            resolvers.attach_databases(databases).await;
            assert_eq!(&*log.lock(), &["resolver_0", "resolver_1"]);
        });
    }

    #[test]
    fn heterogeneous_tuple_attach_compiles() {
        deterministic::Runner::default().start(|_| async move {
            let log = Arc::new(Mutex::new(Vec::new()));
            let resolvers = (
                RecordingResolver::new("db1", log.clone()),
                RecordingResolver::new("db2", log.clone()),
            );
            let db1 = Arc::new(AsyncRwLock::new(Db1));
            let db2 = Arc::new(AsyncRwLock::new(Db2));
            let databases = (db1, db2);

            resolvers.attach_databases(databases).await;
            assert_eq!(&*log.lock(), &["db1", "db2"]);
        });
    }
}
