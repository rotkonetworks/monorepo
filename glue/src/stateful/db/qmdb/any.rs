//! [`ManagedDb`] implementation for QMDB [`any`](commonware_storage::qmdb::any) databases.
//!
//! The QMDB batch API passes `&db` to `get()` and `merkleize()` for
//! read-through to committed state. The glue [`UnmerkleizedTrait`] trait
//! does not carry a DB reference, so this module provides wrapper types
//! that capture `Arc<AsyncRwLock<Db>>` alongside the raw batch.

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait,
};
use commonware_codec::{Codec, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    index::{
        unordered::Index as UnorderedIdx, Ordered as OrderedIndex, Unordered as UnorderedIndex,
    },
    journal::contiguous::{
        fixed::Journal as FixedJournal, variable::Journal as VariableJournal, Contiguous, Mutable,
    },
    mmr::Location,
    qmdb::{
        any::{
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            db::Db,
            operation::{update, Operation},
            value::{self, FixedEncoding, ValueEncoding, VariableEncoding},
            FixedConfig, VariableConfig,
        },
        operation::Key,
        sync, Error,
    },
    translator::Translator,
    Persistable,
};
use commonware_utils::{channel::mpsc, sync::AsyncRwLock, Array};
use std::{future::Future, sync::Arc};

type AnyDbHandle<E, C, I, H, U> = Arc<AsyncRwLock<Db<E, C, I, H, U>>>;

/// Wraps a QMDB [`UnmerkleizedBatch`] with a reference to the parent
/// database, allowing it to implement the glue [`Unmerkleized`](UnmerkleizedTrait)
/// trait (which does not carry a DB parameter).
pub struct AnyUnmerkleized<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    batch: UnmerkleizedBatch<H, U>,
    db: AnyDbHandle<E, C, I, H, U>,
}

/// Wraps a QMDB [`MerkleizedBatch`] with a reference to the parent
/// database, allowing it to implement the glue [`Merkleized`](MerkleizedTrait)
/// trait.
pub struct AnyMerkleized<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    batch: MerkleizedBatch<H::Digest, U>,
    db: AnyDbHandle<E, C, I, H, U>,
}

impl<E, C, I, H, U> AnyMerkleized<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Inactivity floor after merkleization.
    pub const fn inactivity_floor(&self) -> Location {
        self.batch.inactivity_floor()
    }

    /// Total operation count after merkleization.
    pub const fn size(&self) -> Location {
        self.batch.size()
    }
}

/// Adapter trait for update-kind-specific QMDB `init` methods.
///
/// Each concrete QMDB variant (fixed, variable, ordered, etc.) has its own
/// configuration and init implementation. This trait bridges the gap so that
/// the general [`ManagedDb`] impl on [`Db`] can delegate to the correct init.
pub trait InitAny<E>: Sized
where
    E: Storage + Clock + Metrics,
{
    type Config: Clone + Send;

    fn init_any(
        context: E,
        config: Self::Config,
    ) -> impl Future<Output = Result<Self, Error>> + Send;
}

/// Adapter trait for update-kind-specific QMDB `merkleize` methods.
trait MerkleizeAny<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Mutable<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    #[allow(clippy::manual_async_fn)]
    fn merkleize_any(
        self,
        db: &Db<E, C, I, H, U>,
    ) -> impl Future<Output = Result<MerkleizedBatch<H::Digest, U>, Error>> + Send;
}

impl<E, K, V, C, I, H> MerkleizeAny<E, C, I, H, update::Unordered<K, V>>
    for UnmerkleizedBatch<H, update::Unordered<K, V>>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<update::Unordered<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<update::Unordered<K, V>>: Codec,
{
    #[allow(clippy::manual_async_fn)]
    fn merkleize_any(
        self,
        db: &Db<E, C, I, H, update::Unordered<K, V>>,
    ) -> impl Future<Output = Result<MerkleizedBatch<H::Digest, update::Unordered<K, V>>, Error>> + Send
    {
        async move { self.merkleize(None, db).await }
    }
}

impl<E, K, V, C, I, H> MerkleizeAny<E, C, I, H, update::Ordered<K, V>>
    for UnmerkleizedBatch<H, update::Ordered<K, V>>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<update::Ordered<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: OrderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<update::Ordered<K, V>>: Codec,
{
    #[allow(clippy::manual_async_fn)]
    fn merkleize_any(
        self,
        db: &Db<E, C, I, H, update::Ordered<K, V>>,
    ) -> impl Future<Output = Result<MerkleizedBatch<H::Digest, update::Ordered<K, V>>, Error>> + Send
    {
        async move { self.merkleize(None, db).await }
    }
}

/// Implement [`InitAny`] for unordered QMDB databases with fixed-size values.
impl<E, K, V, H, T> InitAny<E>
    for Db<
        E,
        FixedJournal<E, Operation<update::Unordered<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, FixedEncoding<V>>,
    >
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher,
    T: Translator,
{
    type Config = FixedConfig<T>;

    async fn init_any(context: E, config: Self::Config) -> Result<Self, Error> {
        Self::init(context, config).await
    }
}

/// Implement [`InitAny`] for unordered QMDB databases with variable-size values.
impl<E, K, V, H, T> InitAny<E>
    for Db<
        E,
        VariableJournal<E, Operation<update::Unordered<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, VariableEncoding<V>>,
    >
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    Operation<update::Unordered<K, VariableEncoding<V>>>: Codec,
{
    type Config =
        VariableConfig<T, <Operation<update::Unordered<K, VariableEncoding<V>>> as CodecRead>::Cfg>;

    async fn init_any(context: E, config: Self::Config) -> Result<Self, Error> {
        Self::init(context, config).await
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for all supported `any` update kinds.
impl<E, C, I, H, U> UnmerkleizedTrait for AnyUnmerkleized<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync + 'static,
    U::Key: Send,
    U::Value: Send,
    C: Mutable<Item = Operation<U>> + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<U>: Codec,
    UnmerkleizedBatch<H, U>: MerkleizeAny<E, C, I, H, U>,
{
    type Key = U::Key;
    type Value = U::Value;
    type Merkleized = AnyMerkleized<E, C, I, H, U>;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Error> {
        let db = self.db.read().await;
        self.batch.get(key, &*db).await
    }

    fn write(mut self, key: Self::Key, value: Option<Self::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }

    async fn merkleize(self) -> Result<Self::Merkleized, Error> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize_any(&*db).await?;
        Ok(AnyMerkleized {
            batch: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Implement [`Merkleized`](MerkleizedTrait) for all supported `any` update kinds.
impl<E, C, I, H, U> MerkleizedTrait for AnyMerkleized<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Mutable<Item = Operation<U>> + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<U>: Codec,
    AnyUnmerkleized<E, C, I, H, U>: UnmerkleizedTrait,
{
    type Digest = H::Digest;
    type Unmerkleized = AnyUnmerkleized<E, C, I, H, U>;

    fn root(&self) -> H::Digest {
        self.batch.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        AnyUnmerkleized {
            batch: self.batch.new_batch::<H>(),
            db: self.db.clone(),
        }
    }
}

/// Implement [`ManagedDb`] for QMDB databases backed by `any`.
///
/// `new_batch` captures the `Arc<AsyncRwLock<Db>>` in the returned
/// wrapper so that `get()` and `merkleize()` can read through to
/// committed state.
///
/// `finalize` applies the merkleized batch's changeset and durably
/// commits it to disk.
impl<E, C, I, H, U> ManagedDb<E> for Db<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync + 'static,
    C: Mutable<Item = Operation<U>>
        + Persistable<Error = commonware_storage::journal::Error>
        + 'static,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher + 'static,
    Operation<U>: Codec,
    AnyUnmerkleized<E, C, I, H, U>:
        UnmerkleizedTrait<Error = Error, Merkleized = AnyMerkleized<E, C, I, H, U>>,
    AnyMerkleized<E, C, I, H, U>: MerkleizedTrait<Unmerkleized = AnyUnmerkleized<E, C, I, H, U>>,
    Self: InitAny<E>,
{
    type Unmerkleized = AnyUnmerkleized<E, C, I, H, U>;
    type Merkleized = AnyMerkleized<E, C, I, H, U>;
    type Error = Error;
    type Config = <Self as InitAny<E>>::Config;
    type SyncTarget = commonware_storage::qmdb::sync::Target<H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error> {
        <Self as InitAny<E>>::init_any(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        AnyUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error> {
        // Use finalize_from with the current DB size so that batches
        // created against an older DB state (before other forks were
        // finalized) produce correct changesets.
        let current_size = *self.bounds().await.end;
        let changeset = batch.batch.finalize_from(current_size);
        self.apply_batch(changeset).await?;
        self.commit().await?;
        Ok(())
    }
}

impl<E, K, V, H, T, R> StateSyncDb<E, R>
    for Db<
        E,
        FixedJournal<E, Operation<update::Unordered<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, FixedEncoding<V>>,
    >
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator + Send + Sync + 'static,
    R: commonware_storage::qmdb::sync::resolver::Resolver<
            Op = Operation<update::Unordered<K, FixedEncoding<V>>>,
            Digest = H::Digest,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    type SyncError = sync::Error<R::Error, H::Digest>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        resolver: R,
        target: Self::SyncTarget,
        tip_updates: Option<mpsc::Receiver<Self::SyncTarget>>,
        sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        sync::sync(sync::engine::Config {
            context,
            resolver,
            target,
            max_outstanding_requests: sync_config.max_outstanding_requests,
            fetch_batch_size: sync_config.fetch_batch_size,
            apply_batch_size: sync_config.apply_batch_size,
            db_config: config,
            update_rx: tip_updates,
        })
        .await
    }
}

impl<E, K, V, H, T, R> StateSyncDb<E, R>
    for Db<
        E,
        VariableJournal<E, Operation<update::Unordered<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, VariableEncoding<V>>,
    >
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator + Send + Sync + 'static,
    Operation<update::Unordered<K, VariableEncoding<V>>>: Codec,
    R: sync::resolver::Resolver<
            Op = Operation<update::Unordered<K, VariableEncoding<V>>>,
            Digest = H::Digest,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    type SyncError = sync::Error<R::Error, H::Digest>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        resolver: R,
        target: Self::SyncTarget,
        tip_updates: Option<mpsc::Receiver<Self::SyncTarget>>,
        sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        sync::sync(sync::engine::Config {
            context,
            resolver,
            target,
            max_outstanding_requests: sync_config.max_outstanding_requests,
            fetch_batch_size: sync_config.fetch_batch_size,
            apply_batch_size: sync_config.apply_batch_size,
            db_config: config,
            update_rx: tip_updates,
        })
        .await
    }
}
