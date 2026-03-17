//! [`ManagedDb`] implementation for QMDB [`any`](commonware_storage::qmdb::any) databases.
//!
//! The QMDB batch API passes `&db` to `get()` and `merkleize()` for
//! read-through to committed state. The glue [`Unmerkleized`] trait
//! does not carry a DB reference, so this module provides wrapper types
//! that capture `Arc<AsyncRwLock<Db>>` alongside the raw batch.

use super::{ManagedDb, Merkleized as MerkleizedTrait, Unmerkleized as UnmerkleizedTrait};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::contiguous::{Contiguous, Mutable},
    mmr::Location,
    qmdb::{
        any::{
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            db::Db,
            operation::{update, Operation},
            value::ValueEncoding,
        },
        operation::Key,
        Error,
    },
    Persistable,
};
use commonware_utils::sync::AsyncRwLock;
use std::{future::Future, sync::Arc};

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
    db: Arc<AsyncRwLock<Db<E, C, I, H, U>>>,
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
    db: Arc<AsyncRwLock<Db<E, C, I, H, U>>>,
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
    fn merkleize_any(
        self,
        db: &Db<E, C, I, H, update::Ordered<K, V>>,
    ) -> impl Future<Output = Result<MerkleizedBatch<H::Digest, update::Ordered<K, V>>, Error>> + Send
    {
        async move { self.merkleize(None, db).await }
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
impl<E, C, I, H, U> ManagedDb for Db<E, C, I, H, U>
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
{
    type Unmerkleized = AnyUnmerkleized<E, C, I, H, U>;
    type Merkleized = AnyMerkleized<E, C, I, H, U>;
    type Error = Error;

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
