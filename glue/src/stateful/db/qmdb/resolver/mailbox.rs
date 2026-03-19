//! Mailbox and wire types for the QMDB sync resolver service.

use super::handler;
use commonware_codec::Read;
use commonware_cryptography::Digest;
use commonware_storage::{
    mmr::Location,
    qmdb::sync::resolver::{FetchResult, Resolver as SyncResolver},
};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    sync::AsyncRwLock,
};
use std::{num::NonZeroU64, sync::Arc};

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

/// Messages sent from the [`Mailbox`] to the resolver [`Actor`](super::Actor).
pub(super) enum Message<DB, Op, D: Digest> {
    /// Provide a database handle so the actor can serve incoming requests.
    AttachDatabase(Arc<AsyncRwLock<DB>>),
    /// Fetch operations from a remote peer via the P2P resolver engine.
    GetOperations {
        request: handler::Request,
        response: oneshot::Sender<Result<FetchResult<Op, D>, ResponseDropped>>,
    },
}

/// Client-facing resolver mailbox used by the QMDB sync engine.
pub struct Mailbox<Op, D, DB>
where
    D: Digest,
{
    sender: mpsc::Sender<Message<DB, Op, D>>,
}

impl<Op, D, DB> Clone for Mailbox<Op, D, DB>
where
    D: Digest,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<Op, D, DB> Mailbox<Op, D, DB>
where
    D: Digest,
{
    pub(super) const fn new(sender: mpsc::Sender<Message<DB, Op, D>>) -> Self {
        Self { sender }
    }
}

impl<Op, D, DB> Mailbox<Op, D, DB>
where
    Op: Send,
    D: Digest,
    DB: Send + Sync,
{
    pub async fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) {
        self.sender.send_lossy(Message::AttachDatabase(db)).await;
    }
}

impl<Op, D, DB> SyncResolver for Mailbox<Op, D, DB>
where
    Op: Read<Cfg = ()> + Send + Sync + Clone + 'static,
    D: Digest,
    DB: Send + Sync + 'static,
{
    type Digest = D;
    type Op = Op;
    type Error = ResponseDropped;

    async fn get_operations(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
    ) -> Result<FetchResult<Self::Op, Self::Digest>, Self::Error> {
        let request = handler::Request {
            op_count,
            start_loc,
            max_ops,
            include_pinned_nodes,
        };

        self.sender
            .request(|response| Message::GetOperations { request, response })
            .await
            .ok_or(ResponseDropped)?
    }
}
