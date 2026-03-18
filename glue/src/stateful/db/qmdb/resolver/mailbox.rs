//! Mailbox and wire types for the QMDB sync resolver service.

use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_resolver::{p2p, Resolver as _};
use commonware_storage::{
    mmr::{Location, Proof},
    qmdb::sync::resolver::{FetchResult, Resolver as SyncResolver},
};
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::{AsyncRwLock, Mutex},
    Span,
};
use std::{collections::HashMap, fmt, num::NonZeroU64, sync::Arc};

/// Upper bound for proof digests in decoded network responses.
const MAX_PROOF_DIGESTS: usize = 10_000;

/// Upper bound for operations in decoded network responses.
const MAX_OPERATIONS: usize = 10_000;

/// Upper bound for pinned MMR nodes in decoded network responses.
const MAX_PINNED_NODES: usize = 64;

/// Request key sent through `resolver::p2p::Engine`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Request {
    /// Total operation count for proof context.
    pub op_count: Location,
    /// First operation location to fetch.
    pub start_loc: Location,
    /// Maximum number of operations to fetch.
    pub max_ops: NonZeroU64,
    /// Include pinned MMR nodes for `start_loc` when `true`.
    pub include_pinned_nodes: bool,
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Request(count={}, start={}, max={}, pinned={})",
            self.op_count, self.start_loc, self.max_ops, self.include_pinned_nodes,
        )
    }
}

impl Write for Request {
    fn write(&self, buf: &mut impl BufMut) {
        self.op_count.write(buf);
        self.start_loc.write(buf);
        self.max_ops.get().write(buf);
        (self.include_pinned_nodes as u8).write(buf);
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        self.op_count.encode_size()
            + self.start_loc.encode_size()
            + self.max_ops.get().encode_size()
            + 1u8.encode_size()
    }
}

impl Read for Request {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let op_count = Location::read(buf)?;
        let start_loc = Location::read(buf)?;
        let max_ops = u64::read(buf)?;
        let Some(max_ops) = NonZeroU64::new(max_ops) else {
            return Err(CodecError::Invalid("Request", "max_ops cannot be zero"));
        };
        let include_pinned_nodes = u8::read(buf)? != 0;
        Ok(Self {
            op_count,
            start_loc,
            max_ops,
            include_pinned_nodes,
        })
    }
}

impl Span for Request {}

/// Error type returned by [`Mailbox`].
#[derive(Debug)]
pub enum Error {
    /// The pending response was dropped before any payload arrived.
    ResponseDropped,
    /// Payload could not be decoded as a sync response.
    Decode(CodecError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResponseDropped => write!(f, "response dropped before completion"),
            Self::Decode(err) => write!(f, "failed to decode response: {err}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(err) => Some(err),
            Self::ResponseDropped => None,
        }
    }
}

/// Client-facing resolver mailbox used by the QMDB sync engine.
pub struct Mailbox<P, Op, D, DB>
where
    P: PublicKey,
    D: Digest,
{
    resolver: p2p::Mailbox<Request, P>,
    attach_sender: mpsc::Sender<AttachMessage<DB>>,
    pending: PendingMap,
    _marker: std::marker::PhantomData<(Op, D, DB)>,
}

impl<P, Op, D, DB> Mailbox<P, Op, D, DB>
where
    P: PublicKey,
    D: Digest,
{
    pub(super) const fn new(
        resolver: p2p::Mailbox<Request, P>,
        attach_sender: mpsc::Sender<AttachMessage<DB>>,
        pending: PendingMap,
    ) -> Self {
        Self {
            resolver,
            attach_sender,
            pending,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) {
        self.attach_sender
            .send(AttachMessage::AttachDatabase { db })
            .await
            .expect("resolver actor dropped during attach_database");
    }
}

impl<P, Op, D, DB> Clone for Mailbox<P, Op, D, DB>
where
    P: PublicKey,
    D: Digest,
{
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
            attach_sender: self.attach_sender.clone(),
            pending: self.pending.clone(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<P, Op, D, DB> SyncResolver for Mailbox<P, Op, D, DB>
where
    P: PublicKey,
    Op: Read<Cfg = ()> + Send + Sync + Clone + 'static,
    D: Digest,
    DB: Send + Sync + 'static,
{
    type Digest = D;
    type Op = Op;
    type Error = Error;

    async fn get_operations(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
    ) -> Result<FetchResult<Self::Op, Self::Digest>, Self::Error> {
        let request = Request {
            op_count,
            start_loc,
            max_ops,
            include_pinned_nodes,
        };

        let (response_tx, response_rx) = oneshot::channel();
        let (success_tx, success_rx) = oneshot::channel();

        self.pending.lock().insert(
            request.clone(),
            Pending {
                response_tx,
                success_rx,
            },
        );

        let mut resolver = self.resolver.clone();
        resolver.fetch(request).await;

        let payload = response_rx.await.map_err(|_| Error::ResponseDropped)?;
        let decoded = Response::<Op, D>::decode(payload).map_err(Error::Decode)?;

        Ok(FetchResult {
            proof: decoded.proof,
            operations: decoded.operations,
            success_tx,
            pinned_nodes: decoded.pinned_nodes,
        })
    }
}

pub(super) fn pending_map() -> PendingMap {
    Arc::new(Mutex::new(HashMap::new()))
}

pub(super) fn encode_fetch_result<Op, D>(fetch: FetchResult<Op, D>) -> Bytes
where
    Op: Write + EncodeSize,
    D: Digest,
{
    Response {
        proof: fetch.proof,
        operations: fetch.operations,
        pinned_nodes: fetch.pinned_nodes,
    }
    .encode()
}

struct Response<Op, D: Digest> {
    proof: Proof<D>,
    operations: Vec<Op>,
    pinned_nodes: Option<Vec<D>>,
}

impl<Op: Write, D: Digest> Write for Response<Op, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.operations.write(buf);
        match &self.pinned_nodes {
            Some(nodes) => {
                1u8.write(buf);
                nodes.write(buf);
            }
            None => {
                0u8.write(buf);
            }
        }
    }
}

impl<Op: EncodeSize, D: Digest> EncodeSize for Response<Op, D> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size()
            + self.operations.encode_size()
            + 1u8.encode_size()
            + self
                .pinned_nodes
                .as_ref()
                .map_or(0, EncodeSize::encode_size)
    }
}

impl<Op: Read<Cfg = ()>, D: Digest> Read for Response<Op, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let proof = Proof::<D>::read_cfg(buf, &MAX_PROOF_DIGESTS)?;
        let operations = Vec::<Op>::read_range(buf, ..=MAX_OPERATIONS)?;
        let has_pinned_nodes = u8::read(buf)? != 0;
        let pinned_nodes = if has_pinned_nodes {
            Some(Vec::<D>::read_range(buf, ..=MAX_PINNED_NODES)?)
        } else {
            None
        };
        Ok(Self {
            proof,
            operations,
            pinned_nodes,
        })
    }
}

pub(super) struct Pending {
    pub(super) response_tx: oneshot::Sender<Bytes>,
    pub(super) success_rx: oneshot::Receiver<bool>,
}

pub(super) type PendingMap = Arc<Mutex<HashMap<Request, Pending>>>;

#[derive(Clone)]
pub(super) enum AttachMessage<DB> {
    AttachDatabase { db: Arc<AsyncRwLock<DB>> },
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_cryptography::sha256;

    #[test]
    fn request_codec_roundtrip() {
        let req = Request {
            op_count: Location::new(128),
            start_loc: Location::new(64),
            max_ops: NonZeroU64::new(16).unwrap(),
            include_pinned_nodes: true,
        };
        let encoded = req.encode();
        let decoded = Request::decode(encoded).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn response_codec_roundtrip() {
        let response = Response::<u64, sha256::Digest> {
            proof: Proof {
                leaves: Location::new(10),
                digests: vec![sha256::Digest::from([7; 32])],
            },
            operations: vec![1, 2, 3],
            pinned_nodes: Some(vec![sha256::Digest::from([9; 32])]),
        };

        let encoded = response.encode();
        let decoded = Response::<u64, sha256::Digest>::decode(encoded).unwrap();
        assert_eq!(decoded.operations, vec![1, 2, 3]);
        assert_eq!(decoded.proof.leaves, Location::new(10));
        assert_eq!(decoded.pinned_nodes.unwrap().len(), 1);
    }
}
