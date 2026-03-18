//! Resolver service actor for QMDB sync over P2P.

use super::{mailbox, Mailbox, State, SyncableDb};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{self as resolver, p2p::Producer};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::status::{self, CounterExt},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::channel::{
    fallible::{AsyncFallibleExt, OneshotExt},
    mpsc, oneshot,
};
use rand::Rng;
use std::{sync::Arc, time::Duration};
use tracing::info;

type SyncMailbox<E, P, DB> =
    Mailbox<P, <DB as SyncableDb<E>>::SyncOp, <DB as SyncableDb<E>>::SyncDigest, DB>;

/// Configuration for [`Actor`].
pub struct Config<P, D, B, DB>
where
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
{
    /// Provider for the current peer set.
    pub peer_provider: D,

    /// Blocker used when peers send invalid data.
    pub blocker: B,

    /// Local database used to serve incoming requests when available.
    pub database: Option<Arc<commonware_utils::sync::AsyncRwLock<DB>>>,

    /// Maximum size of resolver mailbox backlogs.
    pub mailbox_size: usize,

    /// Local node identity if available.
    pub me: Option<P>,

    /// Initial expected performance for new peers.
    pub initial: Duration,

    /// Request timeout.
    pub timeout: Duration,

    /// Retry cadence for pending fetches.
    pub fetch_retry_timeout: Duration,

    /// Send fetch requests with network priority.
    pub priority_requests: bool,

    /// Send responses with network priority.
    pub priority_responses: bool,
}

enum HandlerMessage {
    Deliver {
        key: mailbox::Request,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    Failed {
        key: mailbox::Request,
    },
    Produce {
        key: mailbox::Request,
        response: oneshot::Sender<Bytes>,
    },
}

#[derive(Clone)]
struct Handler {
    sender: mpsc::Sender<HandlerMessage>,
}

impl Handler {
    const fn new(sender: mpsc::Sender<HandlerMessage>) -> Self {
        Self { sender }
    }
}

impl resolver::Consumer for Handler {
    type Key = mailbox::Request;
    type Value = Bytes;
    type Failure = ();

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        self.sender
            .request_or(
                |response| HandlerMessage::Deliver {
                    key,
                    value,
                    response,
                },
                false,
            )
            .await
    }

    async fn failed(&mut self, key: Self::Key, _: Self::Failure) {
        self.sender.send_lossy(HandlerMessage::Failed { key }).await;
    }
}

impl Producer for Handler {
    type Key = mailbox::Request;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(HandlerMessage::Produce { key, response })
            .await;
        receiver
    }
}

/// Runs a QMDB sync resolver service over `commonware_resolver::p2p::Engine`.
pub struct Actor<E, P, D, B, DB, NetS, NetR>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    DB: SyncableDb<E>,
    DB::SyncOp: commonware_codec::Read<Cfg = ()>
        + commonware_codec::Write
        + commonware_codec::EncodeSize
        + Send
        + Sync
        + Clone
        + 'static,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
{
    context: ContextCell<E>,
    peer_provider: D,
    blocker: B,
    mailbox_size: usize,
    me: Option<P>,
    initial: Duration,
    timeout: Duration,
    fetch_retry_timeout: Duration,
    priority_requests: bool,
    priority_responses: bool,
    handler_tx: mpsc::Sender<HandlerMessage>,
    handler_rx: mpsc::Receiver<HandlerMessage>,
    attach_sender: mpsc::Sender<mailbox::AttachMessage<DB>>,
    attach_rx: mpsc::Receiver<mailbox::AttachMessage<DB>>,
    _network: std::marker::PhantomData<(NetS, NetR)>,
    state: State<DB>,
    serve_requests: status::Counter,
    pending: mailbox::PendingMap,
}

impl<E, P, D, B, DB, NetS, NetR> Actor<E, P, D, B, DB, NetS, NetR>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    DB: SyncableDb<E>,
    DB::SyncOp: commonware_codec::Read<Cfg = ()>
        + commonware_codec::Write
        + commonware_codec::EncodeSize
        + Send
        + Sync
        + Clone
        + 'static,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
{
    /// Create a new resolver actor.
    pub fn new(context: E, cfg: Config<P, D, B, DB>) -> Self {
        let pending = mailbox::pending_map();
        let (handler_tx, handler_rx) = mpsc::channel(cfg.mailbox_size);
        let (attach_sender, attach_rx) = mpsc::channel(cfg.mailbox_size);
        let serve_requests = status::Counter::default();
        context.register(
            "serve_requests",
            "QMDB resolver serve requests by status",
            serve_requests.clone(),
        );

        Self {
            context: ContextCell::new(context),
            peer_provider: cfg.peer_provider,
            blocker: cfg.blocker,
            mailbox_size: cfg.mailbox_size,
            me: cfg.me,
            initial: cfg.initial,
            timeout: cfg.timeout,
            fetch_retry_timeout: cfg.fetch_retry_timeout,
            priority_requests: cfg.priority_requests,
            priority_responses: cfg.priority_responses,
            handler_tx,
            handler_rx,
            attach_sender,
            attach_rx,
            _network: std::marker::PhantomData,
            state: cfg
                .database
                .map_or_else(|| State::NoDb, |database| State::HasDb(database)),
            serve_requests,
            pending,
        }
    }

    /// Start the resolver service and return the sync mailbox.
    pub fn start(mut self, network: (NetS, NetR)) -> (Handle<()>, SyncMailbox<E, P, DB>) {
        let handler = Handler::new(self.handler_tx.clone());
        let (engine, resolver_mailbox) = commonware_resolver::p2p::Engine::new(
            self.context.clone().into_present().with_label("resolver"),
            commonware_resolver::p2p::Config {
                peer_provider: self.peer_provider.clone(),
                blocker: self.blocker.clone(),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                me: self.me.clone(),
                initial: self.initial,
                timeout: self.timeout,
                fetch_retry_timeout: self.fetch_retry_timeout,
                priority_requests: self.priority_requests,
                priority_responses: self.priority_responses,
            },
        );
        let mailbox = Mailbox::new(
            resolver_mailbox,
            self.attach_sender.clone(),
            self.pending.clone(),
        );
        let handle = spawn_cell!(self.context, self.run(network, engine).await);
        (handle, mailbox)
    }

    async fn run(
        mut self,
        network: (NetS, NetR),
        engine: commonware_resolver::p2p::Engine<
            E,
            P,
            D,
            B,
            mailbox::Request,
            Handler,
            Handler,
            NetS,
            NetR,
        >,
    ) {
        let mut resolver_task = engine.start(network);

        select_loop! {
            self.context,
            on_stopped => {
                return;
            },
            _ = &mut resolver_task => {
                return;
            },
            Some(message) = self.attach_rx.recv() else {
                return;
            } => {
                self.handle_attach_message(message);
            },
            Some(message) = self.handler_rx.recv() else {
                return;
            } => {
                self.handle_message(message).await;
            },
        }
    }

    fn handle_attach_message(&mut self, message: mailbox::AttachMessage<DB>) {
        match message {
            mailbox::AttachMessage::AttachDatabase { db } => {
                let replacing_existing = matches!(self.state, State::HasDb(_));
                info!(replacing_existing, "attached resolver database");
                self.state = State::HasDb(db);
            }
        }
    }

    async fn handle_message(&mut self, message: HandlerMessage) {
        match message {
            HandlerMessage::Deliver {
                key,
                value,
                response,
            } => {
                let pending = { self.pending.lock().remove(&key) };
                let valid = if let Some(pending) = pending {
                    if pending.response_tx.send(value).is_err() {
                        // TODO: Just use a lossy send? Can't block ig.
                        true
                    } else {
                        pending.success_rx.await.unwrap_or(false)
                    }
                } else {
                    true
                };
                response.send_lossy(valid);
            }
            HandlerMessage::Failed { key } => {
                self.pending.lock().remove(&key);
            }
            HandlerMessage::Produce { key, response } => {
                let State::HasDb(database) = &self.state else {
                    self.serve_requests.inc(status::Status::Dropped);
                    return;
                };
                let result = DB::get_operations(
                    database,
                    key.op_count,
                    key.start_loc,
                    key.max_ops,
                    key.include_pinned_nodes,
                )
                .await;

                match result {
                    Ok(fetch) => {
                        response.send_lossy(mailbox::encode_fetch_result(fetch));
                        self.serve_requests.inc(status::Status::Success);
                    }
                    Err(_) => {
                        self.serve_requests.inc(status::Status::Failure);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_cryptography::{ed25519, sha256, Sha256};
    use commonware_p2p::Provider;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _};
    use commonware_storage::{
        mmr::Location,
        qmdb::any::{unordered::fixed, FixedConfig},
        translator::TwoCap,
    };
    use commonware_utils::{
        channel::oneshot, ordered::Set, sync::AsyncRwLock, NZUsize, NZU16, NZU64,
    };
    use std::{num::NonZeroU64, sync::Arc, time::Duration};

    #[derive(Clone, Debug)]
    struct DummyProvider;

    impl Provider for DummyProvider {
        type PublicKey = ed25519::PublicKey;

        async fn peer_set(&mut self, _id: u64) -> Option<Set<Self::PublicKey>> {
            None
        }

        async fn subscribe(&mut self) -> commonware_p2p::PeerSetSubscription<Self::PublicKey> {
            let (_tx, rx) = commonware_utils::channel::mpsc::unbounded_channel();
            rx
        }
    }

    #[derive(Clone)]
    struct DummyBlocker;

    impl commonware_p2p::Blocker for DummyBlocker {
        type PublicKey = ed25519::PublicKey;

        async fn block(&mut self, _peer: Self::PublicKey) {}
    }

    type TestDb = fixed::Db<deterministic::Context, sha256::Digest, sha256::Digest, Sha256, TwoCap>;

    type TestActor = Actor<
        deterministic::Context,
        ed25519::PublicKey,
        DummyProvider,
        DummyBlocker,
        TestDb,
        commonware_p2p::simulated::Sender<ed25519::PublicKey, deterministic::Context>,
        commonware_p2p::simulated::Receiver<ed25519::PublicKey>,
    >;

    fn db_config(suffix: &str, pooler: &impl BufferPooler) -> FixedConfig<TwoCap> {
        FixedConfig {
            mmr_journal_partition: format!("{suffix}-mmr-journal"),
            mmr_metadata_partition: format!("{suffix}-mmr-metadata"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("{suffix}-log-journal"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, NZU16!(101), NZUsize!(11)),
        }
    }

    async fn init_db(context: deterministic::Context, suffix: &str) -> Arc<AsyncRwLock<TestDb>> {
        let db = TestDb::init(context.with_label("db"), db_config(suffix, &context))
            .await
            .expect("db init should succeed");
        Arc::new(AsyncRwLock::new(db))
    }

    async fn test_request(db: &Arc<AsyncRwLock<TestDb>>) -> mailbox::Request {
        let op_count = db.read().await.bounds().await.end;
        mailbox::Request {
            op_count,
            start_loc: Location::new(0),
            max_ops: NonZeroU64::new(1).unwrap(),
            include_pinned_nodes: false,
        }
    }

    #[test]
    fn produce_denied_before_attach() {
        deterministic::Runner::default().start(|context| async move {
            let mut actor: TestActor = Actor::new(
                context.clone(),
                Config {
                    peer_provider: DummyProvider,
                    blocker: DummyBlocker,
                    database: None,
                    mailbox_size: 16,
                    me: None,
                    initial: Duration::from_millis(10),
                    timeout: Duration::from_millis(10),
                    fetch_retry_timeout: Duration::from_millis(10),
                    priority_requests: false,
                    priority_responses: false,
                },
            );

            let (response_tx, response_rx) = oneshot::channel();
            let request = mailbox::Request {
                op_count: Location::new(1),
                start_loc: Location::new(0),
                max_ops: NonZeroU64::new(1).unwrap(),
                include_pinned_nodes: false,
            };
            actor
                .handle_message(HandlerMessage::Produce {
                    key: request,
                    response: response_tx,
                })
                .await;
            assert!(response_rx.await.is_err());
        });
    }

    #[test]
    fn same_request_served_after_attach() {
        deterministic::Runner::default().start(|context| async move {
            let mut actor: TestActor = Actor::new(
                context.clone(),
                Config {
                    peer_provider: DummyProvider,
                    blocker: DummyBlocker,
                    database: None,
                    mailbox_size: 16,
                    me: None,
                    initial: Duration::from_millis(10),
                    timeout: Duration::from_millis(10),
                    fetch_retry_timeout: Duration::from_millis(10),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            let db = init_db(context.clone(), "resolver-after-attach").await;
            let request = test_request(&db).await;
            actor.handle_attach_message(mailbox::AttachMessage::AttachDatabase { db });

            let (response_tx, response_rx) = oneshot::channel();
            actor
                .handle_message(HandlerMessage::Produce {
                    key: request,
                    response: response_tx,
                })
                .await;

            let payload = response_rx
                .await
                .expect("response should be available after attach");
            assert!(!payload.is_empty());
        });
    }

    #[test]
    fn deliver_with_dropped_response_receiver_is_treated_as_valid() {
        deterministic::Runner::default().start(|context| async move {
            let mut actor: TestActor = Actor::new(
                context,
                Config {
                    peer_provider: DummyProvider,
                    blocker: DummyBlocker,
                    database: None,
                    mailbox_size: 16,
                    me: None,
                    initial: Duration::from_millis(10),
                    timeout: Duration::from_millis(10),
                    fetch_retry_timeout: Duration::from_millis(10),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            let request = mailbox::Request {
                op_count: Location::new(1),
                start_loc: Location::new(0),
                max_ops: NonZeroU64::new(1).unwrap(),
                include_pinned_nodes: false,
            };

            let (response_tx, response_rx) = oneshot::channel();
            drop(response_rx);
            let (success_tx, success_rx) = oneshot::channel();
            actor.pending.lock().insert(
                request.clone(),
                mailbox::Pending {
                    response_tx,
                    success_rx,
                },
            );
            drop(success_tx);

            let (ack_tx, ack_rx) = oneshot::channel();
            actor
                .handle_message(HandlerMessage::Deliver {
                    key: request,
                    value: Bytes::from_static(b"payload"),
                    response: ack_tx,
                })
                .await;

            assert!(ack_rx.await.unwrap());
        });
    }

    #[test]
    fn failed_then_deliver_clears_pending_and_allows_retry() {
        deterministic::Runner::default().start(|context| async move {
            let mut actor: TestActor = Actor::new(
                context,
                Config {
                    peer_provider: DummyProvider,
                    blocker: DummyBlocker,
                    database: None,
                    mailbox_size: 16,
                    me: None,
                    initial: Duration::from_millis(10),
                    timeout: Duration::from_millis(10),
                    fetch_retry_timeout: Duration::from_millis(10),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            let request = mailbox::Request {
                op_count: Location::new(1),
                start_loc: Location::new(0),
                max_ops: NonZeroU64::new(1).unwrap(),
                include_pinned_nodes: false,
            };

            let (response_tx, _response_rx) = oneshot::channel();
            let (_success_tx, success_rx) = oneshot::channel();
            actor.pending.lock().insert(
                request.clone(),
                mailbox::Pending {
                    response_tx,
                    success_rx,
                },
            );
            actor
                .handle_message(HandlerMessage::Failed {
                    key: request.clone(),
                })
                .await;
            assert!(actor.pending.lock().get(&request).is_none());

            let (ack_tx, ack_rx) = oneshot::channel();
            actor
                .handle_message(HandlerMessage::Deliver {
                    key: request,
                    value: Bytes::from_static(b"late-response"),
                    response: ack_tx,
                })
                .await;
            assert!(ack_rx.await.unwrap());
        });
    }
}
