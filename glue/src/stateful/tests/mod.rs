//! E2E tests for `stateful`

use crate::{
    simulate::{
        engine::EngineDefinition,
        exit::ProcessedHeightAtLeast,
        fault::{Crash, Fault, Schedule},
        plan::PlanBuilder,
    },
    stateful::db::{qmdb::resolver, ManagedDb, StateSyncSet, SyncEngineConfig, Unmerkleized as _},
};
use app::ConsensusEngine;
use commonware_cryptography::{ed25519, sha256, Hasher as _, Sha256, Signer as _};
use commonware_macros::test_traced;
use commonware_p2p::{simulated, Manager as _};
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, BufferPooler, Metrics as _, Quota, Runner as _,
};
use commonware_storage::{
    mmr::Location,
    qmdb::{
        any::{unordered::fixed, FixedConfig},
        sync::{resolver::Resolver as _, Target},
    },
    translator::TwoCap,
};
use commonware_utils::{sync::AsyncRwLock, NZUsize, NZU16, NZU64};
use properties::{BlockAgreementAtHeight, LateJoinerStateSyncHandoff};
use std::{
    num::{NonZeroU32, NonZeroU64},
    sync::Arc,
    time::Duration,
};

pub(crate) mod app;
pub(crate) mod properties;

const NUM_VALIDATORS: u32 = 5;

#[test_traced("DEBUG")]
fn all_validators_finalize_and_commit() {
    PlanBuilder::new(ConsensusEngine::new(NUM_VALIDATORS))
        .exit_condition(ProcessedHeightAtLeast::new(100))
        .property(BlockAgreementAtHeight { height: 100 })
        .run()
        .unwrap();
}

#[test_traced("DEBUG")]
fn deterministic_across_seeds() {
    for seed in 0..5 {
        let r1 = PlanBuilder::new(ConsensusEngine::new(NUM_VALIDATORS))
            .seed(seed)
            .exit_condition(ProcessedHeightAtLeast::new(20))
            .property(BlockAgreementAtHeight { height: 20 })
            .run()
            .unwrap();
        let r2 = PlanBuilder::new(ConsensusEngine::new(NUM_VALIDATORS))
            .seed(seed)
            .exit_condition(ProcessedHeightAtLeast::new(20))
            .property(BlockAgreementAtHeight { height: 20 })
            .run()
            .unwrap();
        assert_eq!(r1.state, r2.state, "seed {seed} produced different state");
    }
}

#[test_traced("DEBUG")]
fn crash_and_restart_one_validator() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let validator = engine.participants()[0].clone();

    PlanBuilder::new(engine)
        .crash(Crash::Schedule(
            Schedule::new()
                .at(Duration::from_millis(2500), Fault::Crash(validator.clone()))
                .at(Duration::from_millis(5000), Fault::Restart(validator)),
        ))
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 20 })
        .run()
        .unwrap();
}

#[test_traced("DEBUG")]
fn delayed_start_one_validator() {
    PlanBuilder::new(ConsensusEngine::new(NUM_VALIDATORS))
        .crash(Crash::Delay { count: 1, after: 5 })
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 20 })
        .run()
        .unwrap();
}

#[test_traced("DEBUG")]
fn late_joiner_state_sync_then_handoffs_to_marshal_sync() {
    PlanBuilder::new(ConsensusEngine::new(NUM_VALIDATORS).with_late_join_state_sync())
        .crash(Crash::Delay {
            count: 1,
            after: 10,
        })
        .exit_condition(ProcessedHeightAtLeast::new(40))
        .timeout(Duration::from_secs(300))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight { height: 40 })
        .run()
        .unwrap();
}

type TestDb = fixed::Db<deterministic::Context, sha256::Digest, sha256::Digest, Sha256, TwoCap>;

fn qmdb_config(suffix: &str, pooler: &impl BufferPooler) -> FixedConfig<TwoCap> {
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

#[test_traced("DEBUG")]
fn state_sync_uses_resolver_mailboxes_and_serves_after_attach() {
    deterministic::Runner::default().start(|context| async move {
        let server_pk = ed25519::PrivateKey::from_seed(101).public_key();
        let client_pk = ed25519::PrivateKey::from_seed(102).public_key();
        let verifier_pk = ed25519::PrivateKey::from_seed(103).public_key();

        let (network, oracle) = simulated::Network::new(
            context.with_label("resolver_network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: Some(3),
            },
        );
        network.start();

        let mut manager = oracle.manager();
        manager
            .track(
                0,
                vec![server_pk.clone(), client_pk.clone(), verifier_pk.clone()]
                    .try_into()
                    .unwrap(),
            )
            .await;

        let quota = Quota::per_second(NonZeroU32::MAX);
        let server_connection: (
            simulated::Sender<ed25519::PublicKey, deterministic::Context>,
            simulated::Receiver<ed25519::PublicKey>,
        ) = oracle
            .control(server_pk.clone())
            .register(0, quota)
            .await
            .unwrap();
        let client_connection: (
            simulated::Sender<ed25519::PublicKey, deterministic::Context>,
            simulated::Receiver<ed25519::PublicKey>,
        ) = oracle
            .control(client_pk.clone())
            .register(0, quota)
            .await
            .unwrap();
        let verifier_connection: (
            simulated::Sender<ed25519::PublicKey, deterministic::Context>,
            simulated::Receiver<ed25519::PublicKey>,
        ) = oracle
            .control(verifier_pk.clone())
            .register(0, quota)
            .await
            .unwrap();

        let link = simulated::Link {
            latency: Duration::from_millis(5),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        oracle
            .add_link(server_pk.clone(), client_pk.clone(), link.clone())
            .await
            .unwrap();
        oracle
            .add_link(client_pk.clone(), server_pk.clone(), link.clone())
            .await
            .unwrap();
        oracle
            .add_link(client_pk.clone(), verifier_pk.clone(), link.clone())
            .await
            .unwrap();
        oracle
            .add_link(verifier_pk.clone(), client_pk.clone(), link)
            .await
            .unwrap();

        let source_db = Arc::new(AsyncRwLock::new(
            TestDb::init(
                context.clone().with_label("source_db"),
                qmdb_config("source", &context),
            )
            .await
            .unwrap(),
        ));
        let key = Sha256::hash(b"sync-key");
        let value = Sha256::hash(b"sync-value");
        let batch = <TestDb as ManagedDb<deterministic::Context>>::new_batch(&source_db)
            .await
            .write(key, Some(value));
        let merkleized = batch.merkleize().await.unwrap();
        {
            let mut db = source_db.write().await;
            db.finalize(merkleized).await.unwrap();
        }

        let (target_root, target_range) = {
            let db = source_db.read().await;
            (db.root(), db.bounds().await)
        };
        let probe_start = Location::new(0);
        let probe_max_ops = NonZeroU64::new(1).unwrap();
        let sync_target = Target {
            root: target_root,
            range: target_range.clone(),
        };

        let server_actor = resolver::Actor::<_, ed25519::PublicKey, _, _, TestDb, _, _>::new(
            context.clone().with_label("server_resolver"),
            resolver::Config {
                peer_provider: oracle.manager(),
                blocker: oracle.control(server_pk.clone()),
                database: Some(source_db.clone()),
                mailbox_size: 64,
                me: Some(server_pk.clone()),
                initial: Duration::from_millis(50),
                timeout: Duration::from_millis(100),
                fetch_retry_timeout: Duration::from_millis(20),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let (server_handle, _server_mailbox) = server_actor.start(server_connection);

        let client_actor = resolver::Actor::<_, ed25519::PublicKey, _, _, TestDb, _, _>::new(
            context.clone().with_label("client_resolver"),
            resolver::Config {
                peer_provider: oracle.manager(),
                blocker: oracle.control(client_pk.clone()),
                database: None,
                mailbox_size: 64,
                me: Some(client_pk.clone()),
                initial: Duration::from_millis(50),
                timeout: Duration::from_millis(100),
                fetch_retry_timeout: Duration::from_millis(20),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let (client_handle, client_mailbox) = client_actor.start(client_connection);

        let verifier_actor = resolver::Actor::<_, ed25519::PublicKey, _, _, TestDb, _, _>::new(
            context.clone().with_label("verifier_resolver"),
            resolver::Config {
                peer_provider: oracle.manager(),
                blocker: oracle.control(verifier_pk.clone()),
                database: None,
                mailbox_size: 64,
                me: Some(verifier_pk.clone()),
                initial: Duration::from_millis(50),
                timeout: Duration::from_millis(100),
                fetch_retry_timeout: Duration::from_millis(20),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let (verifier_handle, verifier_mailbox) = verifier_actor.start(verifier_connection);

        // Client starts with no local DB attached, so this request must be fetched remotely over p2p.
        let pre_sync_fetch = client_mailbox
            .get_operations(target_range.end, probe_start, probe_max_ops, false)
            .await
            .unwrap();
        assert!(!pre_sync_fetch.operations.is_empty());
        let _ = pre_sync_fetch.success_tx.send(true);

        let sync_config = SyncEngineConfig {
            fetch_batch_size: NonZeroU64::new(1).unwrap(),
            apply_batch_size: 1,
            max_outstanding_requests: 1,
            update_channel_size: NZUsize!(1),
        };
        let synced_db = <Arc<AsyncRwLock<TestDb>> as StateSyncSet<_, _>>::sync(
            context.clone().with_label("sync_client"),
            qmdb_config("synced", &context),
            client_mailbox.clone(),
            sync_target,
            None,
            sync_config,
        )
        .await
        .unwrap();

        client_mailbox.attach_database(synced_db.clone()).await;

        // Force future resolver fetches to avoid the original source peer.
        server_handle.abort();
        manager
            .track(
                0,
                vec![client_pk.clone(), verifier_pk.clone()]
                    .try_into()
                    .unwrap(),
            )
            .await;

        let fetch = verifier_mailbox
            .get_operations(target_range.end, probe_start, probe_max_ops, false)
            .await
            .unwrap();
        assert!(!fetch.operations.is_empty());
        let _ = fetch.success_tx.send(true);

        client_handle.abort();
        verifier_handle.abort();
    });
}
