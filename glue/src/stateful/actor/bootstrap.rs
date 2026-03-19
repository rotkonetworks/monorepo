//! Sync orchestration for the [`crate::stateful::Stateful`] actor.
//!
//! When a node boots via state sync, the `Stateful` actor starts in
//! `Mode::Syncing` and a background
//! sync task constructs the databases. This module provides the types and
//! orchestration logic that bridge the two:
//!
//! - [`SyncTip`]: a bundle of `(height, digest, targets)` emitted by the
//!   actor whenever marshal reports a new finalized tip during sync.
//! - [`bootstrap`]: runs one-time startup state sync (if needed), then sets
//!   marshal floor and transitions the actor to running mode.
//!
//! # Height tracking
//!
//! Tip updates stream into the sync process as it runs, so the height
//! that the databases actually synced to is determined by the sync
//! routine, not pre-determined.

use crate::stateful::{
    db::{DatabaseSet, StateSyncSet},
    Application, Mailbox,
};
use commonware_consensus::{marshal, types::Height, Application as ConsensusApplication};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::metadata::{Config as MetadataConfig, Metadata};
use commonware_utils::{channel::mpsc, sequence::U64, sync::Mutex};
use rand::Rng;
use std::sync::Arc;
use tracing::info;

/// Durable metadata key for "state sync completed".
const SYNC_DONE_KEY: U64 = U64::new(0);

/// A finalized-tip notification forwarded from the `Stateful`
/// actor to the background sync task during state sync.
///
/// Bundles the tip's height and digest with the per-database sync targets
/// extracted by [`Application::sync_targets`]
/// (whose type comes from [`DatabaseSet::SyncTargets`]).
pub struct SyncTip<T, D> {
    /// The height of the finalized block that produced these targets.
    pub height: Height,

    /// The digest of the finalized block.
    pub digest: D,

    /// Per-database sync targets extracted from the block.
    pub targets: T,
}

type AppSyncTip<A, E> = SyncTip<
    <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets,
    <<A as Application<E>>::Block as Digestible>::Digest,
>;

/// Startup inputs for bootstrap.
pub enum Startup<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
{
    /// Initialize databases without running startup state sync.
    Fresh,

    /// Run startup state sync from an initial tip and follow tip updates.
    Sync {
        initial_tip: AppSyncTip<A, E>,
        tip_updates: mpsc::Receiver<AppSyncTip<A, E>>,
        resolvers: R,
    },
}

/// Configuration for one-time startup state-sync bootstrap.
pub struct BootstrapConfig<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R>,
{
    /// Runtime context used for metadata and database initialization.
    pub context: E,

    /// Database configuration for the managed set.
    pub db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Metadata partition that stores the durable "state sync done" bit.
    pub metadata_partition: String,

    /// Per-database sync engine parameters.
    pub sync_config: crate::stateful::db::SyncEngineConfig,

    /// Startup mode and required inputs for that mode.
    pub startup: Startup<E, A, R>,
}

async fn current_anchor<E, A, S, V>(
    marshal: &marshal::core::Mailbox<S, V>,
    mailbox: &Mailbox<E, A>,
) -> (Height, <A::Block as Digestible>::Digest)
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    A::Context: Send,
    S: Scheme,
    V: marshal::core::Variant<ApplicationBlock = A::Block>,
{
    let processed_height = marshal
        .get_processed_height()
        .await
        .expect("state sync bootstrap failed to fetch marshal processed height");
    if processed_height == Height::zero() {
        let mut mailbox = mailbox.clone();
        let genesis_digest = mailbox.genesis().await.digest();
        return (Height::zero(), genesis_digest);
    }
    let (_, digest) = marshal
        .get_info(marshal::Identifier::Height(processed_height))
        .await
        .unwrap_or_else(|| {
            panic!(
                "state sync bootstrap missing processed block digest at height {}",
                processed_height.get()
            )
        });
    (processed_height, digest)
}

/// Run startup bootstrap and then transition the actor from syncing to running mode.
///
/// This orchestrates the three startup states:
/// 1. `sync_done = true`: skip state sync, open existing database(s), transition immediately.
/// 2. `sync_done = false` + `initial_tip = None`: initialize a fresh database, mark sync done,
///    and let marshal backfill from genesis.
/// 3. `sync_done = false` + `initial_tip = Some`: run active state sync once, persist sync done,
///    then transition.
///
/// Note: this is intentionally "once only". If metadata says state sync completed, startup never
/// re-enters active state sync.
pub async fn bootstrap<E, A, S, V, R>(
    marshal: marshal::core::Mailbox<S, V>,
    mailbox: Mailbox<E, A>,
    config: BootstrapConfig<E, A, R>,
) where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Context: Send,
    A::Databases: StateSyncSet<E, R>,
    S: Scheme,
    V: marshal::core::Variant<ApplicationBlock = A::Block>,
    R: Clone + Send + 'static,
{
    let marshal_for_sync = marshal.clone();
    let mailbox_for_sync = mailbox.clone();
    let (databases, sync_height, last_processed_digest, floor_height) = {
        let mut metadata = Metadata::<E, U64, bool>::init(
            config.context.clone().with_label("state_sync_metadata"),
            MetadataConfig {
                partition: config.metadata_partition,
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize state sync metadata store");
        let sync_done = metadata.get(&SYNC_DONE_KEY).copied().unwrap_or(false);
        let startup = config.startup;

        if sync_done {
            assert!(
                matches!(startup, Startup::Fresh),
                "state sync bootstrap received a sync startup target after state sync was already marked complete",
            );
            let databases = A::Databases::init(config.context.clone(), config.db_config).await;
            let (height, digest) = current_anchor(&marshal_for_sync, &mailbox_for_sync).await;
            (databases, height, digest, None)
        } else {
            match startup {
                Startup::Fresh => {
                    let databases =
                        A::Databases::init(config.context.clone(), config.db_config).await;
                    metadata.put(SYNC_DONE_KEY, true);
                    metadata
                        .sync()
                        .await
                        .expect("failed to persist state sync completion metadata");
                    let genesis_digest = mailbox_for_sync.clone().genesis().await.digest();
                    (databases, Height::zero(), genesis_digest, None)
                }
                Startup::Sync {
                    initial_tip,
                    mut tip_updates,
                    resolvers,
                } => {
                    marshal.set_floor(initial_tip.height).await;
                    let latest_tip = Arc::new(Mutex::new((initial_tip.height, initial_tip.digest)));
                    let latest_tip_for_forwarder = latest_tip.clone();
                    let context = config.context.clone();
                    let (target_tx, target_rx) =
                        mpsc::channel(config.sync_config.update_channel_size.get());
                    let tip_forwarder: Handle<()> = context
                        .with_label("state_sync_tip_forwarder")
                        .spawn(move |_| async move {
                            while let Some(tip) = tip_updates.recv().await {
                                if target_tx.try_send(tip.targets).is_err() {
                                    continue;
                                }
                                let mut guard = latest_tip_for_forwarder.lock();
                                *guard = (tip.height, tip.digest);
                            }
                        });

                    let databases = <A::Databases as StateSyncSet<E, R>>::sync(
                        config.context.clone(),
                        config.db_config,
                        resolvers,
                        initial_tip.targets,
                        Some(target_rx),
                        config.sync_config,
                    )
                    .await
                    .unwrap_or_else(|err| panic!("state sync failed: {err:?}"));

                    tip_forwarder.abort();

                    metadata.put(SYNC_DONE_KEY, true);
                    metadata
                        .sync()
                        .await
                        .expect("failed to persist state sync completion metadata");

                    let (height, digest) = *latest_tip.lock();
                    (databases, height, digest, Some(height))
                }
            }
        }
    };

    if let Some(floor_height) = floor_height {
        info!(
            sync_height = sync_height.get(),
            "sync complete, setting marshal floor and transitioning to running"
        );
        marshal.set_floor(floor_height).await;
        let processed_height = marshal
            .get_processed_height()
            .await
            .expect("marshal must respond with processed height after set_floor");
        assert!(
            processed_height >= floor_height,
            "marshal floor must be applied before sync_complete"
        );
    } else {
        info!(
            sync_height = sync_height.get(),
            "sync complete, transitioning to running"
        );
    }
    mailbox
        .sync_complete(databases, last_processed_digest)
        .await;
}
