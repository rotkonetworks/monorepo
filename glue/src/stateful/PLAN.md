# State Sync Refactor: One-Shot Database Creation

## Context

State sync creates and returns databases -- you cannot sync into an existing database. The current `SyncableDb::spawn_sync` and `SyncableDatabaseSet::start_sync` incorrectly take existing databases. We need to flip the model: sync produces databases, and the `Stateful` actor receives them after completion.

State sync is one-shot: it happens at most once per node lifetime. Three startup cases:
1. **Genesis**: Network bootstrapping. Create empty databases immediately.
2. **Sync**: Joining a running network. Sync engine runs in background, produces databases.
3. **Already synced**: Restart after prior sync. Open existing databases from disk.

Metadata persistence ensures sync is never re-attempted after completion.

## Files to Modify

| File | Change |
|------|--------|
| `glue/src/stateful/db.rs` | Replace `SyncableDb::spawn_sync` and `SyncableDatabaseSet::start_sync` with static factory methods |
| `glue/src/stateful/sync.rs` | Rework `Coordinator` to create/hold databases, add metadata persistence, add `Startup` enum |
| `glue/src/stateful/actor/core.rs` | Make `databases` an `Option`, gate operations, integrate coordinator |
| `glue/src/stateful/actor/mailbox.rs` | Add `SyncTargetUpdate` message variant |
| `glue/src/stateful/mod.rs` | Update `Application::Databases` bound, re-exports |
| `glue/src/stateful/wrapper.rs` | Same changes as actor/core.rs for the Clone-based wrapper |
| `glue/src/stateful/tests/mocks/db.rs` | Implement revised traits |
| `glue/src/stateful/tests/mocks/app.rs` | Update config construction |
| `glue/src/stateful/tests/mod.rs` | Update test setup for new startup API |

## Step 1: Revise `db.rs` Traits

Remove `SyncableDb` trait entirely. Change `SyncableDatabaseSet` methods:

```rust
pub trait SyncableDatabaseSet: DatabaseSet {
    type SyncConfigs: Clone + Send + Sync;
    type SyncResolvers: Clone + Send + Sync;
    type SyncTargets: Clone + Send;
    type SyncError: Debug + Send;

    /// Create empty databases for genesis bootstrap.
    fn create_genesis<E>(
        context: E,
        sync_configs: Self::SyncConfigs,
    ) -> impl Future<Output = Result<Self, Self::SyncError>> + Send
    where
        E: Rng + Spawner + Metrics + Clock;

    /// Open existing databases from disk (restart after completed sync).
    fn open<E>(
        context: E,
        sync_configs: Self::SyncConfigs,
    ) -> impl Future<Output = Result<Self, Self::SyncError>> + Send
    where
        E: Rng + Spawner + Metrics + Clock;

    /// Spawn a background sync that creates and returns databases.
    fn spawn_sync<E>(
        context: E,
        sync_configs: Self::SyncConfigs,
        sync_resolvers: Self::SyncResolvers,
        initial_targets: Self::SyncTargets,
    ) -> Result<SyncHandle<Self>, Self::SyncError>
    where
        E: Rng + Spawner + Metrics + Clock;
}

/// Handle returned by `spawn_sync`.
pub struct SyncHandle<D: SyncableDatabaseSet> {
    /// Forward newer sync targets while sync runs.
    pub target_updates: mpsc::Sender<D::SyncTargets>,
    /// Resolves with the created databases on completion.
    pub completion: oneshot::Receiver<Result<D, D::SyncError>>,
}
```

Key changes:
- All three methods are **static** (no `&self`). Sync creates databases rather than filling them.
- `SyncHandle::completion` yields `Result<D, ...>` (the databases), not `Result<(), ...>`.
- `SyncableDb` (per-database trait) is removed. Sync orchestration is at the set level only.
- `SyncConfigs` is reused for all paths (implementors can ignore sync-specific fields for genesis/open).
- Update the `Arc<AsyncRwLock<T>>` impl and tuple macro impls.

## Step 2: Add `Startup` Enum and Metadata to `sync.rs`

```rust
/// How databases should be obtained at startup.
pub enum Startup<D: SyncableDatabaseSet> {
    /// Genesis bootstrap: create empty databases. Immediate readiness.
    Genesis,
    /// Already synced: open existing databases. Immediate readiness.
    Open,
    /// Sync from peers: user provides initial target directly.
    Sync {
        initial_target: D::SyncTargets,
    },
}
```

**Metadata persistence** -- two public helpers using the runtime `Storage` trait:

```rust
const METADATA_PARTITION: &str = "stateful-sync-metadata";
const METADATA_KEY: &[u8] = b"completed";

pub async fn has_completed<E: Storage>(context: &E) -> bool { ... }
async fn mark_completed<E: Storage>(context: &E) { ... }
```

The caller checks `has_completed` at startup to decide between `Startup::Open` and `Startup::Sync`. The coordinator calls `mark_completed` after sync succeeds.

**Revised `Coordinator`:**

No `Waiting` state -- user provides initial target directly, so sync starts in `init`.

```rust
enum State<D: SyncableDatabaseSet> {
    /// Sync started. Target updates forwarded to engine.
    Running,
    /// Databases available (genesis, open, or sync completed).
    Ready,
}

pub(crate) struct Coordinator<E, D: SyncableDatabaseSet> {
    context: E,
    readiness: Gate,
    state: Arc<Mutex<State<D>>>,
    target_sender: Arc<Mutex<Option<mpsc::Sender<D::SyncTargets>>>>,
    /// Databases stored here once ready. Retrieved by the actor.
    databases: Arc<Mutex<Option<D>>>,
}
```

Construction paths:
- `Coordinator::ready(databases: D)` -- for genesis/open. Immediately ready.
- `Coordinator::syncing(context, handle: SyncHandle<D>)` -- stores target sender, spawns completion watcher.

The completion watcher:
1. Awaits `handle.completion`.
2. On success: calls `mark_completed`, stores databases, marks gate ready.
3. On failure: logs warning. (Retry requires restart since sync is one-shot.)

`update_targets(&self, targets)` -- forwards via `try_send` on the stored sender.

## Step 3: Update `Stateful` Actor (`actor/core.rs`)

**Config changes:**

```rust
pub struct Config<E, A, P> {
    pub app: A,
    pub input_provider: A::InputProvider,
    pub block_provider: P,
    pub startup: sync::Startup<A::Databases>,
    pub sync_config: sync::Config<A::Databases>,
    // databases field REMOVED
}
```

**`init` becomes `async`** to handle genesis/open I/O:

```rust
pub async fn init(context: E, config: Config<E, A, P>) -> (Self, Mailbox<E, A>) {
    let (databases, coordinator) = match config.startup {
        Startup::Genesis => {
            let dbs = D::create_genesis(context.clone(), sync_configs)
                .await.expect("genesis database creation failed");
            (Some(dbs.clone()), Coordinator::ready(dbs))
        }
        Startup::Open => {
            let dbs = D::open(context.clone(), sync_configs)
                .await.expect("database open failed");
            (Some(dbs.clone()), Coordinator::ready(dbs))
        }
        Startup::Sync { initial_target } => {
            let handle = D::spawn_sync(context.clone(), sync_configs, sync_resolvers, initial_target)
                .expect("sync start failed");
            (None, Coordinator::syncing(context.clone(), handle))
        }
    };
    // ... construct Self with databases: Option<D>, coordinator
}
```

**Gating:**
- `handle_propose`: if `databases.is_none()`, respond with `None` immediately.
- `handle_verify`: await `coordinator.wait_until_ready()`, then retrieve databases from coordinator if still `None`.
- `handle_finalized`: if `databases.is_none()`, only forward sync targets (skip finalize/replay). If `databases.is_some()`, normal path.
- `start_batches`, `rebuild_pending`: only callable when databases are `Some`.

**Database retrieval after sync completes:**

```rust
fn try_install_databases(&mut self) {
    if self.databases.is_none() {
        if let Some(dbs) = self.coordinator.take_databases() {
            self.databases = Some(dbs);
        }
    }
}
```

Called after `wait_until_ready` returns in `handle_verify`, and at the start of `handle_finalized` when readiness is detected.

## Step 4: Update Mailbox (`actor/mailbox.rs`)

Add a `SyncTargetUpdate` message for forwarding finalization-derived targets:

```rust
/// Forward a sync target update to the coordinator.
SyncTargetUpdate {
    targets: <A::Databases as SyncableDatabaseSet>::SyncTargets,
},
```

This is sent from the `Reporter` impl on `Mailbox` (which handles `Activity::Finalization`).

## Step 5: Update `mod.rs`

- `Application::Databases` bound stays `SyncableDatabaseSet` (trait name unchanged).
- Keep `sync_targets` method on `Application` -- it's the app's hook for extracting targets from blocks.
- Update re-exports: add `sync::Startup`, `sync::has_completed`.

## Step 6: Update Mocks and Tests

**`tests/mocks/db.rs`:**
- `MockDb` implements the revised `SyncableDatabaseSet` for `Arc<AsyncRwLock<MockDb>>`.
- `create_genesis` returns `Arc::new(AsyncRwLock::new(MockDb::default()))`.
- `open` returns similar.
- `spawn_sync` spawns a task that polls the resolver until root matches target, then sends `Ok(databases)` on completion.

**`tests/mocks/app.rs`:**
- `ConsensusEngine::init` constructs `Startup::Genesis` for all validators in simple tests.
- Delayed validators use `Startup::Sync { initial_target }` to exercise the sync path.

**`sync.rs` tests:**
- Update `MockDatabaseSet` to implement revised trait methods.
- Add tests for: genesis path (immediate ready), sync completion (databases received), metadata persistence.

**`wrapper.rs` tests:**
- Update `TrackingDatabases` and `RecordingDatabases` to implement revised trait.
- Update `StatefulConfig` construction (no `databases` field, add `startup`).

## Verification

1. `cargo check -p commonware-glue` -- compiles without errors
2. `just test -p commonware-glue` -- all existing tests pass with updated mocks
3. Specifically verify:
   - `all_validators_finalize_and_commit` -- genesis path works
   - `sync_then_participate` -- sync path works end-to-end
   - `stale_sync_target_update_is_ignored_when_fetch_completes_late` -- target forwarding works
   - `sync.rs` unit tests -- coordinator state machine correct
