# QMDB P2P Resolver: Phased Integration Plan

## Scope

Implement a P2P-backed resolver for QMDB state sync that can:

1. Fetch operations from peers (client side) to satisfy `commonware_storage::qmdb::sync::resolver::Resolver`.
2. Serve operations and proofs to peers (server side).
3. Start before databases exist, then attach databases when startup sync completes.
4. Support one resolver per database in arbitrary `DatabaseSet` tuples.

This plan assumes we keep using `commonware-resolver` for transport.

## Target Model

### One Resolver Per Database

For each database in `DatabaseSet`, run one resolver actor.

- DB1 <-> Resolver1
- DB2 <-> Resolver2
- ...

The resolver set shape matches the database set shape (single resolver for single DB, tuple of resolvers for tuple DB set).

### Two-Stage Resolver State

Resolver actor has an explicit state machine:

1. `NoDb`
2. `HasDb(Arc<AsyncRwLock<DB>>)`

Behavior:

- On `Produce` while `NoDb`: deny request.
- On `Produce` while `HasDb`: serve proof + operations.
- `Deliver` and `Failed` continue to function in both states for outbound fetch requests.

## Chicken-and-Egg Resolution

Problem: state sync needs resolvers, but databases are only available after bootstrap.

Solution:

1. Start resolver actors in `NoDb` state.
2. Pass resolver mailboxes to `Stateful` startup.
3. Bootstrap uses resolver mailboxes for outbound fetches during state sync.
4. Bootstrap completes and gives databases to `Stateful` via `SyncComplete`.
5. Actor attaches each finalized database to its corresponding resolver.
6. Resolvers move to `HasDb` and begin serving peers.

This removes circular construction and keeps ownership boundaries clear.

## API Changes

### Resolver Module

In `glue/src/stateful/db/qmdb/resolver`:

1. Make `Actor::Config` database optional-at-start (or remove required `database` field).
2. Add an attach message path:
   - `AttachDatabase { db: Arc<AsyncRwLock<DB>> }`
3. Expose attach handle on mailbox/handle:
   - `attach_database(db)`
4. In `Produce`:
   - `NoDb` => deny
   - `HasDb` => call `SyncableDb::get_operations`

### Resolver Traits

Introduce an attach trait for typed orchestration:

- `AttachableResolver<DB>`
- `attach_database(&self, Arc<AsyncRwLock<DB>>) -> Future<Output = ()>`

Add set-level typed fan-out trait:

- Single DB impl: attach one resolver to one DB
- Tuple impls: attach resolver tuple index-wise to DB tuple

The tuple macro pattern should mirror existing `DatabaseSet` and `StateSyncSet` macro strategy.

### Stateful Actor Wiring

In `glue/src/stateful/actor/core.rs`:

1. Store resolver set in actor startup state.
2. In `handle_sync_complete`:
   - attach resolvers to databases first
   - then transition `Syncing -> Running`
3. Keep `propose` and `verify` gating semantics unchanged.

## Syncable DB Serving Semantics

`SyncableDb` must represent serving semantics explicitly.

- Keep/extend `get_operations` contract to return proof + operations + pinned nodes.
- Ensure QMDB implementations return exactly what sync engine expects.
- Align with `examples/sync` server behavior (historical proof + optional pinned nodes), but via `commonware-resolver` request/response plumbing instead of ad hoc stream protocol.

## Phases

## Phase 0: Interface Freeze

Deliverables:

1. Resolver attach interfaces (`AttachableResolver`, set-level attach trait).
2. Resolver actor state enum (`NoDb`/`HasDb`).
3. Message/API signatures for `attach_database`.

Acceptance:

1. Compiles with no behavior change yet.
2. No bootstrap integration in this phase.

## Phase 1: Resolver Actor Two-Stage Runtime

Deliverables:

1. Implement `NoDb` produce-deny behavior.
2. Implement runtime attach transition to `HasDb`.
3. Implement normal serve path in `HasDb` via `SyncableDb::get_operations`.

Acceptance:

1. Unit test: `Produce` denied before attach.
2. Unit test: same request served after attach.

## Phase 2: Typed Resolver-Set Attach Fan-Out

Deliverables:

1. Single and tuple attach impls.
2. Index-stable attach behavior for tuples.

Acceptance:

1. Unit tests for 1-DB and 2-DB tuple attach mapping.
2. Type-level proof that heterogenous tuples compile.

## Phase 3: Stateful Integration

Deliverables:

1. Actor stores resolver set for startup lifecycle.
2. `handle_sync_complete` attaches DBs to resolver set before entering `Running`.

Acceptance:

1. Integration test: resolver denies pre-sync-complete.
2. Integration test: resolver serves post-sync-complete.

## Phase 4: End-to-End P2P State Sync

Deliverables:

1. Start one resolver actor per DB.
2. Pass resolver mailboxes into startup sync path.
3. Attach local DBs after sync completion.

Acceptance:

1. Node can sync from peers using resolver mailboxes.
2. Node can serve peers once local DBs are attached.

## Phase 5: Hardening and Observability

Deliverables:

1. Metrics for denied serve requests (`NoDb`) and served requests (`HasDb`).
2. Structured logs on attach transitions.
3. Failure-path tests (`Deliver`/`Failed`, dropped responses, retries).

Acceptance:

1. Deterministic async tests cover attach timing races.
2. Multi-DB tuple integration scenario passes.

## Non-Goals in This Plan

1. Introducing a non-P2P resolver transport.
2. Changing state sync gating semantics in `Stateful`.
3. Reworking marshal backfill semantics.
