//! E2E tests for `stateful`

use crate::simulate::{
    engine::EngineDefinition,
    exit::{ExitCondition, ProcessedHeightAtLeast},
    fault::{Crash, Fault, Schedule},
    plan::PlanBuilder,
    processed::ProcessedHeight,
    property::Property,
};
use commonware_cryptography::ed25519;
use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;
use multi_db_app::MultiDbEngine;
use properties::{BlockAgreementAtHeight, LateJoinerStateSyncHandoff};
use single_db_app::SingleDbEngine;
use std::time::Duration;

mod common;
pub(crate) mod multi_db_app;
pub(crate) mod properties;
pub(crate) mod single_db_app;

const NUM_VALIDATORS: u32 = 5;

#[test_traced("DEBUG")]
fn all_validators_finalize_and_commit() {
    run_finalize(SingleDbEngine::new(NUM_VALIDATORS));
    run_finalize(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_traced("DEBUG")]
fn deterministic_across_seeds() {
    run_determinism(SingleDbEngine::new(NUM_VALIDATORS));
    run_determinism(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_traced("DEBUG")]
fn crash_and_restart_one_validator() {
    run_crash_restart(SingleDbEngine::new(NUM_VALIDATORS));
    run_crash_restart(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_traced("DEBUG")]
fn delayed_start_one_validator() {
    run_delayed_start(SingleDbEngine::new(NUM_VALIDATORS));
    run_delayed_start(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_traced("DEBUG")]
fn late_joiner_state_sync_then_handoffs_to_marshal_sync() {
    run_late_joiner(SingleDbEngine::new(NUM_VALIDATORS).with_late_join_state_sync());
    run_late_joiner(MultiDbEngine::new(NUM_VALIDATORS).with_late_join_state_sync());
}

#[test_traced("DEBUG")]
fn lossy_network() {
    let link = Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(150),
        success_rate: 0.7,
    };
    run_lossy(SingleDbEngine::new(NUM_VALIDATORS), link.clone());
    run_lossy(MultiDbEngine::new(NUM_VALIDATORS), link);
}

#[test_traced("DEBUG")]
fn random_crashes() {
    run_random_crashes(SingleDbEngine::new(NUM_VALIDATORS));
    run_random_crashes(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_traced("DEBUG")]
fn many_concurrent_crashes() {
    run_many_crashes(SingleDbEngine::new(NUM_VALIDATORS));
    run_many_crashes(MultiDbEngine::new(NUM_VALIDATORS));
}

fn run_finalize<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .exit_condition(ProcessedHeightAtLeast::new(100))
        .property(BlockAgreementAtHeight { height: 100 })
        .run()
        .unwrap();
}

fn run_determinism<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey> + Clone,
    D::State: ProcessedHeight + PartialEq,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    for seed in 0..5 {
        let r1 = PlanBuilder::new(engine.clone())
            .seed(seed)
            .exit_condition(ProcessedHeightAtLeast::new(20))
            .property(BlockAgreementAtHeight { height: 20 })
            .run()
            .unwrap();
        let r2 = PlanBuilder::new(engine.clone())
            .seed(seed)
            .exit_condition(ProcessedHeightAtLeast::new(20))
            .property(BlockAgreementAtHeight { height: 20 })
            .run()
            .unwrap();
        assert_eq!(r1.state, r2.state, "seed {seed} produced different state");
    }
}

fn run_crash_restart<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
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

fn run_delayed_start<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .crash(Crash::Delay { count: 1, after: 5 })
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 20 })
        .run()
        .unwrap();
}

fn run_late_joiner<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    LateJoinerStateSyncHandoff: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
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

fn run_lossy<D>(engine: D, link: Link)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .link(link)
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 20 })
        .run()
        .unwrap();
}

fn run_random_crashes<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .crash(Crash::Random {
            frequency: Duration::from_secs(2),
            downtime: Duration::from_secs(1),
            count: 1,
        })
        .exit_condition(ProcessedHeightAtLeast::new(50))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 50 })
        .run()
        .unwrap();
}

fn run_many_crashes<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .crash(Crash::Random {
            frequency: Duration::from_secs(2),
            downtime: Duration::from_millis(500),
            count: 3,
        })
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 20 })
        .run()
        .unwrap();
}
