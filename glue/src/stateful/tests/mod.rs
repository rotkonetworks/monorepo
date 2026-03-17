//! E2E tests for `stateful`

use crate::simulate::{
    engine::EngineDefinition,
    exit::ProcessedHeightAtLeast,
    fault::{Crash, Fault, Schedule},
    plan::PlanBuilder,
};
use app::ConsensusEngine;
use commonware_macros::test_traced;
use properties::BlockAgreementAtHeight;
use std::time::Duration;

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
