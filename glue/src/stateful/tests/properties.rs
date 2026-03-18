use crate::{
    simulate::{processed::ProcessedHeight, property::Property, tracker::ProgressTracker},
    stateful::tests::app::MockValidatorState,
};
use commonware_cryptography::ed25519;
use std::{future::Future, pin::Pin};

/// Post-run property: all validators agree on the finalized block at `height`.
pub(crate) struct BlockAgreementAtHeight {
    pub(crate) height: u64,
}

impl Property<ed25519::PublicKey, MockValidatorState> for BlockAgreementAtHeight {
    fn name(&self) -> &str {
        "block_agreement_at_height"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a MockValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let mut expected = None;
            for state in states {
                let Some(digest) = state.digest_at_height(self.height).await else {
                    return Err(format!(
                        "missing finalized digest at height {} on at least one validator",
                        self.height
                    ));
                };
                if let Some(previous) = expected {
                    if digest != previous {
                        return Err(format!(
                            "digest disagreement at finalized height {}",
                            self.height
                        ));
                    }
                } else {
                    expected = Some(digest);
                }
            }

            Ok(())
        })
    }
}

/// Post-run property: at least one node used startup state sync and then advanced further.
pub(crate) struct LateJoinerStateSyncHandoff;

impl Property<ed25519::PublicKey, MockValidatorState> for LateJoinerStateSyncHandoff {
    fn name(&self) -> &str {
        "late_joiner_state_sync_handoff"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a MockValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for state in states {
                let Some(sync_height) = state.startup_sync_height() else {
                    continue;
                };
                let processed_height = state.processed_height().await;
                if processed_height > sync_height {
                    return Ok(());
                }
            }

            Err(
                "no validator both used startup state sync and advanced beyond the synced height"
                    .to_string(),
            )
        })
    }
}
