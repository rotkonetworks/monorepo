//! Mailbox for the [`super::Stateful`] actor.

use crate::stateful::Application;
use commonware_consensus::{
    marshal::{
        ancestry::{AncestorStream, BlockProvider, ErasedBlockProvider},
        Update,
    },
    types::Round,
    Application as ConsensusApplication, Reporter,
    VerifyingApplication as ConsensusVerifyingApplication,
};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    Acknowledgement,
};
use rand::Rng;

/// Type alias for an ancestor stream with an erased block provider.
pub type ErasedAncestorStream<B> = AncestorStream<ErasedBlockProvider<B>, B>;

/// Messages processed by the actor loop.
pub(crate) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// A request for the genesis block.
    Genesis { response: oneshot::Sender<A::Block> },

    /// A request to propose a block.
    Propose {
        context: (E, A::Context),
        ancestry: ErasedAncestorStream<A::Block>,
        response: oneshot::Sender<Option<A::Block>>,
    },

    /// A request to verify a block.
    Verify {
        context: (E, A::Context),
        ancestry: ErasedAncestorStream<A::Block>,
        response: oneshot::Sender<bool>,
    },

    /// A reporting of a new finalized tip.
    Finalized {
        round: Round,
        digest: <A::Block as Digestible>::Digest,
    },
}

/// Channel-based proxy to the [`Stateful`](super::Stateful) actor.
///
/// Implements the consensus [`Application`] and [`VerifyingApplication`]
/// traits by forwarding each call to the actor via a message and awaiting
/// the response.
pub struct Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    sender: mpsc::Sender<Message<E, A>>,
}

impl<E, A> Clone for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<E, A> Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Create a mailbox from the send half of the actor's message channel.
    pub(crate) fn new(sender: mpsc::Sender<Message<E, A>>) -> Self {
        Self { sender }
    }
}

impl<E, A> ConsensusApplication<E> for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    A::Context: Send,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = A::Block;

    async fn genesis(&mut self) -> Self::Block {
        self.sender
            .request(|response| Message::Genesis { response })
            .await
            .expect("stateful actor dropped during genesis")
    }

    async fn propose<BP: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<BP, Self::Block>,
    ) -> Option<Self::Block> {
        let ancestry = ancestry.erase();
        self.sender
            .request(|response| Message::Propose {
                context,
                ancestry,
                response,
            })
            .await
            .flatten()
    }
}

impl<E, A> ConsensusVerifyingApplication<E> for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    A::Context: Send,
{
    async fn verify<BP: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<BP, Self::Block>,
    ) -> bool {
        let ancestry = ancestry.erase();
        self.sender
            .request_or(
                |response| Message::Verify {
                    context,
                    ancestry,
                    response,
                },
                false,
            )
            .await
    }
}

impl<E, A> Reporter for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    A::Context: Send,
{
    type Activity = Update<A::Block>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Update::Tip(round, _, digest) => {
                self.sender
                    .send_lossy(Message::Finalized { round, digest })
                    .await;
            }
            Update::Block(_, ack) => ack.acknowledge(),
        }
    }
}
