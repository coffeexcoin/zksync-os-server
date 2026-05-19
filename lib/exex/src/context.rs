use crate::manager::ManagerCommand;
use crate::notification::ZkExExNotification;
use alloy::eips::BlockNumHash;
use futures::Stream;
use reth_tasks::Runtime;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use zksync_os_storage_api::ReadFinality;

/// Sender used by ExExes to acknowledge durable progress.
#[derive(Clone)]
pub struct ZkExExEventSender {
    pub(crate) id: String,
    pub(crate) sender: mpsc::Sender<ManagerCommand>,
}

impl ZkExExEventSender {
    pub async fn send_finished_height(&self, height: BlockNumHash) -> anyhow::Result<()> {
        self.sender
            .send(ManagerCommand::FinishedHeight {
                id: self.id.clone(),
                height,
            })
            .await?;
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

/// ExEx notification stream with optional WAL backfill before live delivery.
pub struct ZkExExNotifications {
    receiver: mpsc::Receiver<ZkExExNotification>,
    backfill: VecDeque<ZkExExNotification>,
    head: BlockNumHash,
}

impl ZkExExNotifications {
    pub(crate) fn new(
        receiver: mpsc::Receiver<ZkExExNotification>,
        backfill: Vec<ZkExExNotification>,
        head: BlockNumHash,
    ) -> Self {
        Self {
            receiver,
            backfill: VecDeque::from(backfill),
            head,
        }
    }

    pub async fn recv(&mut self) -> Option<ZkExExNotification> {
        if let Some(notification) = self.next_backfill() {
            return Some(notification);
        }

        loop {
            let notification = self.receiver.recv().await?;
            if !notification.is_at_or_below(self.head) {
                return Some(notification);
            }
        }
    }

    fn next_backfill(&mut self) -> Option<ZkExExNotification> {
        while let Some(notification) = self.backfill.pop_front() {
            if !notification.is_at_or_below(self.head) {
                return Some(notification);
            }
        }
        None
    }

    pub fn pending_backfill_len(&self) -> usize {
        self.backfill.len()
    }
}

impl Stream for ZkExExNotifications {
    type Item = ZkExExNotification;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(notification) = this.next_backfill() {
            return Poll::Ready(Some(notification));
        }

        loop {
            match Pin::new(&mut this.receiver).poll_recv(cx) {
                Poll::Ready(Some(notification)) if notification.is_at_or_below(this.head) => {}
                Poll::Ready(other) => return Poll::Ready(other),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Context passed to a ZKsync ExEx at launch time.
pub struct ZkExExContext<Repository, Replay, Finality, State> {
    pub head: BlockNumHash,
    pub runtime: Runtime,
    pub events: ZkExExEventSender,
    pub notifications: ZkExExNotifications,
    pub repository: Repository,
    pub replay: Replay,
    pub finality: Finality,
    pub state: State,
}

impl<Repository, Replay, Finality, State> ZkExExContext<Repository, Replay, Finality, State> {
    pub fn id(&self) -> &str {
        self.events.id()
    }

    pub async fn send_finished_height(&self, height: BlockNumHash) -> anyhow::Result<()> {
        self.events.send_finished_height(height).await
    }

    pub fn repository(&self) -> &Repository {
        &self.repository
    }

    pub fn replay(&self) -> &Replay {
        &self.replay
    }

    pub fn finality(&self) -> &Finality {
        &self.finality
    }

    pub fn state(&self) -> &State {
        &self.state
    }
}

impl<Repository, Replay, Finality, State> ZkExExContext<Repository, Replay, Finality, State>
where
    Finality: ReadFinality,
{
    pub fn latest_finality_status(&self) -> zksync_os_storage_api::FinalityStatus {
        self.finality.get_finality_status()
    }
}
