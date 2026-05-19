use crate::context::{ZkExExEventSender, ZkExExNotifications};
use crate::notification::ZkExExNotification;
use crate::wal::ZkExExWal;
use alloy::eips::BlockNumHash;
use tokio::sync::{mpsc, watch};
use zksync_os_storage_api::FinalityStatus;

pub const DEFAULT_EXEX_MANAGER_CAPACITY: usize = 8192;

#[derive(Clone, Debug)]
pub struct ZkExExConfig {
    pub id: String,
    pub head: Option<BlockNumHash>,
}

impl ZkExExConfig {
    pub fn new(id: impl Into<String>, head: Option<BlockNumHash>) -> Self {
        Self {
            id: id.into(),
            head,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinishedZkExExHeight {
    NoExExs,
    NotReady,
    Height(BlockNumHash),
}

pub struct ZkExExRegistration {
    pub id: String,
    pub head: BlockNumHash,
    pub events: ZkExExEventSender,
    pub notifications: ZkExExNotifications,
}

pub struct ZkExExManager {
    receiver: mpsc::Receiver<ManagerCommand>,
    exexes: Vec<ManagedZkExEx>,
    wal: ZkExExWal,
    finality_receiver: watch::Receiver<FinalityStatus>,
    finished_height_sender: watch::Sender<FinishedZkExExHeight>,
}

#[derive(Clone)]
pub struct ZkExExManagerHandle {
    sender: mpsc::Sender<ManagerCommand>,
    wal: ZkExExWal,
    finished_height_receiver: watch::Receiver<FinishedZkExExHeight>,
}

pub(crate) enum ManagerCommand {
    Notification(ZkExExNotification),
    FinishedHeight { id: String, height: BlockNumHash },
}

struct ManagedZkExEx {
    id: String,
    sender: mpsc::Sender<ZkExExNotification>,
    finished_height: Option<BlockNumHash>,
}

impl ZkExExManager {
    pub fn new(
        node_head: BlockNumHash,
        wal: ZkExExWal,
        finality_receiver: watch::Receiver<FinalityStatus>,
        exexes: Vec<ZkExExConfig>,
    ) -> anyhow::Result<(Self, ZkExExManagerHandle, Vec<ZkExExRegistration>)> {
        Self::with_capacity(
            node_head,
            wal,
            finality_receiver,
            exexes,
            DEFAULT_EXEX_MANAGER_CAPACITY,
        )
    }

    pub fn with_capacity(
        node_head: BlockNumHash,
        wal: ZkExExWal,
        finality_receiver: watch::Receiver<FinalityStatus>,
        exexes: Vec<ZkExExConfig>,
        capacity: usize,
    ) -> anyhow::Result<(Self, ZkExExManagerHandle, Vec<ZkExExRegistration>)> {
        let (sender, receiver) = mpsc::channel(capacity);
        let initial_finished_height = if exexes.is_empty() {
            FinishedZkExExHeight::NoExExs
        } else {
            FinishedZkExExHeight::NotReady
        };
        let (finished_height_sender, finished_height_receiver) =
            watch::channel(initial_finished_height);

        let mut managed = Vec::with_capacity(exexes.len());
        let mut registrations = Vec::with_capacity(exexes.len());
        for config in exexes {
            let head = config.head.unwrap_or(node_head);
            let backfill = wal.notifications_after_head(head)?;
            let (notification_sender, notification_receiver) = mpsc::channel(1);
            managed.push(ManagedZkExEx {
                id: config.id.clone(),
                sender: notification_sender,
                finished_height: None,
            });
            registrations.push(ZkExExRegistration {
                id: config.id.clone(),
                head,
                events: ZkExExEventSender {
                    id: config.id,
                    sender: sender.clone(),
                },
                notifications: ZkExExNotifications::new(notification_receiver, backfill, head),
            });
        }

        let handle = ZkExExManagerHandle {
            sender,
            wal: wal.clone(),
            finished_height_receiver,
        };
        let manager = Self {
            receiver,
            exexes: managed,
            wal,
            finality_receiver,
            finished_height_sender,
        };
        Ok((manager, handle, registrations))
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        self.finalize_wal()?;

        loop {
            tokio::select! {
                command = self.receiver.recv() => {
                    let Some(command) = command else {
                        return Ok(());
                    };
                    self.handle_command(command).await?;
                }
                result = self.finality_receiver.changed() => {
                    if result.is_err() {
                        return Ok(());
                    }
                    self.finalize_wal()?;
                }
            }
        }
    }

    async fn handle_command(&mut self, command: ManagerCommand) -> anyhow::Result<()> {
        match command {
            ManagerCommand::Notification(notification) => {
                self.wal.commit(&notification)?;
                for exex in &self.exexes {
                    exex.sender.send(notification.clone()).await?;
                }
            }
            ManagerCommand::FinishedHeight { id, height } => {
                let Some(exex) = self.exexes.iter_mut().find(|exex| exex.id == id) else {
                    tracing::warn!(id, ?height, "received FinishedHeight from unknown ExEx");
                    return Ok(());
                };
                if exex
                    .finished_height
                    .is_none_or(|current| height.number >= current.number)
                {
                    exex.finished_height = Some(height);
                    self.publish_finished_height();
                    self.finalize_wal()?;
                }
            }
        }
        Ok(())
    }

    fn publish_finished_height(&self) {
        let height = self.lowest_finished_height();
        self.finished_height_sender.send_replace(height);
    }

    fn lowest_finished_height(&self) -> FinishedZkExExHeight {
        if self.exexes.is_empty() {
            return FinishedZkExExHeight::NoExExs;
        }

        self.exexes
            .iter()
            .map(|exex| exex.finished_height)
            .try_fold(None, |lowest: Option<BlockNumHash>, height| {
                let height = height?;
                Some(Some(lowest.map_or(height, |current| {
                    if height.number < current.number {
                        height
                    } else {
                        current
                    }
                })))
            })
            .flatten()
            .map_or(FinishedZkExExHeight::NotReady, FinishedZkExExHeight::Height)
    }

    fn finalize_wal(&self) -> anyhow::Result<()> {
        let finalized_block = self
            .finality_receiver
            .borrow()
            .last_finalized_executed_block;
        let prune_to = match self.lowest_finished_height() {
            FinishedZkExExHeight::NoExExs => finalized_block,
            FinishedZkExExHeight::NotReady => return Ok(()),
            FinishedZkExExHeight::Height(height) => finalized_block.min(height.number),
        };
        self.wal.finalize_up_to(prune_to)?;
        Ok(())
    }
}

impl ZkExExManagerHandle {
    pub async fn send_async(&self, notification: ZkExExNotification) -> anyhow::Result<()> {
        self.sender
            .send(ManagerCommand::Notification(notification))
            .await?;
        Ok(())
    }

    pub fn try_send(
        &self,
        notification: ZkExExNotification,
    ) -> Result<(), mpsc::error::TrySendError<ZkExExNotification>> {
        self.sender
            .try_send(ManagerCommand::Notification(notification))
            .map_err(|err| match err {
                mpsc::error::TrySendError::Full(ManagerCommand::Notification(notification)) => {
                    mpsc::error::TrySendError::Full(notification)
                }
                mpsc::error::TrySendError::Closed(ManagerCommand::Notification(notification)) => {
                    mpsc::error::TrySendError::Closed(notification)
                }
                mpsc::error::TrySendError::Full(ManagerCommand::FinishedHeight { .. }) => {
                    unreachable!("try_send only sends notifications")
                }
                mpsc::error::TrySendError::Closed(ManagerCommand::FinishedHeight { .. }) => {
                    unreachable!("try_send only sends notifications")
                }
            })
    }

    pub fn wal(&self) -> &ZkExExWal {
        &self.wal
    }

    pub fn finished_height_receiver(&self) -> watch::Receiver<FinishedZkExExHeight> {
        self.finished_height_receiver.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification::{ZkChainSegment, ZkExecutedBlock};
    use alloy::primitives::B256;
    use std::time::Duration;

    fn finality(finalized_block: u64) -> FinalityStatus {
        FinalityStatus {
            last_committed_block: finalized_block,
            last_committed_batch: finalized_block,
            last_executed_block: finalized_block,
            last_executed_batch: finalized_block,
            last_finalized_executed_block: finalized_block,
            last_finalized_executed_batch: finalized_block,
        }
    }

    fn head(number: u64) -> BlockNumHash {
        BlockNumHash::new(number, B256::with_last_byte(number as u8))
    }

    fn committed(number: u64) -> ZkExExNotification {
        ZkExExNotification::ChainCommitted {
            new: ZkChainSegment::single(ZkExecutedBlock::header_only(
                number,
                B256::with_last_byte(number as u8),
            )),
        }
    }

    #[tokio::test]
    async fn delivers_notifications_and_tracks_finished_height() {
        let temp = tempfile::tempdir().unwrap();
        let wal = ZkExExWal::open(temp.path()).unwrap();
        let (_finality_sender, finality_receiver) = watch::channel(finality(0));
        let (manager, handle, mut registrations) = ZkExExManager::with_capacity(
            head(0),
            wal,
            finality_receiver,
            vec![ZkExExConfig::new("indexer", None)],
            8,
        )
        .unwrap();
        let registration = registrations.pop().unwrap();
        let mut notifications = registration.notifications;
        let mut finished = handle.finished_height_receiver();
        let manager_task = tokio::spawn(manager.run());

        handle.send_async(committed(1)).await.unwrap();
        let received = notifications.recv().await.unwrap();
        assert_eq!(received.tip().unwrap().number, 1);

        registration
            .events
            .send_finished_height(head(1))
            .await
            .unwrap();
        finished.changed().await.unwrap();
        assert_eq!(*finished.borrow(), FinishedZkExExHeight::Height(head(1)));

        drop(handle);
        drop(registration.events);
        manager_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn waits_for_all_exexes_before_publishing_lowest_finished_height() {
        let temp = tempfile::tempdir().unwrap();
        let wal = ZkExExWal::open(temp.path()).unwrap();
        let (_finality_sender, finality_receiver) = watch::channel(finality(0));
        let (manager, handle, registrations) = ZkExExManager::with_capacity(
            head(0),
            wal,
            finality_receiver,
            vec![ZkExExConfig::new("a", None), ZkExExConfig::new("b", None)],
            8,
        )
        .unwrap();
        let mut finished = handle.finished_height_receiver();
        let manager_task = tokio::spawn(manager.run());

        registrations[0]
            .events
            .send_finished_height(head(3))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(*finished.borrow(), FinishedZkExExHeight::NotReady);

        registrations[1]
            .events
            .send_finished_height(head(2))
            .await
            .unwrap();
        while *finished.borrow_and_update() == FinishedZkExExHeight::NotReady {
            finished.changed().await.unwrap();
        }
        assert_eq!(*finished.borrow(), FinishedZkExExHeight::Height(head(2)));

        drop(handle);
        drop(registrations);
        manager_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn backfills_wal_notifications_after_exex_head_before_live_notifications() {
        let temp = tempfile::tempdir().unwrap();
        let wal = ZkExExWal::open(temp.path()).unwrap();
        wal.commit(&committed(1)).unwrap();
        wal.commit(&committed(2)).unwrap();
        let (_finality_sender, finality_receiver) = watch::channel(finality(0));
        let (manager, handle, mut registrations) = ZkExExManager::with_capacity(
            head(2),
            wal,
            finality_receiver,
            vec![ZkExExConfig::new("indexer", Some(head(1)))],
            8,
        )
        .unwrap();
        let mut notifications = registrations.pop().unwrap().notifications;
        let manager_task = tokio::spawn(manager.run());

        let backfilled = notifications.recv().await.unwrap();
        assert_eq!(backfilled.tip().unwrap().number, 2);
        assert!(
            !backfilled
                .committed_chain()
                .unwrap()
                .tip()
                .unwrap()
                .has_full_execution_data()
        );

        handle.send_async(committed(3)).await.unwrap();
        let live = notifications.recv().await.unwrap();
        assert_eq!(live.tip().unwrap().number, 3);

        drop(handle);
        manager_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn manager_backpressures_when_exex_notification_channel_is_full() {
        let temp = tempfile::tempdir().unwrap();
        let wal = ZkExExWal::open(temp.path()).unwrap();
        let (_finality_sender, finality_receiver) = watch::channel(finality(0));
        let (manager, handle, mut registrations) = ZkExExManager::with_capacity(
            head(0),
            wal,
            finality_receiver,
            vec![ZkExExConfig::new("slow", None)],
            1,
        )
        .unwrap();
        let mut notifications = registrations.pop().unwrap().notifications;
        let manager_task = tokio::spawn(manager.run());

        handle.send_async(committed(1)).await.unwrap();
        handle.send_async(committed(2)).await.unwrap();
        handle.send_async(committed(3)).await.unwrap();
        let blocked =
            tokio::time::timeout(Duration::from_millis(50), handle.send_async(committed(4))).await;
        assert!(blocked.is_err());

        assert_eq!(notifications.recv().await.unwrap().tip().unwrap().number, 1);
        assert_eq!(notifications.recv().await.unwrap().tip().unwrap().number, 2);
        tokio::time::timeout(Duration::from_secs(1), handle.send_async(committed(4)))
            .await
            .unwrap()
            .unwrap();

        drop(handle);
        manager_task.abort();
    }

    #[tokio::test]
    async fn finalizes_wal_only_after_finality_and_finished_height() {
        let temp = tempfile::tempdir().unwrap();
        let wal = ZkExExWal::open(temp.path()).unwrap();
        let (finality_sender, finality_receiver) = watch::channel(finality(0));
        let (manager, handle, mut registrations) = ZkExExManager::with_capacity(
            head(0),
            wal.clone(),
            finality_receiver,
            vec![ZkExExConfig::new("indexer", None)],
            8,
        )
        .unwrap();
        let registration = registrations.pop().unwrap();
        let mut notifications = registration.notifications;
        let manager_task = tokio::spawn(manager.run());

        handle.send_async(committed(1)).await.unwrap();
        handle.send_async(committed(2)).await.unwrap();
        assert_eq!(notifications.recv().await.unwrap().tip().unwrap().number, 1);
        assert_eq!(notifications.recv().await.unwrap().tip().unwrap().number, 2);
        assert_eq!(wal.persisted_len().unwrap(), 2);

        registration
            .events
            .send_finished_height(head(2))
            .await
            .unwrap();
        finality_sender.send_replace(finality(1));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(wal.persisted_len().unwrap(), 1);

        finality_sender.send_replace(finality(2));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(wal.persisted_len().unwrap(), 0);

        drop(handle);
        drop(registration.events);
        manager_task.await.unwrap().unwrap();
    }
}
