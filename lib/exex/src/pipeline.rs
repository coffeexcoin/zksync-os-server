use crate::manager::ZkExExManagerHandle;
use crate::notification::{ZkChainSegment, ZkExExNotification, ZkExecutedBlock};
use async_trait::async_trait;
use tokio::sync::mpsc;
use zksync_os_observability::{ComponentStateReporter, GenericComponentState};
use zksync_os_pipeline::{PeekableReceiver, PipelineComponent, SendAndRecordExt};
use zksync_os_storage_api::TreeBlock;

/// Pipeline pass-through that emits durable ExEx chain-change notifications.
pub struct ExExPipelineNotifier {
    handle: ZkExExManagerHandle,
}

impl ExExPipelineNotifier {
    pub fn new(handle: ZkExExManagerHandle) -> Self {
        Self { handle }
    }

    fn notification_for_block(&self, block: &TreeBlock) -> anyhow::Result<ZkExExNotification> {
        let new = ZkChainSegment::single(ZkExecutedBlock::from_tree_block(block));
        let Some(replaced_hash) = block.replaced_block_hash else {
            return Ok(ZkExExNotification::ChainCommitted { new });
        };

        let Some(old_notification) = self
            .handle
            .wal()
            .committed_notification_by_block_hash(replaced_hash)?
        else {
            tracing::warn!(
                ?replaced_hash,
                block_number = block.output.header.number,
                "replaced block hash was not found in ExEx WAL; emitting ChainCommitted"
            );
            return Ok(ZkExExNotification::ChainCommitted { new });
        };

        if let Some(old) = old_notification.committed_chain().cloned() {
            Ok(ZkExExNotification::ChainReorged { old, new })
        } else {
            tracing::warn!(
                ?replaced_hash,
                block_number = block.output.header.number,
                "replaced block hash resolved to non-committing ExEx notification; emitting ChainCommitted"
            );
            Ok(ZkExExNotification::ChainCommitted { new })
        }
    }
}

#[async_trait]
impl PipelineComponent for ExExPipelineNotifier {
    type Input = TreeBlock;
    type Output = TreeBlock;

    const COMPONENT_ID: zksync_os_pipeline::ComponentId =
        zksync_os_pipeline::ComponentId::ExExPipelineNotifier;

    async fn run(
        self,
        mut input: PeekableReceiver<Self::Input>,
        output: mpsc::Sender<Self::Output>,
        state_reporter: ComponentStateReporter,
    ) -> anyhow::Result<()> {
        loop {
            state_reporter.enter_state(GenericComponentState::Idle);
            let Some(block) = input.recv_and_record_picked(&state_reporter).await else {
                tracing::info!("inbound channel closed");
                return Ok(());
            };
            state_reporter.enter_state(GenericComponentState::Active);
            let notification = self.notification_for_block(&block)?;
            self.handle.send_async(notification).await?;
            output.send_and_record(block, &state_reporter)?;
        }
    }
}
