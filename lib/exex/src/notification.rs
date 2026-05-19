use alloy::eips::BlockNumHash;
use alloy::primitives::B256;
use std::sync::Arc;
use zksync_os_batch_types::BlockMerkleTreeData;
use zksync_os_interface::types::BlockOutput;
use zksync_os_storage_api::{ReplayRecord, TreeBlock};

/// One executed block as exposed to ZKsync ExEx consumers.
///
/// Live pipeline notifications carry full execution data. Notifications loaded
/// from the durable ExEx WAL are intentionally header-only because `BlockOutput`
/// and tree handles are process-local, non-serializable structures.
#[derive(Clone)]
pub struct ZkExecutedBlock {
    pub num_hash: BlockNumHash,
    pub output: Option<Arc<BlockOutput>>,
    pub record: Option<Arc<ReplayRecord>>,
    pub tree: Option<Arc<BlockMerkleTreeData>>,
}

impl std::fmt::Debug for ZkExecutedBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkExecutedBlock")
            .field("num_hash", &self.num_hash)
            .field("has_output", &self.output.is_some())
            .field("has_record", &self.record.is_some())
            .field("has_tree", &self.tree.is_some())
            .finish()
    }
}

impl ZkExecutedBlock {
    pub fn from_tree_block(block: &TreeBlock) -> Self {
        Self {
            num_hash: BlockNumHash::new(block.output.header.number, block.output.header.hash()),
            output: Some(Arc::new(block.output.clone())),
            record: Some(Arc::new(block.record.clone())),
            tree: Some(Arc::new(block.tree.clone())),
        }
    }

    pub fn header_only(number: u64, hash: B256) -> Self {
        Self {
            num_hash: BlockNumHash::new(number, hash),
            output: None,
            record: None,
            tree: None,
        }
    }

    pub fn number(&self) -> u64 {
        self.num_hash.number
    }

    pub fn hash(&self) -> B256 {
        self.num_hash.hash
    }

    pub fn has_full_execution_data(&self) -> bool {
        self.output.is_some() && self.record.is_some() && self.tree.is_some()
    }
}

/// Ordered canonical-chain segment delivered to an ExEx.
#[derive(Debug, Clone, Default)]
pub struct ZkChainSegment {
    blocks: Vec<ZkExecutedBlock>,
}

impl ZkChainSegment {
    pub fn new(blocks: Vec<ZkExecutedBlock>) -> Self {
        assert!(
            blocks
                .windows(2)
                .all(|window| window[0].number() < window[1].number()),
            "ZkChainSegment blocks must be strictly increasing by block number",
        );
        Self { blocks }
    }

    pub fn empty() -> Self {
        Self { blocks: Vec::new() }
    }

    pub fn single(block: ZkExecutedBlock) -> Self {
        Self {
            blocks: vec![block],
        }
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn first(&self) -> Option<&ZkExecutedBlock> {
        self.blocks.first()
    }

    pub fn tip(&self) -> Option<&ZkExecutedBlock> {
        self.blocks.last()
    }

    pub fn tip_num_hash(&self) -> Option<BlockNumHash> {
        self.tip().map(|block| block.num_hash)
    }

    pub fn range(&self) -> Option<std::ops::RangeInclusive<u64>> {
        Some(self.first()?.number()..=self.tip()?.number())
    }

    pub fn blocks(&self) -> &[ZkExecutedBlock] {
        &self.blocks
    }

    pub fn into_blocks(self) -> Vec<ZkExecutedBlock> {
        self.blocks
    }

    pub fn contains_hash(&self, hash: B256) -> bool {
        self.blocks.iter().any(|block| block.hash() == hash)
    }

    pub fn max_block_number(&self) -> Option<u64> {
        self.tip().map(ZkExecutedBlock::number)
    }

    pub(crate) fn is_at_or_below(&self, head: BlockNumHash) -> bool {
        self.tip()
            .is_some_and(|tip| tip.number() < head.number || tip.num_hash == head)
    }
}

impl IntoIterator for ZkChainSegment {
    type IntoIter = std::vec::IntoIter<ZkExecutedBlock>;
    type Item = ZkExecutedBlock;

    fn into_iter(self) -> Self::IntoIter {
        self.blocks.into_iter()
    }
}

impl<'a> IntoIterator for &'a ZkChainSegment {
    type IntoIter = std::slice::Iter<'a, ZkExecutedBlock>;
    type Item = &'a ZkExecutedBlock;

    fn into_iter(self) -> Self::IntoIter {
        self.blocks.iter()
    }
}

/// Chain-change notification delivered to ZKsync ExExes.
#[derive(Debug, Clone)]
pub enum ZkExExNotification {
    ChainCommitted {
        new: ZkChainSegment,
    },
    ChainReorged {
        old: ZkChainSegment,
        new: ZkChainSegment,
    },
    ChainReverted {
        old: ZkChainSegment,
    },
}

impl ZkExExNotification {
    pub fn committed_chain(&self) -> Option<&ZkChainSegment> {
        match self {
            Self::ChainCommitted { new } | Self::ChainReorged { new, .. } => Some(new),
            Self::ChainReverted { .. } => None,
        }
    }

    pub fn reverted_chain(&self) -> Option<&ZkChainSegment> {
        match self {
            Self::ChainReorged { old, .. } | Self::ChainReverted { old } => Some(old),
            Self::ChainCommitted { .. } => None,
        }
    }

    pub fn tip(&self) -> Option<BlockNumHash> {
        self.committed_chain()
            .or_else(|| self.reverted_chain())
            .and_then(ZkChainSegment::tip_num_hash)
    }

    pub fn max_block_number(&self) -> Option<u64> {
        self.committed_chain()
            .and_then(ZkChainSegment::max_block_number)
            .or_else(|| {
                self.reverted_chain()
                    .and_then(ZkChainSegment::max_block_number)
            })
    }

    pub fn into_inverted(self) -> Self {
        match self {
            Self::ChainCommitted { new } => Self::ChainReverted { old: new },
            Self::ChainReorged { old, new } => Self::ChainReorged { old: new, new: old },
            Self::ChainReverted { old } => Self::ChainCommitted { new: old },
        }
    }

    pub(crate) fn is_at_or_below(&self, head: BlockNumHash) -> bool {
        match self {
            Self::ChainCommitted { new } => new.is_at_or_below(head),
            Self::ChainReorged { old, new } => old.is_at_or_below(head) && new.is_at_or_below(head),
            Self::ChainReverted { old } => old.is_at_or_below(head),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(number: u64) -> ZkExecutedBlock {
        ZkExecutedBlock::header_only(number, B256::with_last_byte(number as u8))
    }

    #[test]
    fn inverts_committed_to_reverted() {
        let notification = ZkExExNotification::ChainCommitted {
            new: ZkChainSegment::single(block(1)),
        };

        let ZkExExNotification::ChainReverted { old } = notification.into_inverted() else {
            panic!("expected ChainReverted");
        };
        assert_eq!(old.tip().unwrap().number(), 1);
    }

    #[test]
    fn inverts_reverted_to_committed() {
        let notification = ZkExExNotification::ChainReverted {
            old: ZkChainSegment::single(block(1)),
        };

        let ZkExExNotification::ChainCommitted { new } = notification.into_inverted() else {
            panic!("expected ChainCommitted");
        };
        assert_eq!(new.tip().unwrap().number(), 1);
    }

    #[test]
    fn inverts_reorg_by_swapping_old_and_new_segments() {
        let notification = ZkExExNotification::ChainReorged {
            old: ZkChainSegment::single(block(2)),
            new: ZkChainSegment::single(block(3)),
        };

        let ZkExExNotification::ChainReorged { old, new } = notification.into_inverted() else {
            panic!("expected ChainReorged");
        };
        assert_eq!(old.tip().unwrap().number(), 3);
        assert_eq!(new.tip().unwrap().number(), 2);
    }

    #[test]
    fn detects_notifications_at_or_below_head() {
        let head = BlockNumHash::new(2, B256::with_last_byte(2));
        let committed = ZkExExNotification::ChainCommitted {
            new: ZkChainSegment::single(block(2)),
        };
        let ahead = ZkExExNotification::ChainCommitted {
            new: ZkChainSegment::single(block(3)),
        };

        assert!(committed.is_at_or_below(head));
        assert!(!ahead.is_at_or_below(head));
    }
}
