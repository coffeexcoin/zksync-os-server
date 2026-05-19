//! Native execution extensions for ZKsync OS nodes.
//!
//! This crate intentionally mirrors the operational shape of reth ExExes while
//! using ZKsync-native execution data (`ReplayRecord`, `BlockOutput`, and tree
//! snapshots) instead of reth provider primitives.

mod context;
mod launch;
mod manager;
mod notification;
mod pipeline;
mod wal;

pub use context::{ZkExExContext, ZkExExEventSender, ZkExExNotifications};
pub use launch::{BoxZkExEx, BoxedLaunchZkExEx, LaunchZkExEx};
pub use manager::{
    DEFAULT_EXEX_MANAGER_CAPACITY, FinishedZkExExHeight, ZkExExConfig, ZkExExManager,
    ZkExExManagerHandle, ZkExExRegistration,
};
pub use notification::{ZkChainSegment, ZkExExNotification, ZkExecutedBlock};
pub use pipeline::ExExPipelineNotifier;
pub use wal::{ZkExExWal, ZkExExWalError};
