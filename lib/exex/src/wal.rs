use crate::notification::{ZkChainSegment, ZkExExNotification, ZkExecutedBlock};
use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum ZkExExWalError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Encode(#[from] bincode::error::EncodeError),
    #[error(transparent)]
    Decode(#[from] bincode::error::DecodeError),
    #[error("poisoned ExEx WAL lock")]
    Poisoned,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct WalBlock {
    number: u64,
    hash: B256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum WalNotification {
    Committed {
        new: Vec<WalBlock>,
    },
    Reorged {
        old: Vec<WalBlock>,
        new: Vec<WalBlock>,
    },
    Reverted {
        old: Vec<WalBlock>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalRecord {
    id: u64,
    notification: WalNotification,
}

#[derive(Clone)]
pub struct ZkExExWal {
    inner: Arc<Mutex<WalInner>>,
}

struct WalInner {
    path: PathBuf,
    next_id: u64,
    live_committed_by_hash: HashMap<B256, ZkExExNotification>,
}

impl ZkExExWal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ZkExExWalError> {
        let path = path.as_ref().to_path_buf();
        fs::create_dir_all(&path)?;
        let next_id = read_records(&path)?
            .into_iter()
            .map(|record| record.id)
            .max()
            .map_or(0, |id| id + 1);

        Ok(Self {
            inner: Arc::new(Mutex::new(WalInner {
                path,
                next_id,
                live_committed_by_hash: HashMap::new(),
            })),
        })
    }

    pub fn commit(&self, notification: &ZkExExNotification) -> Result<(), ZkExExWalError> {
        let wal_notification = WalNotification::from_notification(notification);
        let mut inner = self.inner.lock().map_err(|_| ZkExExWalError::Poisoned)?;
        let id = inner.next_id;
        inner.next_id += 1;
        let record = WalRecord {
            id,
            notification: wal_notification,
        };
        let bytes = bincode::serde::encode_to_vec(&record, bincode::config::standard())?;
        let final_path = inner.path.join(record_filename(id));
        let tmp_path = inner.path.join(format!("{}.tmp", record_filename(id)));
        fs::write(&tmp_path, bytes)?;
        fs::rename(tmp_path, final_path)?;
        index_live_notification(&mut inner.live_committed_by_hash, notification);
        Ok(())
    }

    pub fn notifications_after(
        &self,
        head_number: u64,
    ) -> Result<Vec<ZkExExNotification>, ZkExExWalError> {
        let inner = self.inner.lock().map_err(|_| ZkExExWalError::Poisoned)?;
        let notifications = read_records(&inner.path)?
            .into_iter()
            .map(|record| record.notification)
            .filter(|notification| {
                notification
                    .max_block_number()
                    .is_some_and(|n| n > head_number)
            })
            .map(WalNotification::into_notification)
            .collect();
        Ok(notifications)
    }

    pub fn committed_notification_by_block_hash(
        &self,
        hash: B256,
    ) -> Result<Option<ZkExExNotification>, ZkExExWalError> {
        let inner = self.inner.lock().map_err(|_| ZkExExWalError::Poisoned)?;
        if let Some(notification) = inner.live_committed_by_hash.get(&hash) {
            return Ok(Some(notification.clone()));
        }

        let notification = read_records(&inner.path)?
            .into_iter()
            .rev()
            .map(|record| record.notification)
            .find(|notification| notification.committed_hashes().any(|h| h == hash))
            .map(WalNotification::into_notification);
        Ok(notification)
    }

    pub fn finalize_up_to(&self, block_number: u64) -> Result<(), ZkExExWalError> {
        let mut inner = self.inner.lock().map_err(|_| ZkExExWalError::Poisoned)?;
        for record in read_records(&inner.path)? {
            if record
                .notification
                .max_block_number()
                .is_some_and(|number| number <= block_number)
            {
                let path = inner.path.join(record_filename(record.id));
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }
        inner.live_committed_by_hash.retain(|_, notification| {
            notification
                .max_block_number()
                .is_some_and(|number| number > block_number)
        });
        Ok(())
    }

    pub fn persisted_len(&self) -> Result<usize, ZkExExWalError> {
        let inner = self.inner.lock().map_err(|_| ZkExExWalError::Poisoned)?;
        Ok(read_records(&inner.path)?.len())
    }
}

impl WalNotification {
    fn from_notification(notification: &ZkExExNotification) -> Self {
        match notification {
            ZkExExNotification::ChainCommitted { new } => Self::Committed {
                new: WalBlock::from_segment(new),
            },
            ZkExExNotification::ChainReorged { old, new } => Self::Reorged {
                old: WalBlock::from_segment(old),
                new: WalBlock::from_segment(new),
            },
            ZkExExNotification::ChainReverted { old } => Self::Reverted {
                old: WalBlock::from_segment(old),
            },
        }
    }

    fn into_notification(self) -> ZkExExNotification {
        match self {
            Self::Committed { new } => ZkExExNotification::ChainCommitted {
                new: WalBlock::into_segment(new),
            },
            Self::Reorged { old, new } => ZkExExNotification::ChainReorged {
                old: WalBlock::into_segment(old),
                new: WalBlock::into_segment(new),
            },
            Self::Reverted { old } => ZkExExNotification::ChainReverted {
                old: WalBlock::into_segment(old),
            },
        }
    }

    fn max_block_number(&self) -> Option<u64> {
        match self {
            Self::Committed { new } => new.iter().map(|block| block.number).max(),
            Self::Reorged { old, new } => old.iter().chain(new).map(|block| block.number).max(),
            Self::Reverted { old } => old.iter().map(|block| block.number).max(),
        }
    }

    fn committed_hashes(&self) -> impl Iterator<Item = B256> + '_ {
        match self {
            Self::Committed { new } | Self::Reorged { new, .. } => {
                EitherBlocks::Committed(new.iter())
            }
            Self::Reverted { .. } => EitherBlocks::Empty,
        }
    }
}

enum EitherBlocks<'a> {
    Committed(std::slice::Iter<'a, WalBlock>),
    Empty,
}

impl Iterator for EitherBlocks<'_> {
    type Item = B256;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Committed(blocks) => blocks.next().map(|block| block.hash),
            Self::Empty => None,
        }
    }
}

impl WalBlock {
    fn from_segment(segment: &ZkChainSegment) -> Vec<Self> {
        segment
            .blocks()
            .iter()
            .map(|block| Self {
                number: block.number(),
                hash: block.hash(),
            })
            .collect()
    }

    fn into_segment(blocks: Vec<Self>) -> ZkChainSegment {
        ZkChainSegment::new(
            blocks
                .into_iter()
                .map(|block| ZkExecutedBlock::header_only(block.number, block.hash))
                .collect(),
        )
    }
}

fn read_records(path: &Path) -> Result<Vec<WalRecord>, ZkExExWalError> {
    let mut entries = fs::read_dir(path)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "bin")
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());

    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        let bytes = fs::read(entry.path())?;
        let (record, _): (WalRecord, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?;
        records.push(record);
    }
    Ok(records)
}

fn record_filename(id: u64) -> String {
    format!("{id:020}.bin")
}

fn index_live_notification(
    live_committed_by_hash: &mut HashMap<B256, ZkExExNotification>,
    notification: &ZkExExNotification,
) {
    if let Some(segment) = notification.committed_chain() {
        for block in segment {
            live_committed_by_hash.insert(block.hash(), notification.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(number: u64) -> ZkExecutedBlock {
        ZkExecutedBlock::header_only(number, B256::with_last_byte(number as u8))
    }

    fn committed(number: u64) -> ZkExExNotification {
        ZkExExNotification::ChainCommitted {
            new: ZkChainSegment::single(block(number)),
        }
    }

    #[test]
    fn persists_and_replays_header_only_notifications_after_head() {
        let temp = tempfile::tempdir().unwrap();
        let wal = ZkExExWal::open(temp.path()).unwrap();
        wal.commit(&committed(1)).unwrap();
        wal.commit(&committed(2)).unwrap();

        let reopened = ZkExExWal::open(temp.path()).unwrap();
        let notifications = reopened.notifications_after(1).unwrap();

        assert_eq!(notifications.len(), 1);
        let ZkExExNotification::ChainCommitted { new } = &notifications[0] else {
            panic!("expected ChainCommitted");
        };
        let replayed = new.tip().unwrap();
        assert_eq!(replayed.number(), 2);
        assert!(!replayed.has_full_execution_data());
    }

    #[test]
    fn looks_up_live_committed_notifications_by_hash() {
        let temp = tempfile::tempdir().unwrap();
        let wal = ZkExExWal::open(temp.path()).unwrap();
        let notification = committed(3);
        wal.commit(&notification).unwrap();

        let found = wal
            .committed_notification_by_block_hash(B256::with_last_byte(3))
            .unwrap()
            .unwrap();

        assert!(matches!(found, ZkExExNotification::ChainCommitted { .. }));
        assert_eq!(found.tip().unwrap().number, 3);
    }

    #[test]
    fn looks_up_persisted_committed_notifications_by_hash() {
        let temp = tempfile::tempdir().unwrap();
        ZkExExWal::open(temp.path())
            .unwrap()
            .commit(&committed(4))
            .unwrap();

        let reopened = ZkExExWal::open(temp.path()).unwrap();
        let found = reopened
            .committed_notification_by_block_hash(B256::with_last_byte(4))
            .unwrap()
            .unwrap();

        assert_eq!(found.tip().unwrap().number, 4);
        let ZkExExNotification::ChainCommitted { new } = found else {
            panic!("expected ChainCommitted");
        };
        assert!(!new.tip().unwrap().has_full_execution_data());
    }

    #[test]
    fn finalizes_persisted_records_and_live_cache() {
        let temp = tempfile::tempdir().unwrap();
        let wal = ZkExExWal::open(temp.path()).unwrap();
        wal.commit(&committed(1)).unwrap();
        wal.commit(&committed(2)).unwrap();

        wal.finalize_up_to(1).unwrap();

        assert_eq!(wal.persisted_len().unwrap(), 1);
        assert!(
            wal.committed_notification_by_block_hash(B256::with_last_byte(1))
                .unwrap()
                .is_none()
        );
        assert!(
            wal.committed_notification_by_block_hash(B256::with_last_byte(2))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn persists_reorg_segments() {
        let temp = tempfile::tempdir().unwrap();
        let wal = ZkExExWal::open(temp.path()).unwrap();
        let notification = ZkExExNotification::ChainReorged {
            old: ZkChainSegment::single(block(2)),
            new: ZkChainSegment::single(block(3)),
        };
        wal.commit(&notification).unwrap();

        let notifications = ZkExExWal::open(temp.path())
            .unwrap()
            .notifications_after(0)
            .unwrap();
        let ZkExExNotification::ChainReorged { old, new } = &notifications[0] else {
            panic!("expected ChainReorged");
        };
        assert_eq!(old.tip().unwrap().number(), 2);
        assert_eq!(new.tip().unwrap().number(), 3);
    }
}
