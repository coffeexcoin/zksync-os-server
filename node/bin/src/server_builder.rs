use crate::config::Config;
use crate::run_with_exexes;
use crate::state_initializer::StateInitializer;
use alloy::eips::BlockNumHash;
use reth_tasks::Runtime;
use std::collections::HashSet;
use zksync_os_exex::{BoxedLaunchZkExEx, LaunchZkExEx, ZkExExContext};
use zksync_os_storage::db::BlockReplayStorage;
use zksync_os_storage::in_memory::Finality;
use zksync_os_storage::lazy::RepositoryManager;
use zksync_os_storage_api::{ReadStateHistory, WriteState};

pub type ServerZkExExContext<State> =
    ZkExExContext<RepositoryManager, BlockReplayStorage, Finality, State>;
pub type ServerZkExEx<State> = InstalledZkExEx<ServerZkExExContext<State>>;

pub struct InstalledZkExEx<Ctx> {
    pub id: String,
    pub head: Option<BlockNumHash>,
    pub launcher: Box<dyn BoxedLaunchZkExEx<Ctx>>,
}

impl<Ctx> InstalledZkExEx<Ctx>
where
    Ctx: Send + 'static,
{
    pub fn new<L>(id: impl Into<String>, head: Option<BlockNumHash>, launcher: L) -> Self
    where
        L: LaunchZkExEx<Ctx>,
    {
        Self {
            id: id.into(),
            head,
            launcher: Box::new(launcher),
        }
    }
}

/// Builder for launching a ZKsync OS server with in-process execution extensions.
///
/// The installation methods intentionally mirror reth's ExEx builder API:
///
/// ```ignore
/// zksync_os_server::builder::<State>(&runtime, config)
///     .install_exex("my-exex", async move |ctx| Ok(my_exex(ctx)))
///     .launch()
///     .await;
/// ```
pub struct ServerBuilder<'a, State> {
    runtime: &'a Runtime,
    config: Config,
    exexes: Vec<ServerZkExEx<State>>,
}

pub fn builder<State>(runtime: &Runtime, config: Config) -> ServerBuilder<'_, State>
where
    State: Send + 'static,
{
    ServerBuilder::new(runtime, config)
}

impl<'a, State> ServerBuilder<'a, State>
where
    State: Send + 'static,
{
    pub fn new(runtime: &'a Runtime, config: Config) -> Self {
        Self {
            runtime,
            config,
            exexes: Vec::new(),
        }
    }

    /// Installs an ExEx with the same call shape as reth's `install_exex`.
    ///
    /// The ExEx starts from the node's current head. Use
    /// [`Self::install_exex_with_head`] when a consumer has a persisted head and
    /// needs WAL backfill from that point.
    pub fn install_exex<L>(self, exex_id: impl Into<String>, exex: L) -> Self
    where
        L: LaunchZkExEx<ServerZkExExContext<State>>,
    {
        self.install_exex_inner(exex_id, None, exex)
    }

    /// Installs an ExEx only if `cond` is true.
    pub fn install_exex_if<L>(self, cond: bool, exex_id: impl Into<String>, exex: L) -> Self
    where
        L: LaunchZkExEx<ServerZkExExContext<State>>,
    {
        if cond {
            self.install_exex(exex_id, exex)
        } else {
            self
        }
    }

    /// Installs an ExEx with a previously persisted consumer head.
    pub fn install_exex_with_head<L>(
        self,
        exex_id: impl Into<String>,
        head: BlockNumHash,
        exex: L,
    ) -> Self
    where
        L: LaunchZkExEx<ServerZkExExContext<State>>,
    {
        self.install_exex_inner(exex_id, Some(head), exex)
    }

    /// Installs an ExEx with a persisted head only if `cond` is true.
    pub fn install_exex_with_head_if<L>(
        self,
        cond: bool,
        exex_id: impl Into<String>,
        head: BlockNumHash,
        exex: L,
    ) -> Self
    where
        L: LaunchZkExEx<ServerZkExExContext<State>>,
    {
        if cond {
            self.install_exex_with_head(exex_id, head, exex)
        } else {
            self
        }
    }

    fn install_exex_inner<L>(
        mut self,
        exex_id: impl Into<String>,
        head: Option<BlockNumHash>,
        exex: L,
    ) -> Self
    where
        L: LaunchZkExEx<ServerZkExExContext<State>>,
    {
        let id = exex_id.into();
        assert_exex_id_available(&self.exexes, &id);
        self.exexes.push(InstalledZkExEx::new(id, head, exex));
        self
    }
}

impl<'a, State> ServerBuilder<'a, State>
where
    State: ReadStateHistory + WriteState + StateInitializer + Clone + Send + 'static,
{
    /// Launches the configured server.
    pub async fn launch(self) {
        run_with_exexes::<State>(self.runtime, self.config, self.exexes).await;
    }
}

pub(crate) fn ensure_unique_exex_ids<Ctx>(exexes: &[InstalledZkExEx<Ctx>]) {
    let mut ids = HashSet::with_capacity(exexes.len());
    for exex in exexes {
        assert!(
            ids.insert(exex.id.as_str()),
            "duplicate ZKsync ExEx id `{}`",
            exex.id
        );
    }
}

fn assert_exex_id_available<Ctx>(exexes: &[InstalledZkExEx<Ctx>], id: &str) {
    assert!(
        !exexes.iter().any(|exex| exex.id == id),
        "duplicate ZKsync ExEx id `{id}`"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BackpressureConfig, BaseTokenPriceUpdaterConfig, BatchVerificationConfig, BatcherConfig,
        ConsensusConfig, ExternalPriceApiClientConfig, FeeConfig,
        ForceTransactionResubmissionConfig, ForcedPriceClientConfig, GasAdjusterConfig,
        GatewaySenderConfig, GeneralConfig, GenesisConfig, InteropFeeUpdaterConfig, L1SenderConfig,
        L1WatcherConfig, MempoolConfig, MempoolTxValidatorConfig, NetworkConfig,
        ObservabilityConfig, ProverApiConfig, ProverInputGeneratorConfig, ProviderConfig,
        ReplayArchiveConfig, RpcConfig, SequencerConfig, StatusServerConfig,
    };
    use alloy::primitives::{Address, B256};
    use alloy::signers::k256::ecdsa::SigningKey;
    use reth_tasks::{RuntimeBuilder, RuntimeConfig, TokioConfig};
    use smart_config::metadata::EtherUnit;
    use std::time::Duration;
    use tokio::runtime::Handle;
    use zksync_os_operator_signer::SignerConfig;
    use zksync_os_types::{NodeRole, PubdataMode};

    fn local_signer(byte: u8) -> SignerConfig {
        SignerConfig::Local(SigningKey::from_slice(&[byte; 32]).unwrap())
    }

    fn test_config() -> Config {
        Config {
            general_config: GeneralConfig {
                node_role: NodeRole::ExternalNode,
                run_priority_tree: true,
                ..Default::default()
            },
            l1_provider_config: ProviderConfig::default(),
            gateway_provider_config: None,
            network_config: NetworkConfig::default(),
            consensus_config: ConsensusConfig::default(),
            genesis_config: GenesisConfig {
                bridgehub_address: Some(Address::ZERO),
                bytecode_supplier_address: Some(Address::with_last_byte(0x01)),
                chain_id: Some(270),
                genesis_input_path: Some("genesis.json".into()),
            },
            rpc_config: RpcConfig::default(),
            mempool_config: MempoolConfig::default(),
            tx_validator_config: MempoolTxValidatorConfig::default(),
            sequencer_config: SequencerConfig::default(),
            l1_sender_config: L1SenderConfig {
                operator_commit_sk: Some(local_signer(0x11)),
                operator_prove_sk: Some(local_signer(0x22)),
                operator_execute_sk: Some(local_signer(0x33)),
                max_fee_per_gas: 200 * EtherUnit::Gwei,
                max_priority_fee_per_gas: 1 * EtherUnit::Gwei,
                max_fee_per_blob_gas: 2 * EtherUnit::Gwei,
                force_transaction_resubmission: ForceTransactionResubmissionConfig::default(),
                command_limit: 16,
                poll_interval: Duration::from_millis(100),
                transaction_timeout: Duration::from_secs(600),
                fusaka_upgrade_timestamp: u64::MAX,
                enabled: true,
                pubdata_mode: Some(PubdataMode::Blobs),
                max_batch_diff_to_upstream: None,
            },
            gateway_sender_config: GatewaySenderConfig::default(),
            l1_watcher_config: L1WatcherConfig::default(),
            batcher_config: BatcherConfig::default(),
            prover_input_generator_config: ProverInputGeneratorConfig::default(),
            prover_api_config: ProverApiConfig::default(),
            status_server_config: StatusServerConfig::default(),
            observability_config: ObservabilityConfig::default(),
            gas_adjuster_config: GasAdjusterConfig::default(),
            batch_verification_config: BatchVerificationConfig::default(),
            replay_archive_config: ReplayArchiveConfig::default(),
            base_token_price_updater_config: BaseTokenPriceUpdaterConfig::default(),
            interop_fee_updater_config: InteropFeeUpdaterConfig::default(),
            external_price_api_client_config: Some(ExternalPriceApiClientConfig::Forced {
                forced: ForcedPriceClientConfig::default(),
            }),
            fee_config: FeeConfig::default(),
            backpressure_config: BackpressureConfig::default(),
        }
    }

    fn runtime() -> Runtime {
        RuntimeBuilder::new(
            RuntimeConfig::default().with_tokio(TokioConfig::existing_handle(Handle::current())),
        )
        .build()
        .unwrap()
    }

    #[tokio::test]
    async fn install_exex_matches_reth_call_shape() {
        let runtime = runtime();
        let builder = builder::<()>(&runtime, test_config())
            .install_exex("indexer", async |_ctx: ServerZkExExContext<()>| {
                Ok(async { Ok(()) })
            });

        assert_eq!(builder.exexes.len(), 1);
        assert_eq!(builder.exexes[0].id, "indexer");
        assert_eq!(builder.exexes[0].head, None);
    }

    #[tokio::test]
    async fn install_exex_if_skips_when_disabled() {
        let runtime = runtime();
        let builder = builder::<()>(&runtime, test_config()).install_exex_if(
            false,
            "disabled",
            async |_ctx: ServerZkExExContext<()>| Ok(async { Ok(()) }),
        );

        assert!(builder.exexes.is_empty());
    }

    #[tokio::test]
    async fn install_exex_with_head_preserves_resume_point() {
        let runtime = runtime();
        let head = BlockNumHash::new(7, B256::with_last_byte(7));
        let builder = builder::<()>(&runtime, test_config()).install_exex_with_head(
            "indexer",
            head,
            async |_ctx: ServerZkExExContext<()>| Ok(async { Ok(()) }),
        );

        assert_eq!(builder.exexes.len(), 1);
        assert_eq!(builder.exexes[0].id, "indexer");
        assert_eq!(builder.exexes[0].head, Some(head));
    }

    #[tokio::test]
    #[should_panic(expected = "duplicate ZKsync ExEx id `indexer`")]
    async fn install_exex_rejects_duplicate_ids() {
        let runtime = runtime();
        let _builder = builder::<()>(&runtime, test_config())
            .install_exex("indexer", async |_ctx: ServerZkExExContext<()>| {
                Ok(async { Ok(()) })
            })
            .install_exex("indexer", async |_ctx: ServerZkExExContext<()>| {
                Ok(async { Ok(()) })
            });
    }

    #[test]
    #[should_panic(expected = "duplicate ZKsync ExEx id `indexer`")]
    fn direct_exex_vectors_reject_duplicate_ids() {
        let exexes = vec![
            InstalledZkExEx::new("indexer", None, async |_ctx: ServerZkExExContext<()>| {
                Ok(async { Ok(()) })
            }),
            InstalledZkExEx::new("indexer", None, async |_ctx: ServerZkExExContext<()>| {
                Ok(async { Ok(()) })
            }),
        ];

        ensure_unique_exex_ids(&exexes);
    }
}
