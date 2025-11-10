pub mod adapter;
pub mod solana;
pub mod ethereum;

use std::sync::Arc;
use std::collections::HashMap;
use crate::models::{Result, WalletError};
use crate::models::types::Chain;
use adapter::BlockchainAdapter;
use solana::SolanaAdapter;
use ethereum::EthereumAdapter;

/// 区块链适配器注册中心
pub struct AdapterRegistry {
    adapters: HashMap<Chain, Arc<dyn BlockchainAdapter>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            adapters: HashMap::new(),
        }
    }

    /// 注册适配器
    pub fn register(&mut self, chain: Chain, adapter: Arc<dyn BlockchainAdapter>) {
        self.adapters.insert(chain, adapter);
    }

    /// 获取适配器
    pub fn get(&self, chain: &Chain) -> Result<&Arc<dyn BlockchainAdapter>> {
        self.adapters
            .get(chain)
            .ok_or_else(|| WalletError::Config(format!("Adapter not found for chain: {:?}", chain)))
    }

    /// 初始化所有适配器
    pub fn init_all(
        solana_rpc: &str,
        ethereum_rpc: &str,
        ethereum_chain_id: u64,
    ) -> Result<Self> {
        let mut registry = Self::new();

        // 注册Solana适配器
        let solana_adapter = Arc::new(SolanaAdapter::new(solana_rpc));
        registry.register(Chain::Solana, solana_adapter);

        // 注册Ethereum适配器
        let ethereum_adapter = Arc::new(EthereumAdapter::new(ethereum_rpc, ethereum_chain_id)?);
        registry.register(Chain::Ethereum, ethereum_adapter);

        Ok(registry)
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}
