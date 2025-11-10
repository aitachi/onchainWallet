use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use crate::models::{Result, WalletError};

/// 统一的区块链地址
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    pub address: String,
    pub public_key: Option<String>,
}

/// 余额信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub total: u64,
}

/// 未签名交易
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTx {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub nonce: Option<u64>,
    pub data: Vec<u8>,
}

/// 已签名交易
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTx {
    pub signature: Vec<u8>,
    pub raw_tx: Vec<u8>,
}

/// 交易哈希
pub type TxHash = String;

/// 交易信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub block_number: Option<u64>,
    pub confirmations: u32,
    pub status: TxStatus,
    pub timestamp: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxStatus {
    Pending,
    Confirmed,
    Failed,
}

/// 区块链适配器统一接口
#[async_trait]
pub trait BlockchainAdapter: Send + Sync {
    /// 生成地址
    async fn generate_address(&self, derivation_path: &str) -> Result<Address>;

    /// 查询余额
    async fn get_balance(&self, address: &str) -> Result<Balance>;

    /// 查询代币余额
    async fn get_token_balance(&self, address: &str, token: &str) -> Result<Balance>;

    /// 构建转账交易
    async fn build_transfer(
        &self,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<UnsignedTx>;

    /// 签名交易
    async fn sign_transaction(
        &self,
        tx: &UnsignedTx,
        private_key: &[u8],
    ) -> Result<SignedTx>;

    /// 广播交易
    async fn broadcast(&self, tx: &SignedTx) -> Result<TxHash>;

    /// 查询交易
    async fn get_transaction(&self, tx_hash: &str) -> Result<Transaction>;

    /// 获取确认数
    async fn get_confirmations(&self, tx_hash: &str) -> Result<u32>;

    /// 获取最新区块高度
    async fn get_block_height(&self) -> Result<u64>;

    /// 估算Gas费用
    async fn estimate_fee(&self, from: &str, to: &str, amount: u64) -> Result<u64>;

    /// 验证地址格式
    fn validate_address(&self, address: &str) -> Result<bool>;
}
