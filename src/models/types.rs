use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// 支持的区块链
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Chain {
    Solana,
    Ethereum,
    Bitcoin,
    Tron,
    BinanceSmartChain,
    Polygon,
}

impl Chain {
    pub fn as_str(&self) -> &str {
        match self {
            Chain::Solana => "SOL",
            Chain::Ethereum => "ETH",
            Chain::Bitcoin => "BTC",
            Chain::Tron => "TRX",
            Chain::BinanceSmartChain => "BSC",
            Chain::Polygon => "MATIC",
        }
    }
}

/// 钱包层级
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum WalletTier {
    Hot,    // 热钱包: <1% 资产, 实时充提
    Warm,   // 温钱包: 5% 资产, 中转归集
    Cold,   // 冷钱包: 95% 资产, 离线存储
}

/// 用户
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 钱包
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub chain: String,
    pub tier: String,
    pub address: String,
    pub balance: String,
    #[serde(skip_serializing)]
    pub encrypted_private_key: Option<String>,
    pub derivation_path: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 充值记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deposit {
    pub id: Uuid,
    pub user_id: Uuid,
    pub chain: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: String,
    pub token_address: Option<String>,
    pub tx_hash: String,
    pub block_number: Option<i64>,
    pub confirmations: i32,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// 提现记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Withdrawal {
    pub id: Uuid,
    pub user_id: Uuid,
    pub chain: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: String,
    pub fee: String,
    pub token_address: Option<String>,
    pub tx_hash: Option<String>,
    pub status: String,
    pub risk_score: Option<f64>,
    pub risk_decision: Option<String>,
    pub approved_by: Option<Uuid>,
    pub approved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// 风控决策
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskDecision {
    Approve,
    Reject { reason: String },
    ManualReview { score: f64, warnings: Vec<String> },
}

/// 审计日志
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub action: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_data: Option<serde_json::Value>,
    pub response_data: Option<serde_json::Value>,
    pub status: Option<String>,
    pub created_at: DateTime<Utc>,
}
