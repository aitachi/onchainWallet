use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Blockchain error: {0}")]
    Blockchain(String),

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Wallet not found")]
    WalletNotFound,

    #[error("User not found")]
    UserNotFound,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Risk control rejected: {0}")]
    RiskRejected(String),

    #[error("Blacklisted address: {0}")]
    BlacklistedAddress(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, WalletError>;
