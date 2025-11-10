use async_trait::async_trait;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer as SolanaSigner},
    transaction::Transaction as SolanaTransaction,
    system_instruction,
    commitment_config::CommitmentConfig,
};
use solana_client::rpc_client::RpcClient;
use std::str::FromStr;
use crate::models::{Result, WalletError};
use super::adapter::*;

pub struct SolanaAdapter {
    client: RpcClient,
    commitment: CommitmentConfig,
}

impl SolanaAdapter {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            client: RpcClient::new_with_commitment(
                rpc_url.to_string(),
                CommitmentConfig::confirmed(),
            ),
            commitment: CommitmentConfig::confirmed(),
        }
    }

    fn parse_pubkey(&self, address: &str) -> Result<Pubkey> {
        Pubkey::from_str(address)
            .map_err(|e| WalletError::InvalidAddress(format!("Invalid Solana address: {}", e)))
    }
}

#[async_trait]
impl BlockchainAdapter for SolanaAdapter {
    async fn generate_address(&self, _derivation_path: &str) -> Result<Address> {
        // 生成新的密钥对
        let keypair = Keypair::new();
        let pubkey = keypair.pubkey();

        Ok(Address {
            address: pubkey.to_string(),
            public_key: Some(hex::encode(pubkey.to_bytes())),
        })
    }

    async fn get_balance(&self, address: &str) -> Result<Balance> {
        let pubkey = self.parse_pubkey(address)?;

        let balance = self.client
            .get_balance_with_commitment(&pubkey, self.commitment)
            .map_err(|e| WalletError::Blockchain(format!("Failed to get balance: {}", e)))?
            .value;

        Ok(Balance {
            confirmed: balance,
            unconfirmed: 0,
            total: balance,
        })
    }

    async fn get_token_balance(&self, address: &str, _token: &str) -> Result<Balance> {
        // SPL Token 余额查询
        let pubkey = self.parse_pubkey(address)?;

        // TODO: 实现SPL Token余额查询
        let balance = self.client
            .get_balance(&pubkey)
            .map_err(|e| WalletError::Blockchain(format!("Failed to get token balance: {}", e)))?;

        Ok(Balance {
            confirmed: balance,
            unconfirmed: 0,
            total: balance,
        })
    }

    async fn build_transfer(
        &self,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<UnsignedTx> {
        let from_pubkey = self.parse_pubkey(from)?;
        let to_pubkey = self.parse_pubkey(to)?;

        // 获取最新的blockhash
        let recent_blockhash = self.client
            .get_latest_blockhash()
            .map_err(|e| WalletError::Blockchain(format!("Failed to get blockhash: {}", e)))?;

        // 创建转账指令
        let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, amount);

        // 构建交易
        let transaction = SolanaTransaction::new_with_payer(
            &[instruction],
            Some(&from_pubkey),
        );

        // 估算费用
        let fee = self.client
            .get_fee_for_message(&transaction.message())
            .map_err(|e| WalletError::Blockchain(format!("Failed to estimate fee: {}", e)))?;

        Ok(UnsignedTx {
            from: from.to_string(),
            to: to.to_string(),
            amount,
            fee,
            nonce: None,
            data: bincode::serialize(&transaction)
                .map_err(|e| WalletError::Internal(format!("Serialization error: {}", e)))?,
        })
    }

    async fn sign_transaction(
        &self,
        tx: &UnsignedTx,
        private_key: &[u8],
    ) -> Result<SignedTx> {
        // 从私钥恢复密钥对
        let keypair = Keypair::from_bytes(private_key)
            .map_err(|e| WalletError::Encryption(format!("Invalid private key: {}", e)))?;

        // 反序列化交易
        let mut transaction: SolanaTransaction = bincode::deserialize(&tx.data)
            .map_err(|e| WalletError::Internal(format!("Deserialization error: {}", e)))?;

        // 获取最新blockhash
        let recent_blockhash = self.client
            .get_latest_blockhash()
            .map_err(|e| WalletError::Blockchain(format!("Failed to get blockhash: {}", e)))?;

        transaction.sign(&[&keypair], recent_blockhash);

        Ok(SignedTx {
            signature: transaction.signatures[0].as_ref().to_vec(),
            raw_tx: bincode::serialize(&transaction)
                .map_err(|e| WalletError::Internal(format!("Serialization error: {}", e)))?,
        })
    }

    async fn broadcast(&self, tx: &SignedTx) -> Result<TxHash> {
        let transaction: SolanaTransaction = bincode::deserialize(&tx.raw_tx)
            .map_err(|e| WalletError::Internal(format!("Deserialization error: {}", e)))?;

        let signature = self.client
            .send_and_confirm_transaction(&transaction)
            .map_err(|e| WalletError::Blockchain(format!("Failed to broadcast: {}", e)))?;

        Ok(signature.to_string())
    }

    async fn get_transaction(&self, tx_hash: &str) -> Result<Transaction> {
        use solana_sdk::signature::Signature;

        let signature = Signature::from_str(tx_hash)
            .map_err(|e| WalletError::InvalidAddress(format!("Invalid signature: {}", e)))?;

        let tx = self.client
            .get_transaction(&signature, solana_transaction_status::UiTransactionEncoding::Json)
            .map_err(|e| WalletError::TransactionNotFound(format!("Transaction not found: {}", e)))?;

        // 解析交易信息
        let meta = tx.transaction.meta.ok_or_else(||
            WalletError::Internal("Transaction meta not found".to_string()))?;

        let block_time = tx.block_time;
        let slot = tx.slot;

        Ok(Transaction {
            hash: tx_hash.to_string(),
            from: String::new(), // 需要从交易中解析
            to: String::new(),
            amount: 0,
            fee: meta.fee,
            block_number: Some(slot),
            confirmations: 1, // TODO: 计算实际确认数
            status: if meta.err.is_none() {
                TxStatus::Confirmed
            } else {
                TxStatus::Failed
            },
            timestamp: block_time,
        })
    }

    async fn get_confirmations(&self, _tx_hash: &str) -> Result<u32> {
        // Solana使用slot而不是传统的确认数
        // 这里返回固定值，实际应该计算当前slot与交易slot的差值
        Ok(32)
    }

    async fn get_block_height(&self) -> Result<u64> {
        self.client
            .get_slot()
            .map_err(|e| WalletError::Blockchain(format!("Failed to get block height: {}", e)))
    }

    async fn estimate_fee(&self, from: &str, to: &str, amount: u64) -> Result<u64> {
        let unsigned_tx = self.build_transfer(from, to, amount).await?;
        Ok(unsigned_tx.fee)
    }

    fn validate_address(&self, address: &str) -> Result<bool> {
        match Pubkey::from_str(address) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
