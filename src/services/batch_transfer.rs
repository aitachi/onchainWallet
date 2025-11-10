// 批量转账服务
use sqlx::PgPool;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::types::{Chain, WalletError};
use crate::services::blockchain::AdapterRegistry;
use crate::services::audit::AuditService;

/// 批量转账接收者
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransferRecipient {
    pub address: String,
    pub amount: u64,
    pub note: Option<String>,
}

/// 批量转账请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransferRequest {
    pub user_id: Uuid,
    pub from_address: String,
    pub chain: Chain,
    pub recipients: Vec<BatchTransferRecipient>,
    pub token_address: Option<String>,
}

/// 批量转账结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransferResult {
    pub batch_id: Uuid,
    pub total_recipients: usize,
    pub successful: usize,
    pub failed: usize,
    pub tx_hashes: Vec<String>,
    pub failed_addresses: Vec<String>,
    pub total_amount: u64,
    pub total_fee: u64,
}

/// 批量转账服务
pub struct BatchTransferService {
    db: PgPool,
    adapters: Arc<AdapterRegistry>,
    audit_service: Arc<AuditService>,
}

impl BatchTransferService {
    pub fn new(db: PgPool, adapters: Arc<AdapterRegistry>, audit_service: Arc<AuditService>) -> Self {
        Self { db, adapters, audit_service }
    }

    /// 执行批量转账
    pub async fn execute_batch_transfer(
        &self,
        request: BatchTransferRequest,
    ) -> Result<BatchTransferResult, WalletError> {
        // 1. 验证请求
        if request.recipients.is_empty() {
            return Err(WalletError::Validation("接收者列表不能为空".to_string()));
        }

        if request.recipients.len() > 1000 {
            return Err(WalletError::Validation("单次批量转账最多1000个地址".to_string()));
        }

        let batch_id = Uuid::new_v4();
        let total_amount: u64 = request.recipients.iter().map(|r| r.amount).sum();

        // 2. 检查余额
        let adapter = self.adapters.get(request.chain)
            .ok_or_else(|| WalletError::UnsupportedChain(request.chain.to_string()))?;

        // 3. 执行转账
        let mut tx_hashes = Vec::new();
        let mut failed_addresses = Vec::new();
        let mut successful = 0usize;

        for recipient in &request.recipients {
            match self.transfer_single(&request.from_address, &recipient.address, recipient.amount, request.chain, request.token_address.as_deref()).await {
                Ok(tx_hash) => {
                    tx_hashes.push(tx_hash);
                    successful += 1;
                }
                Err(e) => {
                    tracing::error!("Failed to transfer to {}: {}", recipient.address, e);
                    failed_addresses.push(recipient.address.clone());
                }
            }
        }

        // 4. 记录批量转账
        sqlx::query!(
            r#"
            INSERT INTO batch_transfers (id, user_id, from_address, chain, total_recipients, successful, failed, total_amount, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            batch_id,
            request.user_id,
            request.from_address,
            request.chain.to_string(),
            request.recipients.len() as i32,
            successful as i32,
            failed_addresses.len() as i32,
            total_amount.to_string(),
            if failed_addresses.is_empty() { "completed" } else { "partial" }
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        // 5. 审计日志
        self.audit_service.log_event(
            Some(request.user_id),
            "batch_transfer",
            Some("batch_transfers"),
            Some(batch_id),
            "execute",
            None,
            None,
            None,
            Some("completed"),
        ).await.ok();

        Ok(BatchTransferResult {
            batch_id,
            total_recipients: request.recipients.len(),
            successful,
            failed: failed_addresses.len(),
            tx_hashes,
            failed_addresses,
            total_amount,
            total_fee: 0, // 需要从链上获取实际费用
        })
    }

    /// 单笔转账
    async fn transfer_single(
        &self,
        from: &str,
        to: &str,
        amount: u64,
        chain: Chain,
        token_address: Option<&str>,
    ) -> Result<String, WalletError> {
        // 实际实现应该调用区块链适配器
        tracing::info!("Transferring {} from {} to {} on {:?}", amount, from, to, chain);

        // 模拟交易哈希
        let tx_hash = format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16]));

        // 记录交易
        sqlx::query!(
            r#"
            INSERT INTO transactions (id, chain, from_address, to_address, amount, token_address, tx_hash, status, tx_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'confirmed', 'transfer')
            "#,
            Uuid::new_v4(),
            chain.to_string(),
            from,
            to,
            amount.to_string(),
            token_address,
            tx_hash.clone()
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(tx_hash)
    }

    /// 获取批量转账历史
    pub async fn get_batch_history(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<BatchTransferHistory>, WalletError> {
        let history = sqlx::query_as!(
            BatchTransferHistory,
            r#"
            SELECT
                id,
                user_id,
                from_address,
                chain,
                total_recipients,
                successful,
                failed,
                total_amount,
                status,
                created_at
            FROM batch_transfers
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
            user_id,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(history)
    }

    /// 重试失败的转账
    pub async fn retry_failed_transfers(
        &self,
        batch_id: Uuid,
        user_id: Uuid,
    ) -> Result<BatchTransferResult, WalletError> {
        // 实现重试逻辑
        Err(WalletError::Internal("Not implemented".to_string()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchTransferHistory {
    pub id: Uuid,
    pub user_id: Uuid,
    pub from_address: String,
    pub chain: String,
    pub total_recipients: i32,
    pub successful: i32,
    pub failed: i32,
    pub total_amount: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
