use std::sync::Arc;
use sqlx::PgPool;
use uuid::Uuid;
use crate::models::{Result, WalletError, types::{Chain, RiskDecision}};
use crate::services::blockchain::AdapterRegistry;
use crate::services::key_manager::KeyManager;
use crate::services::risk::RiskControlService;
use crate::services::audit::AuditService;

/// 提现请求
#[derive(Debug, Clone)]
pub struct WithdrawalRequest {
    pub user_id: Uuid,
    pub chain: Chain,
    pub to_address: String,
    pub amount: u64,
    pub token_address: Option<String>,
}

/// 提现服务
pub struct WithdrawalService {
    db: PgPool,
    adapters: Arc<AdapterRegistry>,
    key_manager: Arc<KeyManager>,
    risk_service: Arc<RiskControlService>,
    audit_service: Arc<AuditService>,
}

impl WithdrawalService {
    pub fn new(
        db: PgPool,
        adapters: Arc<AdapterRegistry>,
        key_manager: Arc<KeyManager>,
        risk_service: Arc<RiskControlService>,
        audit_service: Arc<AuditService>,
    ) -> Self {
        Self {
            db,
            adapters,
            key_manager,
            risk_service,
            audit_service,
        }
    }

    /// 创建提现请求
    pub async fn create_withdrawal(&self, req: WithdrawalRequest) -> Result<Uuid> {
        // 1. 验证地址格式
        let adapter = self.adapters.get(&req.chain)?;
        if !adapter.validate_address(&req.to_address)? {
            return Err(WalletError::InvalidAddress(req.to_address.clone()));
        }

        // 2. 风控检查
        let risk_result = self.risk_service.check_withdrawal(&req).await?;

        let (status, risk_score, risk_decision) = match risk_result {
            RiskDecision::Approve => ("approved", None, None),
            RiskDecision::Reject { reason } => {
                return Err(WalletError::RiskRejected(reason));
            }
            RiskDecision::ManualReview { score, warnings } => {
                ("pending", Some(score), Some(warnings.join(", ")))
            }
        };

        // 3. 检查用户余额
        let user_balance = self.get_user_balance(req.user_id, req.chain).await?;
        let fee = adapter.estimate_fee("", &req.to_address, req.amount).await?;

        if user_balance < req.amount + fee {
            return Err(WalletError::InsufficientBalance {
                required: req.amount + fee,
                available: user_balance,
            });
        }

        // 4. 创建提现记录
        let withdrawal_id = Uuid::new_v4();

        sqlx::query!(
            r#"
            INSERT INTO withdrawals
            (id, user_id, chain, to_address, amount, fee, status, risk_score, risk_decision, token_address)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            withdrawal_id,
            req.user_id,
            req.chain.as_str(),
            req.to_address,
            req.amount.to_string(),
            fee.to_string(),
            status,
            risk_score,
            risk_decision,
            req.token_address
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        // 5. 记录审计日志
        self.audit_service.log_withdrawal_request(
            req.user_id,
            withdrawal_id,
            &req.to_address,
            req.amount,
        ).await?;

        // 6. 如果自动批准，立即处理
        if status == "approved" {
            tokio::spawn({
                let service = Arc::new(self.clone());
                let id = withdrawal_id;
                async move {
                    if let Err(e) = service.process_withdrawal(id).await {
                        tracing::error!("Failed to process withdrawal {}: {}", id, e);
                    }
                }
            });
        }

        Ok(withdrawal_id)
    }

    /// 处理提现
    pub async fn process_withdrawal(&self, withdrawal_id: Uuid) -> Result<String> {
        // 1. 获取提现信息
        let withdrawal = sqlx::query!(
            r#"
            SELECT user_id, chain, to_address, amount, fee, from_address, token_address
            FROM withdrawals
            WHERE id = $1 AND status = 'approved'
            "#,
            withdrawal_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?
        .ok_or(WalletError::TransactionNotFound(withdrawal_id.to_string()))?;

        // 2. 更新状态为处理中
        sqlx::query!(
            r#"UPDATE withdrawals SET status = 'processing' WHERE id = $1"#,
            withdrawal_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        let chain = self.parse_chain(&withdrawal.chain)?;
        let amount: u64 = withdrawal.amount.parse()
            .map_err(|e| WalletError::Internal(format!("Invalid amount: {}", e)))?;

        // 3. 获取热钱包地址
        let from_address = match withdrawal.from_address {
            Some(addr) => addr,
            None => self.get_hot_wallet_address(chain).await?,
        };

        // 4. 获取私钥
        let encrypted_key = sqlx::query!(
            r#"SELECT encrypted_private_key FROM wallets WHERE address = $1 AND chain = $2"#,
            from_address,
            withdrawal.chain
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?
        .encrypted_private_key
        .ok_or(WalletError::WalletNotFound)?;

        let private_key = self.key_manager.decrypt_private_key(
            &hex::decode(encrypted_key).map_err(|e| WalletError::Encryption(e.to_string()))?
        )?;

        // 5. 构建、签名、广播交易
        let adapter = self.adapters.get(&chain)?;

        let unsigned_tx = adapter.build_transfer(
            &from_address,
            &withdrawal.to_address,
            amount,
        ).await?;

        let signed_tx = adapter.sign_transaction(&unsigned_tx, &private_key).await?;
        let tx_hash = adapter.broadcast(&signed_tx).await?;

        // 6. 更新提现记录
        sqlx::query!(
            r#"
            UPDATE withdrawals
            SET tx_hash = $1, status = 'completed', completed_at = NOW()
            WHERE id = $2
            "#,
            tx_hash,
            withdrawal_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        // 7. 记录交易
        sqlx::query!(
            r#"
            INSERT INTO transactions (chain, tx_hash, from_address, to_address, amount, fee, tx_type, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'withdrawal', 'pending')
            "#,
            withdrawal.chain,
            tx_hash,
            from_address,
            withdrawal.to_address,
            withdrawal.amount,
            withdrawal.fee,
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        // 8. 记录审计日志
        self.audit_service.log_withdrawal_completed(
            withdrawal.user_id.unwrap(),
            withdrawal_id,
            &tx_hash,
        ).await?;

        tracing::info!("Withdrawal {} completed: {}", withdrawal_id, tx_hash);

        Ok(tx_hash)
    }

    /// 批准提现
    pub async fn approve_withdrawal(&self, withdrawal_id: Uuid, approver_id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE withdrawals
            SET status = 'approved', approved_by = $1, approved_at = NOW()
            WHERE id = $2 AND status = 'pending'
            "#,
            approver_id,
            withdrawal_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        // 异步处理
        tokio::spawn({
            let service = Arc::new(self.clone());
            let id = withdrawal_id;
            async move {
                if let Err(e) = service.process_withdrawal(id).await {
                    tracing::error!("Failed to process approved withdrawal {}: {}", id, e);
                }
            }
        });

        Ok(())
    }

    /// 拒绝提现
    pub async fn reject_withdrawal(&self, withdrawal_id: Uuid, reason: String) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE withdrawals
            SET status = 'rejected', risk_decision = $1
            WHERE id = $2 AND status = 'pending'
            "#,
            reason,
            withdrawal_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        Ok(())
    }

    /// 获取用户余额
    async fn get_user_balance(&self, user_id: Uuid, chain: Chain) -> Result<u64> {
        let records = sqlx::query!(
            r#"SELECT balance FROM wallets WHERE user_id = $1 AND chain = $2"#,
            user_id,
            chain.as_str()
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        let total: u64 = records.iter()
            .filter_map(|r| r.balance.parse::<u64>().ok())
            .sum();

        Ok(total)
    }

    /// 获取热钱包地址
    async fn get_hot_wallet_address(&self, chain: Chain) -> Result<String> {
        let record = sqlx::query!(
            r#"SELECT address FROM wallets WHERE chain = $1 AND tier = 'hot' LIMIT 1"#,
            chain.as_str()
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?
        .ok_or(WalletError::WalletNotFound)?;

        Ok(record.address)
    }

    fn parse_chain(&self, chain_str: &str) -> Result<Chain> {
        match chain_str {
            "SOL" => Ok(Chain::Solana),
            "ETH" => Ok(Chain::Ethereum),
            "BTC" => Ok(Chain::Bitcoin),
            "TRX" => Ok(Chain::Tron),
            "BSC" => Ok(Chain::BinanceSmartChain),
            "MATIC" => Ok(Chain::Polygon),
            _ => Err(WalletError::Config(format!("Unknown chain: {}", chain_str))),
        }
    }
}

// 为了tokio::spawn需要实现Clone
impl Clone for WithdrawalService {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            adapters: Arc::clone(&self.adapters),
            key_manager: Arc::clone(&self.key_manager),
            risk_service: Arc::clone(&self.risk_service),
            audit_service: Arc::clone(&self.audit_service),
        }
    }
}
