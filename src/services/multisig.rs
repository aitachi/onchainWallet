// 多签钱包服务
use sqlx::PgPool;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::models::types::{Chain, WalletError};
use crate::services::blockchain::AdapterRegistry;

/// 多签钱包配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigWallet {
    pub id: Uuid,
    pub address: String,
    pub chain: String,
    pub owners: Vec<String>,
    pub threshold: i32,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// 多签提案
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigProposal {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub proposer: String,
    pub to_address: String,
    pub amount: String,
    pub token_address: Option<String>,
    pub data: Option<Vec<u8>>,
    pub approvals: Vec<String>,
    pub rejections: Vec<String>,
    pub status: String,
    pub tx_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub executed_at: Option<DateTime<Utc>>,
}

/// 多签钱包服务
pub struct MultisigService {
    db: PgPool,
    adapters: Arc<AdapterRegistry>,
}

impl MultisigService {
    pub fn new(db: PgPool, adapters: Arc<AdapterRegistry>) -> Self {
        Self { db, adapters }
    }

    /// 创建多签钱包
    pub async fn create_multisig_wallet(
        &self,
        chain: Chain,
        owners: Vec<String>,
        threshold: u32,
        name: String,
    ) -> Result<MultisigWallet, WalletError> {
        if owners.len() < 2 {
            return Err(WalletError::Validation("至少需要2个所有者".to_string()));
        }

        if threshold < 1 || threshold as usize > owners.len() {
            return Err(WalletError::Validation("阈值必须在1和所有者数量之间".to_string()));
        }

        // 实际实现中应该在链上部署多签合约
        // Ethereum: Gnosis Safe
        // Solana: Squads Protocol

        let id = Uuid::new_v4();
        let address = format!("multisig_{}", id); // 模拟地址

        let wallet = sqlx::query_as!(
            MultisigWallet,
            r#"
            INSERT INTO multisig_wallets (id, address, chain, owners, threshold, name)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, address, chain, owners as "owners!", threshold, name, created_at
            "#,
            id,
            address,
            chain.to_string(),
            &owners,
            threshold as i32,
            name
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(wallet)
    }

    /// 创建提案
    pub async fn create_proposal(
        &self,
        wallet_id: Uuid,
        proposer: String,
        to_address: String,
        amount: u64,
        token_address: Option<String>,
        data: Option<Vec<u8>>,
    ) -> Result<MultisigProposal, WalletError> {
        // 验证提议者是多签钱包的所有者
        let wallet = self.get_wallet(wallet_id).await?;
        if !wallet.owners.contains(&proposer) {
            return Err(WalletError::Unauthorized);
        }

        let id = Uuid::new_v4();

        let proposal = sqlx::query_as!(
            MultisigProposal,
            r#"
            INSERT INTO multisig_proposals (id, wallet_id, proposer, to_address, amount, token_address, data, approvals, rejections, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, ARRAY[$3], ARRAY[]::text[], 'pending')
            RETURNING
                id,
                wallet_id,
                proposer,
                to_address,
                amount,
                token_address,
                data,
                approvals as "approvals!",
                rejections as "rejections!",
                status,
                tx_hash,
                created_at,
                executed_at
            "#,
            id,
            wallet_id,
            proposer,
            to_address,
            amount.to_string(),
            token_address,
            data
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(proposal)
    }

    /// 批准提案
    pub async fn approve_proposal(
        &self,
        proposal_id: Uuid,
        approver: String,
    ) -> Result<MultisigProposal, WalletError> {
        let proposal = self.get_proposal(proposal_id).await?;
        let wallet = self.get_wallet(proposal.wallet_id).await?;

        // 验证批准者
        if !wallet.owners.contains(&approver) {
            return Err(WalletError::Unauthorized);
        }

        // 添加批准
        sqlx::query!(
            r#"
            UPDATE multisig_proposals
            SET approvals = array_append(approvals, $1),
                rejections = array_remove(rejections, $1)
            WHERE id = $2
            "#,
            approver,
            proposal_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        let updated_proposal = self.get_proposal(proposal_id).await?;

        // 检查是否达到阈值
        if updated_proposal.approvals.len() as i32 >= wallet.threshold {
            self.execute_proposal(proposal_id).await?;
        }

        self.get_proposal(proposal_id).await
    }

    /// 拒绝提案
    pub async fn reject_proposal(
        &self,
        proposal_id: Uuid,
        rejecter: String,
    ) -> Result<MultisigProposal, WalletError> {
        let proposal = self.get_proposal(proposal_id).await?;
        let wallet = self.get_wallet(proposal.wallet_id).await?;

        if !wallet.owners.contains(&rejecter) {
            return Err(WalletError::Unauthorized);
        }

        sqlx::query!(
            r#"
            UPDATE multisig_proposals
            SET rejections = array_append(rejections, $1),
                approvals = array_remove(approvals, $1)
            WHERE id = $2
            "#,
            rejecter,
            proposal_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        self.get_proposal(proposal_id).await
    }

    /// 执行提案
    async fn execute_proposal(&self, proposal_id: Uuid) -> Result<String, WalletError> {
        // 实际实现应该在链上执行多签交易
        let tx_hash = format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16]));

        sqlx::query!(
            r#"
            UPDATE multisig_proposals
            SET status = 'executed', tx_hash = $1, executed_at = NOW()
            WHERE id = $2
            "#,
            tx_hash.clone(),
            proposal_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(tx_hash)
    }

    /// 获取多签钱包
    pub async fn get_wallet(&self, wallet_id: Uuid) -> Result<MultisigWallet, WalletError> {
        let wallet = sqlx::query_as!(
            MultisigWallet,
            r#"
            SELECT id, address, chain, owners as "owners!", threshold, name, created_at
            FROM multisig_wallets
            WHERE id = $1
            "#,
            wallet_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(wallet)
    }

    /// 获取提案
    pub async fn get_proposal(&self, proposal_id: Uuid) -> Result<MultisigProposal, WalletError> {
        let proposal = sqlx::query_as!(
            MultisigProposal,
            r#"
            SELECT
                id,
                wallet_id,
                proposer,
                to_address,
                amount,
                token_address,
                data,
                approvals as "approvals!",
                rejections as "rejections!",
                status,
                tx_hash,
                created_at,
                executed_at
            FROM multisig_proposals
            WHERE id = $1
            "#,
            proposal_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(proposal)
    }

    /// 获取钱包的所有提案
    pub async fn get_wallet_proposals(
        &self,
        wallet_id: Uuid,
        status: Option<String>,
    ) -> Result<Vec<MultisigProposal>, WalletError> {
        let proposals = if let Some(status) = status {
            sqlx::query_as!(
                MultisigProposal,
                r#"
                SELECT
                    id,
                    wallet_id,
                    proposer,
                    to_address,
                    amount,
                    token_address,
                    data,
                    approvals as "approvals!",
                    rejections as "rejections!",
                    status,
                    tx_hash,
                    created_at,
                    executed_at
                FROM multisig_proposals
                WHERE wallet_id = $1 AND status = $2
                ORDER BY created_at DESC
                "#,
                wallet_id,
                status
            )
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as!(
                MultisigProposal,
                r#"
                SELECT
                    id,
                    wallet_id,
                    proposer,
                    to_address,
                    amount,
                    token_address,
                    data,
                    approvals as "approvals!",
                    rejections as "rejections!",
                    status,
                    tx_hash,
                    created_at,
                    executed_at
                FROM multisig_proposals
                WHERE wallet_id = $1
                ORDER BY created_at DESC
                "#,
                wallet_id
            )
            .fetch_all(&self.db)
            .await
        };

        proposals.map_err(|e| WalletError::Database(e.to_string()))
    }

    /// 获取用户参与的多签钱包
    pub async fn get_user_wallets(&self, owner_address: &str) -> Result<Vec<MultisigWallet>, WalletError> {
        let wallets = sqlx::query_as!(
            MultisigWallet,
            r#"
            SELECT id, address, chain, owners as "owners!", threshold, name, created_at
            FROM multisig_wallets
            WHERE $1 = ANY(owners)
            ORDER BY created_at DESC
            "#,
            owner_address
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(wallets)
    }
}
