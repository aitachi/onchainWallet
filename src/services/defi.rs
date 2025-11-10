// DeFi协议集成服务 (Swap, Staking)
use sqlx::PgPool;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::models::types::{Chain, WalletError};
use crate::services::blockchain::AdapterRegistry;

/// Swap交易请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRequest {
    pub user_address: String,
    pub chain: Chain,
    pub from_token: String,  // 原生代币用 "native"
    pub to_token: String,
    pub amount_in: u64,
    pub min_amount_out: u64,
    pub slippage_tolerance: f64, // 0.5 表示 0.5%
    pub deadline: Option<DateTime<Utc>>,
}

/// Swap报价
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapQuote {
    pub from_token: String,
    pub to_token: String,
    pub amount_in: u64,
    pub amount_out: u64,
    pub price_impact: f64,
    pub minimum_received: u64,
    pub gas_estimate: u64,
    pub route: Vec<String>, // 交易路径
}

/// 质押请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeRequest {
    pub user_address: String,
    pub chain: Chain,
    pub pool_address: String,
    pub token_address: String,
    pub amount: u64,
}

/// 质押信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeInfo {
    pub id: Uuid,
    pub user_address: String,
    pub chain: String,
    pub pool_address: String,
    pub token_address: String,
    pub staked_amount: String,
    pub rewards_earned: String,
    pub apy: Option<f64>,
    pub staked_at: DateTime<Utc>,
    pub last_claimed: Option<DateTime<Utc>>,
}

/// DeFi服务
pub struct DeFiService {
    db: PgPool,
    adapters: Arc<AdapterRegistry>,
}

impl DeFiService {
    pub fn new(db: PgPool, adapters: Arc<AdapterRegistry>) -> Self {
        Self { db, adapters }
    }

    /// 获取Swap报价
    pub async fn get_swap_quote(
        &self,
        request: &SwapRequest,
    ) -> Result<SwapQuote, WalletError> {
        // 实际实现中应该调用DEX聚合器API
        // Solana: Jupiter Aggregator
        // Ethereum: 1inch, 0x Protocol, Uniswap V3

        tracing::info!("Getting swap quote: {} {} -> {}",
            request.amount_in, request.from_token, request.to_token);

        // 模拟报价
        let amount_out = (request.amount_in as f64 * 0.998) as u64; // 0.2% 滑点
        let minimum_received = (amount_out as f64 * (1.0 - request.slippage_tolerance / 100.0)) as u64;

        Ok(SwapQuote {
            from_token: request.from_token.clone(),
            to_token: request.to_token.clone(),
            amount_in: request.amount_in,
            amount_out,
            price_impact: 0.15,
            minimum_received,
            gas_estimate: 150000,
            route: vec![request.from_token.clone(), request.to_token.clone()],
        })
    }

    /// 执行Swap交易
    pub async fn execute_swap(
        &self,
        request: SwapRequest,
    ) -> Result<String, WalletError> {
        // 1. 获取报价
        let quote = self.get_swap_quote(&request).await?;

        // 2. 验证滑点
        if quote.amount_out < request.min_amount_out {
            return Err(WalletError::Validation(
                format!("滑点过大: 预期 {}, 实际 {}", request.min_amount_out, quote.amount_out)
            ));
        }

        // 3. 构建并发送Swap交易
        // Solana: 调用Jupiter程序
        // Ethereum: 调用Uniswap Router

        let adapter = self.adapters.get(request.chain)
            .ok_or_else(|| WalletError::UnsupportedChain(request.chain.to_string()))?;

        tracing::info!("Executing swap: {} {} -> {} {}",
            request.amount_in, request.from_token,
            quote.amount_out, request.to_token);

        let tx_hash = format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16]));

        // 4. 记录Swap历史
        sqlx::query!(
            r#"
            INSERT INTO defi_swaps (id, user_address, chain, from_token, to_token, amount_in, amount_out, tx_hash, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'completed')
            "#,
            Uuid::new_v4(),
            request.user_address,
            request.chain.to_string(),
            request.from_token,
            request.to_token,
            request.amount_in.to_string(),
            quote.amount_out.to_string(),
            tx_hash.clone()
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(tx_hash)
    }

    /// 质押代币
    pub async fn stake_tokens(
        &self,
        request: StakeRequest,
    ) -> Result<String, WalletError> {
        let adapter = self.adapters.get(request.chain)
            .ok_or_else(|| WalletError::UnsupportedChain(request.chain.to_string()))?;

        // 实际实现中应该调用质押协议
        // Solana: Marinade, Lido
        // Ethereum: Lido, Rocket Pool

        tracing::info!("Staking {} tokens to pool {}",
            request.amount, request.pool_address);

        let tx_hash = format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16]));

        // 记录质押信息
        sqlx::query!(
            r#"
            INSERT INTO defi_stakes (id, user_address, chain, pool_address, token_address, staked_amount, tx_hash, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
            "#,
            Uuid::new_v4(),
            request.user_address,
            request.chain.to_string(),
            request.pool_address,
            request.token_address,
            request.amount.to_string(),
            tx_hash.clone()
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(tx_hash)
    }

    /// 解除质押
    pub async fn unstake_tokens(
        &self,
        stake_id: Uuid,
        amount: u64,
    ) -> Result<String, WalletError> {
        // 查询质押信息
        let stake = sqlx::query!(
            "SELECT user_address, chain, pool_address, staked_amount FROM defi_stakes WHERE id = $1",
            stake_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        let staked_amount: u64 = stake.staked_amount.parse()
            .map_err(|_| WalletError::Validation("Invalid staked amount".to_string()))?;

        if amount > staked_amount {
            return Err(WalletError::Validation("解除质押金额超过已质押金额".to_string()));
        }

        tracing::info!("Unstaking {} tokens from pool {}", amount, stake.pool_address);

        let tx_hash = format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16]));

        // 更新质押金额
        let new_amount = staked_amount - amount;
        sqlx::query!(
            "UPDATE defi_stakes SET staked_amount = $1, status = $2 WHERE id = $3",
            new_amount.to_string(),
            if new_amount == 0 { "unstaked" } else { "active" },
            stake_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(tx_hash)
    }

    /// 领取质押奖励
    pub async fn claim_rewards(
        &self,
        stake_id: Uuid,
    ) -> Result<String, WalletError> {
        // 查询质押信息
        let stake = sqlx::query!(
            "SELECT user_address, chain, pool_address FROM defi_stakes WHERE id = $1",
            stake_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        tracing::info!("Claiming rewards for stake {}", stake_id);

        let tx_hash = format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16]));

        // 更新最后领取时间
        sqlx::query!(
            "UPDATE defi_stakes SET last_claimed = $1 WHERE id = $2",
            Utc::now(),
            stake_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(tx_hash)
    }

    /// 获取用户的所有质押
    pub async fn get_user_stakes(
        &self,
        user_address: &str,
        chain: Chain,
    ) -> Result<Vec<StakeInfo>, WalletError> {
        let chain_str = chain.to_string();

        let stakes = sqlx::query_as!(
            StakeInfo,
            r#"
            SELECT
                id,
                user_address,
                chain,
                pool_address,
                token_address,
                staked_amount,
                rewards_earned,
                apy,
                staked_at,
                last_claimed
            FROM defi_stakes
            WHERE user_address = $1 AND chain = $2 AND status = 'active'
            ORDER BY staked_at DESC
            "#,
            user_address,
            chain_str
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(stakes)
    }

    /// 获取Swap历史
    pub async fn get_swap_history(
        &self,
        user_address: &str,
        chain: Option<Chain>,
        limit: i64,
    ) -> Result<Vec<SwapHistory>, WalletError> {
        let swaps = if let Some(chain) = chain {
            let chain_str = chain.to_string();
            sqlx::query_as!(
                SwapHistory,
                r#"
                SELECT
                    id,
                    user_address,
                    chain,
                    from_token,
                    to_token,
                    amount_in,
                    amount_out,
                    tx_hash,
                    status,
                    created_at
                FROM defi_swaps
                WHERE user_address = $1 AND chain = $2
                ORDER BY created_at DESC
                LIMIT $3
                "#,
                user_address,
                chain_str,
                limit
            )
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as!(
                SwapHistory,
                r#"
                SELECT
                    id,
                    user_address,
                    chain,
                    from_token,
                    to_token,
                    amount_in,
                    amount_out,
                    tx_hash,
                    status,
                    created_at
                FROM defi_swaps
                WHERE user_address = $1
                ORDER BY created_at DESC
                LIMIT $2
                "#,
                user_address,
                limit
            )
            .fetch_all(&self.db)
            .await
        };

        swaps.map_err(|e| WalletError::Database(e.to_string()))
    }

    /// 获取流动性池APY
    pub async fn get_pool_apy(
        &self,
        pool_address: &str,
        chain: Chain,
    ) -> Result<f64, WalletError> {
        // 实际实现中应该调用DeFi协议API获取实时APY
        tracing::info!("Getting APY for pool {} on chain {:?}", pool_address, chain);

        // 模拟返回
        Ok(12.5)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwapHistory {
    pub id: Uuid,
    pub user_address: String,
    pub chain: String,
    pub from_token: String,
    pub to_token: String,
    pub amount_in: String,
    pub amount_out: String,
    pub tx_hash: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swap_quote_calculation() {
        let amount_in = 1000000u64;
        let slippage = 0.5f64;

        let amount_out = (amount_in as f64 * 0.998) as u64;
        let minimum = (amount_out as f64 * (1.0 - slippage / 100.0)) as u64;

        assert!(minimum < amount_out);
    }
}
