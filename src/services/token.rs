// 代币管理服务 (ERC20/SPL Token)
use sqlx::PgPool;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::models::types::{Chain, WalletError};
use crate::services::blockchain::AdapterRegistry;

/// 代币信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub id: Uuid,
    pub chain: String,
    pub contract_address: String,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub logo_url: Option<String>,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
}

/// 代币余额
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    pub token_info: TokenInfo,
    pub balance: String,
    pub balance_usd: Option<f64>,
}

/// 代币转账请求
#[derive(Debug, Clone)]
pub struct TokenTransferRequest {
    pub from_address: String,
    pub to_address: String,
    pub token_address: String,
    pub amount: u64,
    pub chain: Chain,
}

/// 代币服务
pub struct TokenService {
    db: PgPool,
    adapters: Arc<AdapterRegistry>,
}

impl TokenService {
    pub fn new(db: PgPool, adapters: Arc<AdapterRegistry>) -> Self {
        Self { db, adapters }
    }

    /// 添加自定义代币
    pub async fn add_custom_token(
        &self,
        chain: Chain,
        contract_address: String,
        symbol: String,
        name: String,
        decimals: u8,
        logo_url: Option<String>,
    ) -> Result<TokenInfo, WalletError> {
        let chain_str = chain.to_string();
        let id = Uuid::new_v4();

        let token = sqlx::query_as!(
            TokenInfo,
            r#"
            INSERT INTO tokens (id, chain, contract_address, symbol, name, decimals, logo_url, is_verified)
            VALUES ($1, $2, $3, $4, $5, $6, $7, false)
            RETURNING id, chain, contract_address, symbol, name, decimals, logo_url, is_verified, created_at
            "#,
            id,
            chain_str,
            contract_address,
            symbol,
            name,
            decimals as i16,
            logo_url
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(token)
    }

    /// 获取代币信息
    pub async fn get_token_info(
        &self,
        contract_address: &str,
        chain: Chain,
    ) -> Result<TokenInfo, WalletError> {
        let chain_str = chain.to_string();

        let token = sqlx::query_as!(
            TokenInfo,
            r#"
            SELECT id, chain, contract_address, symbol, name, decimals, logo_url, is_verified, created_at
            FROM tokens
            WHERE contract_address = $1 AND chain = $2
            "#,
            contract_address,
            chain_str
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(token)
    }

    /// 获取钱包的代币余额列表
    pub async fn get_wallet_token_balances(
        &self,
        address: &str,
        chain: Chain,
    ) -> Result<Vec<TokenBalance>, WalletError> {
        let adapter = self.adapters.get(chain)
            .ok_or_else(|| WalletError::UnsupportedChain(chain.to_string()))?;

        // 获取该链上所有已验证的代币
        let chain_str = chain.to_string();
        let tokens = sqlx::query_as!(
            TokenInfo,
            r#"
            SELECT id, chain, contract_address, symbol, name, decimals, logo_url, is_verified, created_at
            FROM tokens
            WHERE chain = $1 AND (is_verified = true OR id IN (
                SELECT token_id FROM user_tokens WHERE user_address = $2
            ))
            "#,
            chain_str,
            address
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        let mut balances = Vec::new();

        for token in tokens {
            // 查询代币余额 (这里应该调用区块链适配器)
            let balance = self.get_token_balance(address, &token.contract_address, chain).await?;

            if balance > 0 {
                balances.push(TokenBalance {
                    token_info: token,
                    balance: balance.to_string(),
                    balance_usd: None, // 可以集成价格API
                });
            }
        }

        Ok(balances)
    }

    /// 查询单个代币余额
    pub async fn get_token_balance(
        &self,
        wallet_address: &str,
        token_address: &str,
        chain: Chain,
    ) -> Result<u64, WalletError> {
        let adapter = self.adapters.get(chain)
            .ok_or_else(|| WalletError::UnsupportedChain(chain.to_string()))?;

        // 实际实现中应该调用区块链适配器查询代币余额
        // Ethereum: 调用 ERC20.balanceOf(address)
        // Solana: 调用 getTokenAccountsByOwner

        tracing::info!("Querying token balance for {} on {}", wallet_address, token_address);

        // 模拟返回
        Ok(0)
    }

    /// 转账代币
    pub async fn transfer_token(
        &self,
        request: TokenTransferRequest,
    ) -> Result<String, WalletError> {
        // 1. 验证代币信息
        let token_info = self.get_token_info(&request.token_address, request.chain).await?;

        // 2. 检查余额
        let balance = self.get_token_balance(&request.from_address, &request.token_address, request.chain).await?;

        if balance < request.amount {
            return Err(WalletError::InsufficientBalance {
                available: balance,
                required: request.amount,
            });
        }

        // 3. 构建转账交易
        let adapter = self.adapters.get(request.chain)
            .ok_or_else(|| WalletError::UnsupportedChain(request.chain.to_string()))?;

        // 实际实现中应该构建代币转账交易
        // Ethereum: ERC20.transfer(to, amount)
        // Solana: SPL Token transfer

        tracing::info!("Transferring {} {} from {} to {}",
            request.amount, token_info.symbol, request.from_address, request.to_address);

        let tx_hash = format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16]));

        // 4. 记录交易
        sqlx::query!(
            r#"
            INSERT INTO transactions (id, chain, from_address, to_address, amount, token_address, tx_hash, status, tx_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'confirmed', 'token_transfer')
            "#,
            Uuid::new_v4(),
            request.chain.to_string(),
            request.from_address,
            request.to_address,
            request.amount.to_string(),
            Some(request.token_address),
            tx_hash.clone()
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(tx_hash)
    }

    /// 批量转账代币
    pub async fn batch_transfer_tokens(
        &self,
        requests: Vec<TokenTransferRequest>,
    ) -> Result<Vec<String>, WalletError> {
        let mut tx_hashes = Vec::new();

        for request in requests {
            let tx_hash = self.transfer_token(request).await?;
            tx_hashes.push(tx_hash);
        }

        Ok(tx_hashes)
    }

    /// 获取用户添加的自定义代币
    pub async fn get_user_custom_tokens(
        &self,
        user_address: &str,
        chain: Chain,
    ) -> Result<Vec<TokenInfo>, WalletError> {
        let chain_str = chain.to_string();

        let tokens = sqlx::query_as!(
            TokenInfo,
            r#"
            SELECT t.id, t.chain, t.contract_address, t.symbol, t.name, t.decimals, t.logo_url, t.is_verified, t.created_at
            FROM tokens t
            INNER JOIN user_tokens ut ON t.id = ut.token_id
            WHERE ut.user_address = $1 AND t.chain = $2
            "#,
            user_address,
            chain_str
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(tokens)
    }

    /// 用户添加代币到列表
    pub async fn add_token_to_user(
        &self,
        user_address: String,
        token_id: Uuid,
    ) -> Result<(), WalletError> {
        sqlx::query!(
            "INSERT INTO user_tokens (user_address, token_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            user_address,
            token_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(())
    }

    /// 获取代币价格 (集成外部价格API)
    pub async fn get_token_price(
        &self,
        token_address: &str,
        chain: Chain,
    ) -> Result<Option<f64>, WalletError> {
        // 这里应该集成CoinGecko, CoinMarketCap等价格API
        // 简化实现返回None

        tracing::info!("Getting price for token {} on chain {:?}", token_address, chain);

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_transfer_request() {
        let request = TokenTransferRequest {
            from_address: "0x123".to_string(),
            to_address: "0x456".to_string(),
            token_address: "0xToken".to_string(),
            amount: 1000000,
            chain: Chain::Ethereum,
        };

        assert_eq!(request.amount, 1000000);
    }
}
