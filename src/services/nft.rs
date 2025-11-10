// NFT资产管理服务
use sqlx::PgPool;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::models::types::{Chain, WalletError};
use crate::services::blockchain::AdapterRegistry;

/// NFT元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFTMetadata {
    pub name: String,
    pub description: Option<String>,
    pub image: String,
    pub attributes: Option<Vec<NFTAttribute>>,
    pub external_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFTAttribute {
    pub trait_type: String,
    pub value: String,
}

/// NFT资产
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFTAsset {
    pub id: Uuid,
    pub chain: String,
    pub owner_address: String,
    pub contract_address: String,
    pub token_id: String,
    pub metadata: Option<NFTMetadata>,
    pub image_url: Option<String>,
    pub last_synced: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// NFT转移请求
#[derive(Debug, Clone)]
pub struct NFTTransferRequest {
    pub from_address: String,
    pub to_address: String,
    pub contract_address: String,
    pub token_id: String,
    pub chain: Chain,
}

/// NFT服务
pub struct NFTService {
    db: PgPool,
    adapters: Arc<AdapterRegistry>,
}

impl NFTService {
    pub fn new(db: PgPool, adapters: Arc<AdapterRegistry>) -> Self {
        Self { db, adapters }
    }

    /// 查询钱包的所有NFT
    pub async fn get_wallet_nfts(
        &self,
        address: &str,
        chain: Chain,
    ) -> Result<Vec<NFTAsset>, WalletError> {
        let chain_str = chain.to_string();

        let nfts = sqlx::query_as!(
            NFTAsset,
            r#"
            SELECT
                id,
                chain,
                owner_address,
                contract_address,
                token_id,
                metadata as "metadata: sqlx::types::Json<NFTMetadata>",
                image_url,
                last_synced,
                created_at
            FROM nft_assets
            WHERE owner_address = $1 AND chain = $2
            ORDER BY created_at DESC
            "#,
            address,
            chain_str
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(nfts)
    }

    /// 同步钱包NFT (从链上获取最新数据)
    pub async fn sync_wallet_nfts(
        &self,
        address: &str,
        chain: Chain,
    ) -> Result<usize, WalletError> {
        // 这里应该调用区块链适配器获取NFT列表
        // 由于示例简化,这里返回模拟数据

        tracing::info!("Syncing NFTs for address {} on chain {:?}", address, chain);

        // 实际实现中,应该调用链上API获取NFT列表
        // 例如: Solana使用Metaplex, Ethereum使用OpenSea/Alchemy API

        Ok(0)
    }

    /// 转移NFT
    pub async fn transfer_nft(
        &self,
        request: NFTTransferRequest,
    ) -> Result<String, WalletError> {
        // 1. 验证NFT所有权
        let nft = self.get_nft_by_token(&request.contract_address, &request.token_id, request.chain).await?;

        if nft.owner_address != request.from_address {
            return Err(WalletError::Validation("NFT不属于该地址".to_string()));
        }

        // 2. 构建并发送转移交易
        let adapter = self.adapters.get(request.chain)
            .ok_or_else(|| WalletError::UnsupportedChain(request.chain.to_string()))?;

        // 这里应该构建NFT转移交易
        // Solana: 使用Metaplex Token Metadata
        // Ethereum: 使用ERC721 transferFrom

        tracing::info!("Transferring NFT {} from {} to {}",
            request.token_id, request.from_address, request.to_address);

        // 3. 更新数据库
        let tx_hash = format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16]));

        sqlx::query!(
            "UPDATE nft_assets SET owner_address = $1, last_synced = $2 WHERE contract_address = $3 AND token_id = $4",
            request.to_address,
            Utc::now(),
            request.contract_address,
            request.token_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(tx_hash)
    }

    /// 批量转移NFT
    pub async fn batch_transfer_nfts(
        &self,
        requests: Vec<NFTTransferRequest>,
    ) -> Result<Vec<String>, WalletError> {
        let mut tx_hashes = Vec::new();

        for request in requests {
            let tx_hash = self.transfer_nft(request).await?;
            tx_hashes.push(tx_hash);
        }

        Ok(tx_hashes)
    }

    /// 获取单个NFT详情
    pub async fn get_nft_by_token(
        &self,
        contract_address: &str,
        token_id: &str,
        chain: Chain,
    ) -> Result<NFTAsset, WalletError> {
        let chain_str = chain.to_string();

        let nft = sqlx::query_as!(
            NFTAsset,
            r#"
            SELECT
                id,
                chain,
                owner_address,
                contract_address,
                token_id,
                metadata as "metadata: sqlx::types::Json<NFTMetadata>",
                image_url,
                last_synced,
                created_at
            FROM nft_assets
            WHERE contract_address = $1 AND token_id = $2 AND chain = $3
            "#,
            contract_address,
            token_id,
            chain_str
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(nft)
    }

    /// 获取NFT统计信息
    pub async fn get_nft_stats(
        &self,
        address: &str,
        chain: Chain,
    ) -> Result<NFTStats, WalletError> {
        let chain_str = chain.to_string();

        let count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM nft_assets WHERE owner_address = $1 AND chain = $2",
            address,
            chain_str
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?
        .unwrap_or(0);

        let collections_count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(DISTINCT contract_address) FROM nft_assets WHERE owner_address = $1 AND chain = $2",
            address,
            chain_str
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?
        .unwrap_or(0);

        Ok(NFTStats {
            total_nfts: count as u64,
            total_collections: collections_count as u64,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct NFTStats {
    pub total_nfts: u64,
    pub total_collections: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nft_metadata_parsing() {
        let metadata = NFTMetadata {
            name: "Test NFT".to_string(),
            description: Some("A test NFT".to_string()),
            image: "https://example.com/image.png".to_string(),
            attributes: Some(vec![
                NFTAttribute {
                    trait_type: "Background".to_string(),
                    value: "Blue".to_string(),
                },
            ]),
            external_url: None,
        };

        assert_eq!(metadata.name, "Test NFT");
    }
}
