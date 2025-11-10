// 地址簿管理服务
use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::models::types::{Chain, WalletError};

/// 地址簿条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressBookEntry {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub address: String,
    pub chain: String,
    pub labels: Vec<String>,
    pub note: Option<String>,
    pub is_favorite: bool,
    pub usage_count: i32,
    pub last_used: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 创建地址簿条目请求
#[derive(Debug, Clone, Deserialize)]
pub struct CreateAddressBookEntryRequest {
    pub user_id: Uuid,
    pub name: String,
    pub address: String,
    pub chain: Chain,
    pub labels: Option<Vec<String>>,
    pub note: Option<String>,
}

/// 更新地址簿条目请求
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateAddressBookEntryRequest {
    pub name: Option<String>,
    pub labels: Option<Vec<String>>,
    pub note: Option<String>,
    pub is_favorite: Option<bool>,
}

/// 地址簿服务
pub struct AddressBookService {
    db: PgPool,
}

impl AddressBookService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// 添加地址到地址簿
    pub async fn add_address(
        &self,
        request: CreateAddressBookEntryRequest,
    ) -> Result<AddressBookEntry, WalletError> {
        // 验证地址格式 (实际应该调用区块链适配器验证)
        self.validate_address(&request.address, request.chain)?;

        // 检查是否已存在
        let existing = sqlx::query!(
            "SELECT id FROM address_book WHERE user_id = $1 AND address = $2 AND chain = $3",
            request.user_id,
            request.address,
            request.chain.to_string()
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        if existing.is_some() {
            return Err(WalletError::Validation("地址已存在于地址簿中".to_string()));
        }

        let id = Uuid::new_v4();
        let labels = request.labels.unwrap_or_default();

        let entry = sqlx::query_as!(
            AddressBookEntry,
            r#"
            INSERT INTO address_book (id, user_id, name, address, chain, labels, note, is_favorite, usage_count)
            VALUES ($1, $2, $3, $4, $5, $6, $7, false, 0)
            RETURNING id, user_id, name, address, chain, labels as "labels!", note, is_favorite, usage_count, last_used, created_at, updated_at
            "#,
            id,
            request.user_id,
            request.name,
            request.address,
            request.chain.to_string(),
            &labels,
            request.note
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(entry)
    }

    /// 获取用户的地址簿
    pub async fn get_address_book(
        &self,
        user_id: Uuid,
        chain: Option<Chain>,
    ) -> Result<Vec<AddressBookEntry>, WalletError> {
        let entries = if let Some(chain) = chain {
            let chain_str = chain.to_string();
            sqlx::query_as!(
                AddressBookEntry,
                r#"
                SELECT id, user_id, name, address, chain, labels as "labels!", note, is_favorite, usage_count, last_used, created_at, updated_at
                FROM address_book
                WHERE user_id = $1 AND chain = $2
                ORDER BY is_favorite DESC, usage_count DESC, name ASC
                "#,
                user_id,
                chain_str
            )
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as!(
                AddressBookEntry,
                r#"
                SELECT id, user_id, name, address, chain, labels as "labels!", note, is_favorite, usage_count, last_used, created_at, updated_at
                FROM address_book
                WHERE user_id = $1
                ORDER BY is_favorite DESC, usage_count DESC, name ASC
                "#,
                user_id
            )
            .fetch_all(&self.db)
            .await
        };

        entries.map_err(|e| WalletError::Database(e.to_string()))
    }

    /// 获取单个地址簿条目
    pub async fn get_entry(
        &self,
        id: Uuid,
    ) -> Result<AddressBookEntry, WalletError> {
        let entry = sqlx::query_as!(
            AddressBookEntry,
            r#"
            SELECT id, user_id, name, address, chain, labels as "labels!", note, is_favorite, usage_count, last_used, created_at, updated_at
            FROM address_book
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(entry)
    }

    /// 更新地址簿条目
    pub async fn update_entry(
        &self,
        id: Uuid,
        user_id: Uuid,
        request: UpdateAddressBookEntryRequest,
    ) -> Result<AddressBookEntry, WalletError> {
        // 验证所有权
        let entry = self.get_entry(id).await?;
        if entry.user_id != user_id {
            return Err(WalletError::Unauthorized);
        }

        if let Some(name) = request.name {
            sqlx::query!(
                "UPDATE address_book SET name = $1, updated_at = NOW() WHERE id = $2",
                name,
                id
            )
            .execute(&self.db)
            .await
            .map_err(|e| WalletError::Database(e.to_string()))?;
        }

        if let Some(labels) = request.labels {
            sqlx::query!(
                "UPDATE address_book SET labels = $1, updated_at = NOW() WHERE id = $2",
                &labels,
                id
            )
            .execute(&self.db)
            .await
            .map_err(|e| WalletError::Database(e.to_string()))?;
        }

        if let Some(note) = request.note {
            sqlx::query!(
                "UPDATE address_book SET note = $1, updated_at = NOW() WHERE id = $2",
                note,
                id
            )
            .execute(&self.db)
            .await
            .map_err(|e| WalletError::Database(e.to_string()))?;
        }

        if let Some(is_favorite) = request.is_favorite {
            sqlx::query!(
                "UPDATE address_book SET is_favorite = $1, updated_at = NOW() WHERE id = $2",
                is_favorite,
                id
            )
            .execute(&self.db)
            .await
            .map_err(|e| WalletError::Database(e.to_string()))?;
        }

        self.get_entry(id).await
    }

    /// 删除地址簿条目
    pub async fn delete_entry(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<(), WalletError> {
        let result = sqlx::query!(
            "DELETE FROM address_book WHERE id = $1 AND user_id = $2",
            id,
            user_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(WalletError::NotFound("地址簿条目不存在".to_string()));
        }

        Ok(())
    }

    /// 搜索地址簿
    pub async fn search_address_book(
        &self,
        user_id: Uuid,
        query: &str,
    ) -> Result<Vec<AddressBookEntry>, WalletError> {
        let search_pattern = format!("%{}%", query);

        let entries = sqlx::query_as!(
            AddressBookEntry,
            r#"
            SELECT id, user_id, name, address, chain, labels as "labels!", note, is_favorite, usage_count, last_used, created_at, updated_at
            FROM address_book
            WHERE user_id = $1
                AND (name ILIKE $2 OR address ILIKE $2 OR $2 = ANY(labels))
            ORDER BY usage_count DESC, name ASC
            "#,
            user_id,
            search_pattern
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(entries)
    }

    /// 按标签过滤
    pub async fn get_entries_by_label(
        &self,
        user_id: Uuid,
        label: &str,
    ) -> Result<Vec<AddressBookEntry>, WalletError> {
        let entries = sqlx::query_as!(
            AddressBookEntry,
            r#"
            SELECT id, user_id, name, address, chain, labels as "labels!", note, is_favorite, usage_count, last_used, created_at, updated_at
            FROM address_book
            WHERE user_id = $1 AND $2 = ANY(labels)
            ORDER BY usage_count DESC, name ASC
            "#,
            user_id,
            label
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(entries)
    }

    /// 获取收藏的地址
    pub async fn get_favorite_addresses(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AddressBookEntry>, WalletError> {
        let entries = sqlx::query_as!(
            AddressBookEntry,
            r#"
            SELECT id, user_id, name, address, chain, labels as "labels!", note, is_favorite, usage_count, last_used, created_at, updated_at
            FROM address_book
            WHERE user_id = $1 AND is_favorite = true
            ORDER BY usage_count DESC, name ASC
            "#,
            user_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(entries)
    }

    /// 记录地址使用
    pub async fn record_address_usage(
        &self,
        user_id: Uuid,
        address: &str,
    ) -> Result<(), WalletError> {
        sqlx::query!(
            r#"
            UPDATE address_book
            SET usage_count = usage_count + 1, last_used = NOW()
            WHERE user_id = $1 AND address = $2
            "#,
            user_id,
            address
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(())
    }

    /// 获取最常使用的地址
    pub async fn get_most_used_addresses(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AddressBookEntry>, WalletError> {
        let entries = sqlx::query_as!(
            AddressBookEntry,
            r#"
            SELECT id, user_id, name, address, chain, labels as "labels!", note, is_favorite, usage_count, last_used, created_at, updated_at
            FROM address_book
            WHERE user_id = $1 AND usage_count > 0
            ORDER BY usage_count DESC, last_used DESC
            LIMIT $2
            "#,
            user_id,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(entries)
    }

    /// 获取所有标签
    pub async fn get_all_labels(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<String>, WalletError> {
        let result = sqlx::query!(
            r#"
            SELECT DISTINCT UNNEST(labels) as label
            FROM address_book
            WHERE user_id = $1
            ORDER BY label
            "#,
            user_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        let labels = result.into_iter()
            .filter_map(|r| r.label)
            .collect();

        Ok(labels)
    }

    /// 验证地址格式
    fn validate_address(&self, address: &str, chain: Chain) -> Result<(), WalletError> {
        // 简化的地址验证
        match chain {
            Chain::Ethereum | Chain::BinanceSmartChain | Chain::Polygon => {
                if !address.starts_with("0x") || address.len() != 42 {
                    return Err(WalletError::Validation("无效的以太坊地址格式".to_string()));
                }
            }
            Chain::Solana => {
                if address.len() < 32 || address.len() > 44 {
                    return Err(WalletError::Validation("无效的Solana地址格式".to_string()));
                }
            }
            Chain::Bitcoin => {
                // Bitcoin地址验证
                if address.len() < 26 || address.len() > 35 {
                    return Err(WalletError::Validation("无效的Bitcoin地址格式".to_string()));
                }
            }
            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_address_book_request() {
        let request = CreateAddressBookEntryRequest {
            user_id: Uuid::new_v4(),
            name: "Alice".to_string(),
            address: "0x123...".to_string(),
            chain: Chain::Ethereum,
            labels: Some(vec!["friend".to_string()]),
            note: Some("My friend Alice".to_string()),
        };

        assert_eq!(request.name, "Alice");
    }
}
