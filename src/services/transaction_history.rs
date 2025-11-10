// 交易记录查询与导出服务
use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use csv::Writer;
use std::io::Write as IoWrite;

use crate::models::types::{Chain, WalletError};

/// 交易类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    Transfer,
    TokenTransfer,
    NftTransfer,
    Swap,
    Stake,
    Unstake,
    Deposit,
    Withdrawal,
}

/// 交易记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub id: Uuid,
    pub chain: String,
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: String,
    pub token_address: Option<String>,
    pub token_symbol: Option<String>,
    pub tx_type: String,
    pub status: String,
    pub fee: Option<String>,
    pub block_number: Option<i64>,
    pub confirmations: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// 交易查询过滤器
#[derive(Debug, Clone, Default)]
pub struct TransactionFilter {
    pub address: Option<String>,
    pub chain: Option<Chain>,
    pub tx_type: Option<String>,
    pub status: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub min_amount: Option<u64>,
    pub max_amount: Option<u64>,
}

/// 交易统计
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionStats {
    pub total_transactions: i64,
    pub total_sent: String,
    pub total_received: String,
    pub total_fees: String,
    pub by_type: Vec<TypeStats>,
    pub by_chain: Vec<ChainStats>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TypeStats {
    pub tx_type: String,
    pub count: i64,
    pub total_amount: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChainStats {
    pub chain: String,
    pub count: i64,
    pub total_amount: String,
}

/// 交易导出格式
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    CSV,
    JSON,
    PDF,
}

/// 交易历史服务
pub struct TransactionHistoryService {
    db: PgPool,
}

impl TransactionHistoryService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// 查询交易记录
    pub async fn query_transactions(
        &self,
        filter: TransactionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TransactionRecord>, WalletError> {
        let mut query = String::from(
            r#"
            SELECT
                id,
                chain,
                tx_hash,
                from_address,
                to_address,
                amount,
                token_address,
                token_symbol,
                tx_type,
                status,
                fee,
                block_number,
                confirmations,
                created_at,
                confirmed_at
            FROM transactions
            WHERE 1=1
            "#
        );

        let mut params: Vec<String> = Vec::new();

        if let Some(address) = &filter.address {
            query.push_str(&format!(" AND (from_address = '{}' OR to_address = '{}')", address, address));
        }

        if let Some(chain) = &filter.chain {
            query.push_str(&format!(" AND chain = '{}'", chain.to_string()));
        }

        if let Some(tx_type) = &filter.tx_type {
            query.push_str(&format!(" AND tx_type = '{}'", tx_type));
        }

        if let Some(status) = &filter.status {
            query.push_str(&format!(" AND status = '{}'", status));
        }

        if let Some(start_date) = &filter.start_date {
            query.push_str(&format!(" AND created_at >= '{}'", start_date.to_rfc3339()));
        }

        if let Some(end_date) = &filter.end_date {
            query.push_str(&format!(" AND created_at <= '{}'", end_date.to_rfc3339()));
        }

        query.push_str(&format!(" ORDER BY created_at DESC LIMIT {} OFFSET {}", limit, offset));

        let records = sqlx::query_as::<_, TransactionRecord>(&query)
            .fetch_all(&self.db)
            .await
            .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(records)
    }

    /// 获取单个交易详情
    pub async fn get_transaction(
        &self,
        tx_hash: &str,
    ) -> Result<TransactionRecord, WalletError> {
        let record = sqlx::query_as!(
            TransactionRecord,
            r#"
            SELECT
                id,
                chain,
                tx_hash,
                from_address,
                to_address,
                amount,
                token_address,
                token_symbol,
                tx_type,
                status,
                fee,
                block_number,
                confirmations,
                created_at,
                confirmed_at
            FROM transactions
            WHERE tx_hash = $1
            "#,
            tx_hash
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(record)
    }

    /// 获取交易统计
    pub async fn get_transaction_stats(
        &self,
        address: &str,
        chain: Option<Chain>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> Result<TransactionStats, WalletError> {
        let chain_filter = chain.map(|c| c.to_string());

        // 总交易数
        let total: i64 = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)
            FROM transactions
            WHERE (from_address = $1 OR to_address = $1)
                AND ($2::text IS NULL OR chain = $2)
                AND ($3::timestamptz IS NULL OR created_at >= $3)
                AND ($4::timestamptz IS NULL OR created_at <= $4)
            "#,
            address,
            chain_filter.as_deref(),
            start_date,
            end_date
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?
        .unwrap_or(0);

        // 按类型统计
        let type_stats = sqlx::query_as!(
            TypeStats,
            r#"
            SELECT
                tx_type,
                COUNT(*) as count,
                COALESCE(SUM(amount::bigint), 0)::text as total_amount
            FROM transactions
            WHERE (from_address = $1 OR to_address = $1)
                AND ($2::text IS NULL OR chain = $2)
            GROUP BY tx_type
            "#,
            address,
            chain_filter.as_deref()
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        // 按链统计
        let chain_stats = sqlx::query_as!(
            ChainStats,
            r#"
            SELECT
                chain,
                COUNT(*) as count,
                COALESCE(SUM(amount::bigint), 0)::text as total_amount
            FROM transactions
            WHERE (from_address = $1 OR to_address = $1)
            GROUP BY chain
            "#,
            address
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(TransactionStats {
            total_transactions: total,
            total_sent: "0".to_string(),
            total_received: "0".to_string(),
            total_fees: "0".to_string(),
            by_type: type_stats,
            by_chain: chain_stats,
        })
    }

    /// 导出交易记录为CSV
    pub async fn export_to_csv(
        &self,
        filter: TransactionFilter,
    ) -> Result<Vec<u8>, WalletError> {
        let transactions = self.query_transactions(filter, 10000, 0).await?;

        let mut wtr = Writer::from_writer(vec![]);

        // 写入表头
        wtr.write_record(&[
            "交易哈希", "链", "类型", "发送地址", "接收地址", "金额",
            "代币符号", "状态", "手续费", "区块高度", "时间"
        ])
        .map_err(|e| WalletError::Internal(e.to_string()))?;

        // 写入数据
        for tx in transactions {
            wtr.write_record(&[
                &tx.tx_hash,
                &tx.chain,
                &tx.tx_type,
                &tx.from_address,
                &tx.to_address,
                &tx.amount,
                &tx.token_symbol.unwrap_or_else(|| "Native".to_string()),
                &tx.status,
                &tx.fee.unwrap_or_else(|| "0".to_string()),
                &tx.block_number.map(|b| b.to_string()).unwrap_or_else(|| "-".to_string()),
                &tx.created_at.to_rfc3339(),
            ])
            .map_err(|e| WalletError::Internal(e.to_string()))?;
        }

        wtr.flush().map_err(|e| WalletError::Internal(e.to_string()))?;

        Ok(wtr.into_inner().map_err(|e| WalletError::Internal(e.to_string()))?)
    }

    /// 导出交易记录为JSON
    pub async fn export_to_json(
        &self,
        filter: TransactionFilter,
    ) -> Result<Vec<u8>, WalletError> {
        let transactions = self.query_transactions(filter, 10000, 0).await?;

        let json = serde_json::to_string_pretty(&transactions)
            .map_err(|e| WalletError::Internal(e.to_string()))?;

        Ok(json.into_bytes())
    }

    /// 导出交易记录
    pub async fn export_transactions(
        &self,
        filter: TransactionFilter,
        format: ExportFormat,
    ) -> Result<Vec<u8>, WalletError> {
        match format {
            ExportFormat::CSV => self.export_to_csv(filter).await,
            ExportFormat::JSON => self.export_to_json(filter).await,
            ExportFormat::PDF => {
                // PDF导出需要额外的库,这里简化处理
                Err(WalletError::Internal("PDF export not implemented".to_string()))
            }
        }
    }

    /// 获取地址的交易计数
    pub async fn get_transaction_count(
        &self,
        address: &str,
        chain: Option<Chain>,
    ) -> Result<i64, WalletError> {
        let chain_str = chain.map(|c| c.to_string());

        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)
            FROM transactions
            WHERE (from_address = $1 OR to_address = $1)
                AND ($2::text IS NULL OR chain = $2)
            "#,
            address,
            chain_str.as_deref()
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?
        .unwrap_or(0);

        Ok(count)
    }

    /// 获取最近的交易
    pub async fn get_recent_transactions(
        &self,
        address: &str,
        limit: i64,
    ) -> Result<Vec<TransactionRecord>, WalletError> {
        let records = sqlx::query_as!(
            TransactionRecord,
            r#"
            SELECT
                id,
                chain,
                tx_hash,
                from_address,
                to_address,
                amount,
                token_address,
                token_symbol,
                tx_type,
                status,
                fee,
                block_number,
                confirmations,
                created_at,
                confirmed_at
            FROM transactions
            WHERE from_address = $1 OR to_address = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
            address,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_filter() {
        let filter = TransactionFilter {
            address: Some("0x123".to_string()),
            chain: Some(Chain::Ethereum),
            ..Default::default()
        };

        assert!(filter.address.is_some());
        assert!(filter.chain.is_some());
    }
}
