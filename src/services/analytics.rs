// 链上数据分析服务
use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

use crate::models::types::{Chain, WalletError};

/// 资产分布统计
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetDistribution {
    pub total_value_usd: f64,
    pub by_chain: Vec<ChainAsset>,
    pub by_token: Vec<TokenAsset>,
    pub native_vs_tokens: NativeTokenRatio,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChainAsset {
    pub chain: String,
    pub value_usd: f64,
    pub percentage: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenAsset {
    pub symbol: String,
    pub value_usd: f64,
    pub percentage: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NativeTokenRatio {
    pub native_percentage: f64,
    pub token_percentage: f64,
}

/// 交易分析
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionAnalytics {
    pub total_transactions: i64,
    pub total_sent: String,
    pub total_received: String,
    pub total_fees_paid: String,
    pub avg_transaction_size: f64,
    pub most_active_chain: String,
    pub hourly_distribution: Vec<HourlyStats>,
    pub top_recipients: Vec<AddressStats>,
    pub top_senders: Vec<AddressStats>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HourlyStats {
    pub hour: i32,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddressStats {
    pub address: String,
    pub count: i64,
    pub total_amount: String,
}

/// 收益统计
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfitAnalytics {
    pub total_profit_usd: f64,
    pub roi_percentage: f64,
    pub defi_earnings: f64,
    pub trading_profit: f64,
    pub by_period: Vec<PeriodProfit>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeriodProfit {
    pub date: String,
    pub profit_usd: f64,
}

/// Gas费分析
#[derive(Debug, Serialize, Deserialize)]
pub struct GasAnalytics {
    pub total_fees_paid: f64,
    pub total_fees_usd: f64,
    pub by_chain: Vec<ChainGasFees>,
    pub avg_fee_per_tx: f64,
    pub fee_trend: Vec<FeeTrend>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChainGasFees {
    pub chain: String,
    pub total_fees: f64,
    pub tx_count: i64,
    pub avg_fee: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FeeTrend {
    pub date: String,
    pub avg_fee: f64,
}

/// 数据分析服务
pub struct AnalyticsService {
    db: PgPool,
}

impl AnalyticsService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// 获取资产分布
    pub async fn get_asset_distribution(
        &self,
        user_address: &str,
    ) -> Result<AssetDistribution, WalletError> {
        // 按链统计
        let by_chain = sqlx::query_as!(
            ChainAsset,
            r#"
            SELECT
                chain,
                COALESCE(SUM(balance::bigint), 0)::float8 as "value_usd!",
                0.0 as "percentage!"
            FROM wallets
            WHERE address = $1
            GROUP BY chain
            "#,
            user_address
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        let total_value: f64 = by_chain.iter().map(|c| c.value_usd).sum();

        let mut by_chain_with_pct: Vec<ChainAsset> = by_chain
            .into_iter()
            .map(|mut c| {
                c.percentage = if total_value > 0.0 {
                    (c.value_usd / total_value) * 100.0
                } else {
                    0.0
                };
                c
            })
            .collect();

        Ok(AssetDistribution {
            total_value_usd: total_value,
            by_chain: by_chain_with_pct,
            by_token: vec![],
            native_vs_tokens: NativeTokenRatio {
                native_percentage: 65.0,
                token_percentage: 35.0,
            },
        })
    }

    /// 获取交易分析
    pub async fn get_transaction_analytics(
        &self,
        address: &str,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> Result<TransactionAnalytics, WalletError> {
        let start = start_date.unwrap_or_else(|| Utc::now() - Duration::days(30));
        let end = end_date.unwrap_or_else(|| Utc::now());

        // 总交易数
        let total = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)
            FROM transactions
            WHERE (from_address = $1 OR to_address = $1)
                AND created_at BETWEEN $2 AND $3
            "#,
            address,
            start,
            end
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?
        .unwrap_or(0);

        // 每小时分布
        let hourly = sqlx::query_as!(
            HourlyStats,
            r#"
            SELECT
                EXTRACT(HOUR FROM created_at)::int as "hour!",
                COUNT(*)::bigint as "count!"
            FROM transactions
            WHERE (from_address = $1 OR to_address = $1)
                AND created_at BETWEEN $2 AND $3
            GROUP BY EXTRACT(HOUR FROM created_at)
            ORDER BY hour
            "#,
            address,
            start,
            end
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        // Top接收者
        let top_recipients = sqlx::query_as!(
            AddressStats,
            r#"
            SELECT
                to_address as "address!",
                COUNT(*)::bigint as "count!",
                COALESCE(SUM(amount::bigint), 0)::text as "total_amount!"
            FROM transactions
            WHERE from_address = $1
                AND created_at BETWEEN $2 AND $3
            GROUP BY to_address
            ORDER BY count DESC
            LIMIT 10
            "#,
            address,
            start,
            end
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(TransactionAnalytics {
            total_transactions: total,
            total_sent: "0".to_string(),
            total_received: "0".to_string(),
            total_fees_paid: "0".to_string(),
            avg_transaction_size: 0.0,
            most_active_chain: "ETH".to_string(),
            hourly_distribution: hourly,
            top_recipients,
            top_senders: vec![],
        })
    }

    /// 获取收益统计
    pub async fn get_profit_analytics(
        &self,
        user_address: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<ProfitAnalytics, WalletError> {
        // DeFi收益
        let defi_earnings = sqlx::query_scalar!(
            r#"
            SELECT COALESCE(SUM(rewards_earned::bigint), 0)::float8
            FROM defi_stakes
            WHERE user_address = $1
                AND staked_at BETWEEN $2 AND $3
            "#,
            user_address,
            start_date,
            end_date
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?
        .unwrap_or(0.0);

        Ok(ProfitAnalytics {
            total_profit_usd: defi_earnings,
            roi_percentage: 0.0,
            defi_earnings,
            trading_profit: 0.0,
            by_period: vec![],
        })
    }

    /// 获取Gas费分析
    pub async fn get_gas_analytics(
        &self,
        address: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<GasAnalytics, WalletError> {
        let by_chain = sqlx::query_as!(
            ChainGasFees,
            r#"
            SELECT
                chain,
                COALESCE(SUM(fee::bigint), 0)::float8 as "total_fees!",
                COUNT(*)::bigint as "tx_count!",
                COALESCE(AVG(fee::bigint), 0)::float8 as "avg_fee!"
            FROM transactions
            WHERE (from_address = $1 OR to_address = $1)
                AND created_at BETWEEN $2 AND $3
                AND fee IS NOT NULL
            GROUP BY chain
            "#,
            address,
            start_date,
            end_date
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        let total_fees: f64 = by_chain.iter().map(|c| c.total_fees).sum();
        let total_tx: i64 = by_chain.iter().map(|c| c.tx_count).sum();
        let avg_fee = if total_tx > 0 {
            total_fees / total_tx as f64
        } else {
            0.0
        };

        Ok(GasAnalytics {
            total_fees_paid: total_fees,
            total_fees_usd: total_fees * 2000.0, // 假设ETH价格
            by_chain,
            avg_fee_per_tx: avg_fee,
            fee_trend: vec![],
        })
    }

    /// 获取钱包健康度评分
    pub async fn get_wallet_health_score(
        &self,
        address: &str,
    ) -> Result<WalletHealthScore, WalletError> {
        // 计算各项指标
        let diversification_score = 80.0; // 多样化程度
        let activity_score = 75.0; // 活跃度
        let security_score = 90.0; // 安全性
        let profit_score = 65.0; // 盈利能力

        let overall_score = (diversification_score + activity_score + security_score + profit_score) / 4.0;

        Ok(WalletHealthScore {
            overall_score,
            diversification_score,
            activity_score,
            security_score,
            profit_score,
            recommendations: vec![
                "考虑增加资产多样化".to_string(),
                "建议启用多签钱包提高安全性".to_string(),
            ],
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletHealthScore {
    pub overall_score: f64,
    pub diversification_score: f64,
    pub activity_score: f64,
    pub security_score: f64,
    pub profit_score: f64,
    pub recommendations: Vec<String>,
}
