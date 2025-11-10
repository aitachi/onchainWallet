// Gas费预测与优化服务
use sqlx::PgPool;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::models::types::{Chain, WalletError};
use crate::services::blockchain::AdapterRegistry;

/// Gas费优先级
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GasPriority {
    Slow,
    Standard,
    Fast,
    Instant,
}

/// Gas费估算结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimate {
    pub chain: String,
    pub slow: GasFee,
    pub standard: GasFee,
    pub fast: GasFee,
    pub instant: GasFee,
    pub estimated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasFee {
    pub gas_price: Option<u64>,      // Wei for Ethereum
    pub max_fee: Option<u64>,        // EIP-1559
    pub max_priority_fee: Option<u64>, // EIP-1559
    pub compute_units: Option<u64>,  // Solana
    pub estimated_cost_usd: Option<f64>,
    pub estimated_time_seconds: u64,
}

/// Gas费历史记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasHistory {
    pub chain: String,
    pub timestamp: DateTime<Utc>,
    pub avg_gas_price: u64,
    pub min_gas_price: u64,
    pub max_gas_price: u64,
    pub network_utilization: f64,
}

/// Gas费优化建议
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasOptimizationAdvice {
    pub current_gas_price: u64,
    pub recommended_gas_price: u64,
    pub potential_savings_percent: f64,
    pub best_time_to_send: Option<DateTime<Utc>>,
    pub network_congestion: NetworkCongestion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkCongestion {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Gas费服务
pub struct GasService {
    db: PgPool,
    adapters: Arc<AdapterRegistry>,
}

impl GasService {
    pub fn new(db: PgPool, adapters: Arc<AdapterRegistry>) -> Self {
        Self { db, adapters }
    }

    /// 获取当前Gas费估算
    pub async fn get_gas_estimate(
        &self,
        chain: Chain,
    ) -> Result<GasEstimate, WalletError> {
        let adapter = self.adapters.get(chain)
            .ok_or_else(|| WalletError::UnsupportedChain(chain.to_string()))?;

        match chain {
            Chain::Ethereum | Chain::BinanceSmartChain | Chain::Polygon => {
                self.get_evm_gas_estimate(chain).await
            }
            Chain::Solana => {
                self.get_solana_gas_estimate().await
            }
            _ => Err(WalletError::UnsupportedChain(chain.to_string())),
        }
    }

    /// 获取EVM链Gas费估算
    async fn get_evm_gas_estimate(
        &self,
        chain: Chain,
    ) -> Result<GasEstimate, WalletError> {
        // 实际实现中应该调用链上RPC或Gas Station API
        // Ethereum: Etherscan Gas Tracker, EthGasStation
        // BSC: BscScan Gas Tracker
        // Polygon: PolygonScan Gas Tracker

        tracing::info!("Getting gas estimate for {:?}", chain);

        // 模拟返回 (单位: Gwei)
        let base_price = 30u64;

        Ok(GasEstimate {
            chain: chain.to_string(),
            slow: GasFee {
                gas_price: Some(base_price * 1_000_000_000),
                max_fee: Some((base_price + 2) * 1_000_000_000),
                max_priority_fee: Some(1 * 1_000_000_000),
                compute_units: None,
                estimated_cost_usd: Some(0.50),
                estimated_time_seconds: 300,
            },
            standard: GasFee {
                gas_price: Some((base_price + 5) * 1_000_000_000),
                max_fee: Some((base_price + 7) * 1_000_000_000),
                max_priority_fee: Some(2 * 1_000_000_000),
                compute_units: None,
                estimated_cost_usd: Some(0.75),
                estimated_time_seconds: 60,
            },
            fast: GasFee {
                gas_price: Some((base_price + 10) * 1_000_000_000),
                max_fee: Some((base_price + 12) * 1_000_000_000),
                max_priority_fee: Some(3 * 1_000_000_000),
                compute_units: None,
                estimated_cost_usd: Some(1.20),
                estimated_time_seconds: 15,
            },
            instant: GasFee {
                gas_price: Some((base_price + 20) * 1_000_000_000),
                max_fee: Some((base_price + 25) * 1_000_000_000),
                max_priority_fee: Some(5 * 1_000_000_000),
                compute_units: None,
                estimated_cost_usd: Some(2.00),
                estimated_time_seconds: 5,
            },
            estimated_at: Utc::now(),
        })
    }

    /// 获取Solana Gas费估算
    async fn get_solana_gas_estimate(&self) -> Result<GasEstimate, WalletError> {
        // Solana使用compute units和lamports per compute unit

        tracing::info!("Getting gas estimate for Solana");

        Ok(GasEstimate {
            chain: "SOL".to_string(),
            slow: GasFee {
                gas_price: None,
                max_fee: None,
                max_priority_fee: None,
                compute_units: Some(200_000),
                estimated_cost_usd: Some(0.00025),
                estimated_time_seconds: 10,
            },
            standard: GasFee {
                gas_price: None,
                max_fee: None,
                max_priority_fee: None,
                compute_units: Some(200_000),
                estimated_cost_usd: Some(0.00025),
                estimated_time_seconds: 5,
            },
            fast: GasFee {
                gas_price: None,
                max_fee: None,
                max_priority_fee: None,
                compute_units: Some(400_000),
                estimated_cost_usd: Some(0.0005),
                estimated_time_seconds: 2,
            },
            instant: GasFee {
                gas_price: None,
                max_fee: None,
                max_priority_fee: None,
                compute_units: Some(600_000),
                estimated_cost_usd: Some(0.00075),
                estimated_time_seconds: 1,
            },
            estimated_at: Utc::now(),
        })
    }

    /// 记录Gas费历史
    pub async fn record_gas_price(
        &self,
        chain: Chain,
        gas_price: u64,
        network_utilization: f64,
    ) -> Result<(), WalletError> {
        sqlx::query!(
            r#"
            INSERT INTO gas_history (chain, avg_gas_price, min_gas_price, max_gas_price, network_utilization)
            VALUES ($1, $2, $2, $2, $3)
            "#,
            chain.to_string(),
            gas_price.to_string(),
            network_utilization
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(())
    }

    /// 获取Gas费历史
    pub async fn get_gas_history(
        &self,
        chain: Chain,
        hours: i64,
    ) -> Result<Vec<GasHistory>, WalletError> {
        let chain_str = chain.to_string();

        let history = sqlx::query_as!(
            GasHistory,
            r#"
            SELECT
                chain,
                timestamp,
                avg_gas_price::bigint as "avg_gas_price!",
                min_gas_price::bigint as "min_gas_price!",
                max_gas_price::bigint as "max_gas_price!",
                network_utilization
            FROM gas_history
            WHERE chain = $1
                AND timestamp >= NOW() - INTERVAL '1 hour' * $2
            ORDER BY timestamp DESC
            "#,
            chain_str,
            hours
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(history)
    }

    /// 获取Gas费优化建议
    pub async fn get_optimization_advice(
        &self,
        chain: Chain,
    ) -> Result<GasOptimizationAdvice, WalletError> {
        // 获取当前Gas费
        let current_estimate = self.get_gas_estimate(chain).await?;
        let current_price = current_estimate.standard.gas_price.unwrap_or(0);

        // 获取24小时历史平均
        let history = self.get_gas_history(chain, 24).await?;
        let avg_price = if !history.is_empty() {
            history.iter().map(|h| h.avg_gas_price).sum::<u64>() / history.len() as u64
        } else {
            current_price
        };

        // 计算网络拥堵程度
        let congestion = if current_price > avg_price * 2 {
            NetworkCongestion::VeryHigh
        } else if current_price > avg_price * 3 / 2 {
            NetworkCongestion::High
        } else if current_price > avg_price {
            NetworkCongestion::Medium
        } else {
            NetworkCongestion::Low
        };

        // 计算潜在节省
        let savings_percent = if current_price > avg_price {
            ((current_price - avg_price) as f64 / current_price as f64) * 100.0
        } else {
            0.0
        };

        // 推荐最佳发送时间 (凌晨2-4点通常Gas费较低)
        let best_time = if matches!(congestion, NetworkCongestion::High | NetworkCongestion::VeryHigh) {
            let now = Utc::now();
            let tomorrow_2am = (now + chrono::Duration::days(1))
                .date_naive()
                .and_hms_opt(2, 0, 0)
                .map(|dt| dt.and_utc());
            tomorrow_2am
        } else {
            None
        };

        Ok(GasOptimizationAdvice {
            current_gas_price: current_price,
            recommended_gas_price: avg_price,
            potential_savings_percent: savings_percent,
            best_time_to_send: best_time,
            network_congestion: congestion,
        })
    }

    /// 计算交易成本
    pub async fn calculate_transaction_cost(
        &self,
        chain: Chain,
        gas_limit: u64,
        priority: GasPriority,
    ) -> Result<TransactionCost, WalletError> {
        let estimate = self.get_gas_estimate(chain).await?;

        let gas_fee = match priority {
            GasPriority::Slow => &estimate.slow,
            GasPriority::Standard => &estimate.standard,
            GasPriority::Fast => &estimate.fast,
            GasPriority::Instant => &estimate.instant,
        };

        let gas_price = gas_fee.gas_price.unwrap_or(0);
        let total_cost = gas_price * gas_limit;

        Ok(TransactionCost {
            chain: chain.to_string(),
            gas_limit,
            gas_price,
            total_cost,
            estimated_cost_usd: gas_fee.estimated_cost_usd,
            estimated_time_seconds: gas_fee.estimated_time_seconds,
        })
    }

    /// 获取最佳Gas费设置
    pub async fn get_optimal_gas_settings(
        &self,
        chain: Chain,
        target_time_seconds: u64,
    ) -> Result<GasFee, WalletError> {
        let estimate = self.get_gas_estimate(chain).await?;

        // 根据目标时间选择合适的Gas设置
        if target_time_seconds <= 10 {
            Ok(estimate.instant)
        } else if target_time_seconds <= 60 {
            Ok(estimate.fast)
        } else if target_time_seconds <= 180 {
            Ok(estimate.standard)
        } else {
            Ok(estimate.slow)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionCost {
    pub chain: String,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub total_cost: u64,
    pub estimated_cost_usd: Option<f64>,
    pub estimated_time_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_priority() {
        let priority = GasPriority::Fast;
        assert!(matches!(priority, GasPriority::Fast));
    }

    #[test]
    fn test_network_congestion() {
        let congestion = NetworkCongestion::High;
        assert!(matches!(congestion, NetworkCongestion::High));
    }
}
