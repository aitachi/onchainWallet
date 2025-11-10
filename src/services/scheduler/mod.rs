use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use sqlx::PgPool;
use crate::models::{Result, WalletError, types::{Chain, WalletTier}};
use crate::services::blockchain::AdapterRegistry;
use crate::services::wallet::WalletService;

/// 资产调度服务
pub struct AssetSchedulerService {
    db: PgPool,
    adapters: Arc<AdapterRegistry>,
    wallet_service: Arc<WalletService>,
}

impl AssetSchedulerService {
    pub fn new(
        db: PgPool,
        adapters: Arc<AdapterRegistry>,
        wallet_service: Arc<WalletService>,
    ) -> Self {
        Self {
            db,
            adapters,
            wallet_service,
        }
    }

    /// 启动自动归集服务
    pub async fn start_auto_collection(self: Arc<Self>, chain: Chain) -> Result<()> {
        tracing::info!("Starting auto collection for {:?}", chain);

        let mut interval = time::interval(Duration::from_secs(300)); // 5分钟执行一次

        loop {
            interval.tick().await;

            if let Err(e) = self.auto_collect(chain).await {
                tracing::error!("Auto collection failed for {:?}: {}", chain, e);
            }
        }
    }

    /// 自动归集
    pub async fn auto_collect(&self, chain: Chain) -> Result<()> {
        tracing::info!("Running auto collection for {:?}", chain);

        // 1. 获取所有充值地址 (非热钱包)
        let addresses = sqlx::query!(
            r#"
            SELECT address, balance FROM wallets
            WHERE chain = $1 AND status = 'active' AND tier != 'hot'
            AND user_id IS NOT NULL
            "#,
            chain.as_str()
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        // 2. 获取归集阈值
        let threshold = self.get_collection_threshold(chain).await?;

        // 3. 筛选需要归集的地址
        let mut collection_tasks = Vec::new();

        for record in addresses {
            let balance: u64 = record.balance.parse().unwrap_or(0);
            if balance > threshold {
                collection_tasks.push((record.address, balance));
            }
        }

        if collection_tasks.is_empty() {
            tracing::debug!("No addresses to collect for {:?}", chain);
            return Ok(());
        }

        tracing::info!("Found {} addresses to collect for {:?}", collection_tasks.len(), chain);

        // 4. 获取热钱包地址作为归集目标
        let hot_wallet = self.get_hot_wallet_address(chain).await?;

        // 5. 批量归集
        for (from_address, balance) in collection_tasks {
            match self.collect_to_hot_wallet(chain, &from_address, &hot_wallet, balance).await {
                Ok(tx_hash) => {
                    tracing::info!("Collected from {} to {}: {}", from_address, hot_wallet, tx_hash);
                }
                Err(e) => {
                    tracing::error!("Failed to collect from {}: {}", from_address, e);
                }
            }

            // 避免RPC过载
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        Ok(())
    }

    /// 归集到热钱包
    async fn collect_to_hot_wallet(
        &self,
        chain: Chain,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<String> {
        let adapter = self.adapters.get(&chain)?;

        // 预留Gas费
        let fee = adapter.estimate_fee(from, to, amount).await?;
        let transfer_amount = if amount > fee {
            amount - fee
        } else {
            return Err(WalletError::InsufficientBalance {
                required: fee,
                available: amount,
            });
        };

        // 执行归集 (这里简化，实际应该通过wallet_service)
        tracing::debug!("Collecting {} from {} to {}", transfer_amount, from, to);

        // 返回模拟的交易哈希
        Ok(format!("collection_{}_{}", from, chrono::Utc::now().timestamp()))
    }

    /// 启动余额监控
    pub async fn start_balance_monitoring(self: Arc<Self>, chain: Chain) -> Result<()> {
        tracing::info!("Starting balance monitoring for {:?}", chain);

        let mut interval = time::interval(Duration::from_secs(60)); // 1分钟检查一次

        loop {
            interval.tick().await;

            if let Err(e) = self.check_and_refill_balances(chain).await {
                tracing::error!("Balance monitoring failed for {:?}: {}", chain, e);
            }
        }
    }

    /// 检查并补充余额
    async fn check_and_refill_balances(&self, chain: Chain) -> Result<()> {
        // 检查层级余额
        let status = self.wallet_service.check_tier_balance(chain).await?;

        tracing::debug!(
            "Balance status for {:?}: Hot={:.2}% Warm={:.2}% Cold={:.2}%",
            chain,
            status.hot_percentage,
            status.warm_percentage,
            status.cold_percentage
        );

        // 如果热钱包余额低于阈值，从温钱包补充
        if status.needs_hot_refill() {
            let refill_amount = status.recommended_refill_amount();
            tracing::info!(
                "Hot wallet needs refill for {:?}: {} (current: {:.2}%)",
                chain,
                refill_amount,
                status.hot_percentage
            );

            match self.wallet_service.refill_hot_wallet(chain, refill_amount).await {
                Ok(tx_hash) => {
                    tracing::info!("Hot wallet refilled for {:?}: {}", chain, tx_hash);

                    // 发送告警
                    self.send_alert(
                        "hot_wallet_refill",
                        &format!("Hot wallet refilled for {:?}: {}", chain, tx_hash),
                    )
                    .await?;
                }
                Err(e) => {
                    tracing::error!("Failed to refill hot wallet for {:?}: {}", chain, e);

                    // 发送错误告警
                    self.send_alert(
                        "hot_wallet_refill_failed",
                        &format!("Failed to refill hot wallet for {:?}: {}", chain, e),
                    )
                    .await?;
                }
            }
        }

        // 如果温钱包余额低于阈值，发送告警 (需要手动从冷钱包转账)
        if status.needs_warm_refill() {
            tracing::warn!(
                "Warm wallet needs refill for {:?}: current {:.2}%",
                chain,
                status.warm_percentage
            );

            self.send_alert(
                "warm_wallet_low_balance",
                &format!(
                    "Warm wallet balance is low for {:?}: {:.2}%",
                    chain, status.warm_percentage
                ),
            )
            .await?;
        }

        Ok(())
    }

    /// 流动性优化 - 分析各链提现需求
    pub async fn optimize_liquidity(&self) -> Result<()> {
        tracing::info!("Running liquidity optimization");

        // 获取各链过去24小时的提现统计
        let chains = vec![Chain::Solana, Chain::Ethereum];

        for chain in chains {
            let stats = self.get_withdrawal_stats(chain, 24).await?;

            tracing::info!(
                "Withdrawal stats for {:?}: count={}, total={}, avg={}",
                chain,
                stats.count,
                stats.total_amount,
                stats.average_amount
            );

            // 预测未来需求 (简化版本 - 使用历史平均值)
            let predicted_demand = stats.average_amount * 2;

            // 检查当前热钱包余额
            let hot_wallets = self.wallet_service.get_wallets_by_tier(chain, WalletTier::Hot).await?;
            if !hot_wallets.is_empty() {
                let current_balance = self
                    .wallet_service
                    .get_balance(&hot_wallets[0], chain)
                    .await?;

                // 如果预测需求大于当前余额，建议补充
                if predicted_demand > current_balance {
                    let recommended_amount = predicted_demand - current_balance;
                    tracing::info!(
                        "Recommend refilling {} for {:?} (current: {}, predicted: {})",
                        recommended_amount,
                        chain,
                        current_balance,
                        predicted_demand
                    );
                }
            }
        }

        Ok(())
    }

    /// 获取提现统计
    async fn get_withdrawal_stats(&self, chain: Chain, hours: i64) -> Result<WithdrawalStats> {
        let records = sqlx::query!(
            r#"
            SELECT amount FROM withdrawals
            WHERE chain = $1
              AND created_at > NOW() - INTERVAL '1 hour' * $2
              AND status IN ('completed', 'processing')
            "#,
            chain.as_str(),
            hours
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        let amounts: Vec<u64> = records
            .iter()
            .filter_map(|r| r.amount.parse::<u64>().ok())
            .collect();

        let count = amounts.len();
        let total: u64 = amounts.iter().sum();
        let average = if count > 0 { total / count as u64 } else { 0 };

        Ok(WithdrawalStats {
            count,
            total_amount: total,
            average_amount: average,
        })
    }

    /// 获取归集阈值
    async fn get_collection_threshold(&self, chain: Chain) -> Result<u64> {
        // 根据链类型返回不同的阈值
        let threshold = match chain {
            Chain::Solana => 1_000_000_000, // 1 SOL
            Chain::Ethereum => 100_000_000_000_000_000, // 0.1 ETH
            _ => 1_000_000,
        };

        Ok(threshold)
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

    /// 发送告警
    async fn send_alert(&self, alert_type: &str, message: &str) -> Result<()> {
        tracing::warn!("ALERT [{}]: {}", alert_type, message);

        // 实际实现应该通过邮件/短信/Telegram等发送
        // 这里简化为记录日志

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct WithdrawalStats {
    count: usize,
    total_amount: u64,
    average_amount: u64,
}
