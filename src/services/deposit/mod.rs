use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use sqlx::PgPool;
use std::collections::HashSet;
use crate::models::{Result, WalletError, types::Chain};
use crate::services::blockchain::AdapterRegistry;

/// 充值监听服务
pub struct DepositMonitorService {
    db: PgPool,
    adapters: Arc<AdapterRegistry>,
    // 正在监听的地址
    monitored_addresses: Arc<RwLock<HashSet<String>>>,
    // 已处理的交易哈希
    processed_txs: Arc<RwLock<HashSet<String>>>,
}

impl DepositMonitorService {
    pub fn new(db: PgPool, adapters: Arc<AdapterRegistry>) -> Self {
        Self {
            db,
            adapters,
            monitored_addresses: Arc::new(RwLock::new(HashSet::new())),
            processed_txs: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// 添加监听地址
    pub async fn add_address(&self, address: String) {
        let mut addresses = self.monitored_addresses.write().await;
        addresses.insert(address);
    }

    /// 移除监听地址
    pub async fn remove_address(&self, address: &str) {
        let mut addresses = self.monitored_addresses.write().await;
        addresses.remove(address);
    }

    /// 启动监听服务
    pub async fn start(self: Arc<Self>, chain: Chain) -> Result<()> {
        tracing::info!("Starting deposit monitor for {:?}", chain);

        let mut interval = time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            if let Err(e) = self.scan_deposits(chain).await {
                tracing::error!("Failed to scan deposits for {:?}: {}", chain, e);
            }
        }
    }

    /// 扫描充值
    async fn scan_deposits(&self, chain: Chain) -> Result<()> {
        let addresses: Vec<String> = {
            let monitored = self.monitored_addresses.read().await;
            monitored.iter().cloned().collect()
        };

        if addresses.is_empty() {
            return Ok(());
        }

        let adapter = self.adapters.get(&chain)?;

        for address in addresses {
            // 获取最新交易（这里简化为查询余额变化）
            match adapter.get_balance(&address).await {
                Ok(balance_info) => {
                    // 检查数据库中的余额
                    let db_balance = sqlx::query!(
                        r#"SELECT balance FROM wallets WHERE address = $1 AND chain = $2"#,
                        address,
                        chain.as_str()
                    )
                    .fetch_optional(&self.db)
                    .await
                    .map_err(|e| WalletError::Database(e))?;

                    if let Some(record) = db_balance {
                        let old_balance: u64 = record.balance.parse().unwrap_or(0);
                        let new_balance = balance_info.total;

                        // 如果余额增加，记录为充值
                        if new_balance > old_balance {
                            let amount = new_balance - old_balance;
                            self.record_deposit(&address, chain, amount).await?;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to get balance for {}: {}", address, e);
                }
            }
        }

        Ok(())
    }

    /// 记录充值
    async fn record_deposit(&self, address: &str, chain: Chain, amount: u64) -> Result<()> {
        // 查找用户ID
        let wallet = sqlx::query!(
            r#"SELECT user_id FROM wallets WHERE address = $1 AND chain = $2"#,
            address,
            chain.as_str()
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        if let Some(wallet_record) = wallet {
            if let Some(user_id) = wallet_record.user_id {
                // 生成交易哈希占位符
                let tx_hash = format!("deposit_{}_{}_{}", chain.as_str(), address, chrono::Utc::now().timestamp());

                // 检查是否已处理
                {
                    let processed = self.processed_txs.read().await;
                    if processed.contains(&tx_hash) {
                        return Ok(());
                    }
                }

                // 记录充值
                sqlx::query!(
                    r#"
                    INSERT INTO deposits (user_id, chain, from_address, to_address, amount, tx_hash, status, confirmations)
                    VALUES ($1, $2, 'unknown', $3, $4, $5, 'pending', 0)
                    "#,
                    user_id,
                    chain.as_str(),
                    address,
                    amount.to_string(),
                    tx_hash
                )
                .execute(&self.db)
                .await
                .map_err(|e| WalletError::Database(e))?;

                // 标记为已处理
                {
                    let mut processed = self.processed_txs.write().await;
                    processed.insert(tx_hash.clone());
                }

                // 更新钱包余额
                sqlx::query!(
                    r#"
                    UPDATE wallets
                    SET balance = $1, updated_at = NOW()
                    WHERE address = $2 AND chain = $3
                    "#,
                    amount.to_string(),
                    address,
                    chain.as_str()
                )
                .execute(&self.db)
                .await
                .map_err(|e| WalletError::Database(e))?;

                tracing::info!("Recorded deposit: {} {} to {}", amount, chain.as_str(), address);
            }
        }

        Ok(())
    }

    /// 确认充值
    pub async fn confirm_deposit(&self, tx_hash: &str, confirmations: i32) -> Result<()> {
        let status = if confirmations >= 6 { "confirmed" } else { "pending" };

        sqlx::query!(
            r#"
            UPDATE deposits
            SET confirmations = $1, status = $2, confirmed_at = CASE WHEN $2 = 'confirmed' THEN NOW() ELSE confirmed_at END
            WHERE tx_hash = $3
            "#,
            confirmations,
            status,
            tx_hash
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        Ok(())
    }

    /// 从数据库加载所有需要监听的地址
    pub async fn load_addresses_from_db(&self, chain: Chain) -> Result<()> {
        let records = sqlx::query!(
            r#"SELECT address FROM wallets WHERE chain = $1 AND status = 'active' AND tier = 'hot'"#,
            chain.as_str()
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        let mut addresses = self.monitored_addresses.write().await;
        for record in records {
            addresses.insert(record.address);
        }

        tracing::info!("Loaded {} addresses for {:?} monitoring", addresses.len(), chain);

        Ok(())
    }
}
