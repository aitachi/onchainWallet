use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use sqlx::PgPool;
use crate::models::{Result, WalletError, types::{Chain, WalletTier}};
use crate::services::blockchain::AdapterRegistry;
use crate::services::key_manager::KeyManager;

/// 钱包服务
pub struct WalletService {
    db: PgPool,
    adapters: Arc<AdapterRegistry>,
    key_manager: Arc<KeyManager>,
    // 余额缓存
    balance_cache: Arc<RwLock<HashMap<String, u64>>>,
}

impl WalletService {
    pub fn new(
        db: PgPool,
        adapters: Arc<AdapterRegistry>,
        key_manager: Arc<KeyManager>,
    ) -> Self {
        Self {
            db,
            adapters,
            key_manager,
            balance_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 创建新钱包
    pub async fn create_wallet(
        &self,
        user_id: uuid::Uuid,
        chain: Chain,
        tier: WalletTier,
        derivation_path: &str,
    ) -> Result<String> {
        // 使用适配器生成地址
        let adapter = self.adapters.get(&chain)?;
        let address = adapter.generate_address(derivation_path).await?;

        // 生成并加密私钥 (实际应该从HD钱包派生)
        let private_key = vec![0u8; 32]; // 占位符
        let encrypted_key = self.key_manager.encrypt_private_key(&private_key)?;
        let encrypted_hex = hex::encode(encrypted_key);

        // 存入数据库
        sqlx::query!(
            r#"
            INSERT INTO wallets (user_id, chain, tier, address, encrypted_private_key, derivation_path)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            user_id,
            chain.as_str(),
            match tier {
                WalletTier::Hot => "hot",
                WalletTier::Warm => "warm",
                WalletTier::Cold => "cold",
            },
            address.address,
            encrypted_hex,
            derivation_path
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        Ok(address.address)
    }

    /// 获取钱包余额
    pub async fn get_balance(&self, address: &str, chain: Chain) -> Result<u64> {
        // 先查缓存
        {
            let cache = self.balance_cache.read().await;
            if let Some(&balance) = cache.get(address) {
                return Ok(balance);
            }
        }

        // 查询链上余额
        let adapter = self.adapters.get(&chain)?;
        let balance_info = adapter.get_balance(address).await?;

        // 更新缓存
        {
            let mut cache = self.balance_cache.write().await;
            cache.insert(address.to_string(), balance_info.total);
        }

        // 更新数据库
        sqlx::query!(
            r#"
            UPDATE wallets
            SET balance = $1, updated_at = NOW()
            WHERE address = $2 AND chain = $3
            "#,
            balance_info.total.to_string(),
            address,
            chain.as_str()
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        Ok(balance_info.total)
    }

    /// 获取指定层级的所有钱包
    pub async fn get_wallets_by_tier(&self, chain: Chain, tier: WalletTier) -> Result<Vec<String>> {
        let tier_str = match tier {
            WalletTier::Hot => "hot",
            WalletTier::Warm => "warm",
            WalletTier::Cold => "cold",
        };

        let records = sqlx::query!(
            r#"
            SELECT address FROM wallets
            WHERE chain = $1 AND tier = $2 AND status = 'active'
            "#,
            chain.as_str(),
            tier_str
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        Ok(records.into_iter().map(|r| r.address).collect())
    }

    /// 检查是否需要资金调度
    pub async fn check_tier_balance(&self, chain: Chain) -> Result<TierBalanceStatus> {
        let hot_wallets = self.get_wallets_by_tier(chain, WalletTier::Hot).await?;
        let warm_wallets = self.get_wallets_by_tier(chain, WalletTier::Warm).await?;
        let cold_wallets = self.get_wallets_by_tier(chain, WalletTier::Cold).await?;

        // 计算各层级总余额
        let mut hot_total = 0u64;
        for addr in &hot_wallets {
            hot_total += self.get_balance(addr, chain).await?;
        }

        let mut warm_total = 0u64;
        for addr in &warm_wallets {
            warm_total += self.get_balance(addr, chain).await?;
        }

        let mut cold_total = 0u64;
        for addr in &cold_wallets {
            cold_total += self.get_balance(addr, chain).await?;
        }

        let total = hot_total + warm_total + cold_total;

        Ok(TierBalanceStatus {
            hot_balance: hot_total,
            warm_balance: warm_total,
            cold_balance: cold_total,
            total_balance: total,
            hot_percentage: if total > 0 { (hot_total as f64 / total as f64) * 100.0 } else { 0.0 },
            warm_percentage: if total > 0 { (warm_total as f64 / total as f64) * 100.0 } else { 0.0 },
            cold_percentage: if total > 0 { (cold_total as f64 / total as f64) * 100.0 } else { 0.0 },
        })
    }

    /// 资金调度 - 从温钱包补充热钱包
    pub async fn refill_hot_wallet(&self, chain: Chain, amount: u64) -> Result<String> {
        // 获取温钱包地址
        let warm_wallets = self.get_wallets_by_tier(chain, WalletTier::Warm).await?;
        if warm_wallets.is_empty() {
            return Err(WalletError::WalletNotFound);
        }

        // 获取热钱包地址
        let hot_wallets = self.get_wallets_by_tier(chain, WalletTier::Hot).await?;
        if hot_wallets.is_empty() {
            return Err(WalletError::WalletNotFound);
        }

        let from_addr = &warm_wallets[0];
        let to_addr = &hot_wallets[0];

        // 执行转账
        self.transfer_internal(chain, from_addr, to_addr, amount).await
    }

    /// 内部转账
    async fn transfer_internal(
        &self,
        chain: Chain,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<String> {
        // 获取适配器
        let adapter = self.adapters.get(&chain)?;

        // 检查余额
        let balance = self.get_balance(from, chain).await?;
        let fee = adapter.estimate_fee(from, to, amount).await?;

        if balance < amount + fee {
            return Err(WalletError::InsufficientBalance {
                required: amount + fee,
                available: balance,
            });
        }

        // 获取加密的私钥
        let encrypted_key = sqlx::query!(
            r#"SELECT encrypted_private_key FROM wallets WHERE address = $1 AND chain = $2"#,
            from,
            chain.as_str()
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?
        .encrypted_private_key
        .ok_or(WalletError::WalletNotFound)?;

        // 解密私钥
        let private_key = self.key_manager.decrypt_private_key(
            &hex::decode(encrypted_key).map_err(|e| WalletError::Encryption(e.to_string()))?
        )?;

        // 构建交易
        let unsigned_tx = adapter.build_transfer(from, to, amount).await?;

        // 签名
        let signed_tx = adapter.sign_transaction(&unsigned_tx, &private_key).await?;

        // 广播
        let tx_hash = adapter.broadcast(&signed_tx).await?;

        // 记录到数据库
        sqlx::query!(
            r#"
            INSERT INTO transactions (chain, tx_hash, from_address, to_address, amount, fee, tx_type, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'internal_transfer', 'pending')
            "#,
            chain.as_str(),
            tx_hash,
            from,
            to,
            amount.to_string(),
            fee.to_string()
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        // 清除缓存
        {
            let mut cache = self.balance_cache.write().await;
            cache.remove(from);
            cache.remove(to);
        }

        Ok(tx_hash)
    }
}

/// 层级余额状态
#[derive(Debug, Clone)]
pub struct TierBalanceStatus {
    pub hot_balance: u64,
    pub warm_balance: u64,
    pub cold_balance: u64,
    pub total_balance: u64,
    pub hot_percentage: f64,
    pub warm_percentage: f64,
    pub cold_percentage: f64,
}

impl TierBalanceStatus {
    /// 检查是否需要从温钱包补充热钱包
    pub fn needs_hot_refill(&self) -> bool {
        self.hot_percentage < 0.5 // 低于0.5%需要补充
    }

    /// 检查是否需要从冷钱包补充温钱包
    pub fn needs_warm_refill(&self) -> bool {
        self.warm_percentage < 3.0 // 低于3%需要补充
    }

    /// 获取建议的补充金额
    pub fn recommended_refill_amount(&self) -> u64 {
        if self.needs_hot_refill() {
            // 补充到1%
            (self.total_balance as f64 * 0.01 - self.hot_balance as f64) as u64
        } else {
            0
        }
    }
}
