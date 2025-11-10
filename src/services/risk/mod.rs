use std::sync::Arc;
use sqlx::PgPool;
use std::collections::HashMap;
use tokio::sync::RwLock;
use crate::models::{Result, WalletError, types::RiskDecision};
use crate::services::withdrawal::WithdrawalRequest;

/// 风控服务
pub struct RiskControlService {
    db: PgPool,
    // 黑名单缓存
    blacklist_cache: Arc<RwLock<HashMap<String, String>>>,
    // 风控规则缓存
    rules_cache: Arc<RwLock<Vec<RiskRule>>>,
}

#[derive(Debug, Clone)]
pub struct RiskRule {
    pub id: uuid::Uuid,
    pub name: String,
    pub rule_type: String,
    pub threshold: f64,
    pub action: String,
    pub priority: i32,
}

impl RiskControlService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            blacklist_cache: Arc::new(RwLock::new(HashMap::new())),
            rules_cache: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 检查提现请求
    pub async fn check_withdrawal(&self, req: &WithdrawalRequest) -> Result<RiskDecision> {
        let mut risk_score = 0.0;
        let mut warnings = Vec::new();

        // 1. 黑名单检查
        if self.is_blacklisted(&req.to_address).await? {
            return Ok(RiskDecision::Reject {
                reason: format!("Address {} is blacklisted", req.to_address),
            });
        }

        // 2. 金额检查
        let daily_limit = std::env::var("WITHDRAWAL_DAILY_LIMIT")
            .unwrap_or_else(|_| "100000000000".to_string())
            .parse::<u64>()
            .unwrap_or(100_000_000_000);

        if req.amount > daily_limit {
            risk_score += 0.5;
            warnings.push(format!("Amount exceeds daily limit: {}", daily_limit));
        }

        // 3. 用户历史检查
        let user_history = self.get_user_withdrawal_history(req.user_id, 24).await?;

        // 检查24小时内提现次数
        if user_history.count >= 10 {
            risk_score += 0.3;
            warnings.push("High withdrawal frequency in last 24 hours".to_string());
        }

        // 检查金额异常
        if user_history.average_amount > 0 && req.amount > (user_history.average_amount as f64 * 5.0) as u64 {
            risk_score += 0.3;
            warnings.push("Unusual withdrawal amount".to_string());
        }

        // 4. 地址信誉检查
        let address_reputation = self.check_address_reputation(&req.to_address).await?;
        if address_reputation < 0.5 {
            risk_score += 0.2;
            warnings.push("Low reputation address".to_string());
        }

        // 5. 规则引擎检查
        let rule_result = self.apply_rules(req, risk_score).await?;
        risk_score = rule_result.0;
        warnings.extend(rule_result.1);

        // 6. 决策
        if risk_score >= 0.8 {
            Ok(RiskDecision::Reject {
                reason: warnings.join("; "),
            })
        } else if risk_score >= 0.5 {
            Ok(RiskDecision::ManualReview {
                score: risk_score,
                warnings,
            })
        } else {
            Ok(RiskDecision::Approve)
        }
    }

    /// 检查地址是否在黑名单
    pub async fn is_blacklisted(&self, address: &str) -> Result<bool> {
        // 先查缓存
        {
            let cache = self.blacklist_cache.read().await;
            if cache.contains_key(address) {
                return Ok(true);
            }
        }

        // 查数据库
        let record = sqlx::query!(
            r#"
            SELECT reason FROM blacklist
            WHERE address = $1 AND (expires_at IS NULL OR expires_at > NOW())
            "#,
            address
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        if let Some(r) = record {
            // 更新缓存
            let mut cache = self.blacklist_cache.write().await;
            cache.insert(address.to_string(), r.reason.unwrap_or_default());
            return Ok(true);
        }

        Ok(false)
    }

    /// 添加到黑名单
    pub async fn add_to_blacklist(
        &self,
        address: String,
        chain: String,
        reason: String,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO blacklist (address, chain, reason, expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (address) DO UPDATE SET
                reason = EXCLUDED.reason,
                expires_at = EXCLUDED.expires_at
            "#,
            address,
            chain,
            reason,
            expires_at
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        // 清除缓存
        let mut cache = self.blacklist_cache.write().await;
        cache.insert(address, reason);

        Ok(())
    }

    /// 获取用户提现历史
    async fn get_user_withdrawal_history(
        &self,
        user_id: uuid::Uuid,
        hours: i64,
    ) -> Result<UserWithdrawalHistory> {
        let records = sqlx::query!(
            r#"
            SELECT amount FROM withdrawals
            WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour' * $2
            AND status IN ('approved', 'processing', 'completed')
            "#,
            user_id,
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

        Ok(UserWithdrawalHistory {
            count,
            total_amount: total,
            average_amount: average,
        })
    }

    /// 检查地址信誉
    async fn check_address_reputation(&self, _address: &str) -> Result<f64> {
        // 简化实现 - 实际应该查询外部API或内部数据库
        // 返回0.0-1.0之间的信誉分数
        Ok(0.8)
    }

    /// 应用风控规则
    async fn apply_rules(
        &self,
        req: &WithdrawalRequest,
        mut risk_score: f64,
    ) -> Result<(f64, Vec<String>)> {
        let mut warnings = Vec::new();

        // 从缓存获取规则
        let rules = {
            let cache = self.rules_cache.read().await;
            cache.clone()
        };

        for rule in rules {
            match rule.rule_type.as_str() {
                "amount_limit" => {
                    if req.amount as f64 > rule.threshold {
                        risk_score += 0.2;
                        warnings.push(format!("Triggered rule: {}", rule.name));
                    }
                }
                "daily_count" => {
                    // 实现每日次数限制检查
                }
                "velocity" => {
                    // 实现速率限制检查
                }
                _ => {}
            }
        }

        Ok((risk_score, warnings))
    }

    /// 加载规则到缓存
    pub async fn load_rules(&self) -> Result<()> {
        let records = sqlx::query!(
            r#"
            SELECT id, name, rule_type, priority, action
            FROM risk_rules
            WHERE enabled = true
            ORDER BY priority DESC
            "#
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        let rules: Vec<RiskRule> = records
            .into_iter()
            .map(|r| RiskRule {
                id: r.id,
                name: r.name,
                rule_type: r.rule_type,
                threshold: 0.0, // 从condition JSON解析
                action: r.action,
                priority: r.priority,
            })
            .collect();

        let mut cache = self.rules_cache.write().await;
        *cache = rules;

        tracing::info!("Loaded {} risk rules", cache.len());

        Ok(())
    }

    /// 机器学习异常检测 (简化版)
    pub async fn detect_anomaly(&self, req: &WithdrawalRequest) -> Result<f64> {
        // 特征提取
        let features = vec![
            req.amount as f64,
            chrono::Utc::now().timestamp() as f64,
        ];

        // 简化的异常检测 - 实际应该使用ML模型
        let score = if req.amount > 1_000_000_000 {
            0.8
        } else {
            0.2
        };

        Ok(score)
    }

    /// 批量检查地址
    pub async fn batch_check_addresses(&self, addresses: Vec<String>) -> Result<Vec<(String, bool)>> {
        let mut results = Vec::new();

        for addr in addresses {
            let is_blacklisted = self.is_blacklisted(&addr).await?;
            results.push((addr, is_blacklisted));
        }

        Ok(results)
    }
}

#[derive(Debug, Clone)]
struct UserWithdrawalHistory {
    count: usize,
    total_amount: u64,
    average_amount: u64,
}
