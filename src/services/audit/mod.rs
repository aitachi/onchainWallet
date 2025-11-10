use std::sync::Arc;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde_json::Value;
use crate::models::{Result, WalletError};

/// 审计服务
pub struct AuditService {
    db: PgPool,
}

impl AuditService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// 记录审计日志
    pub async fn log_event(
        &self,
        user_id: Option<Uuid>,
        event_type: &str,
        resource_type: Option<&str>,
        resource_id: Option<Uuid>,
        action: &str,
        ip_address: Option<&str>,
        request_data: Option<Value>,
        response_data: Option<Value>,
        status: Option<&str>,
    ) -> Result<()> {
        let ip_addr = ip_address.and_then(|s| s.parse().ok());

        sqlx::query!(
            r#"
            INSERT INTO audit_logs
            (user_id, event_type, resource_type, resource_id, action, ip_address, request_data, response_data, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            user_id,
            event_type,
            resource_type,
            resource_id,
            action,
            ip_addr,
            request_data,
            response_data,
            status
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        Ok(())
    }

    /// 记录提现请求
    pub async fn log_withdrawal_request(
        &self,
        user_id: Uuid,
        withdrawal_id: Uuid,
        to_address: &str,
        amount: u64,
    ) -> Result<()> {
        let request_data = serde_json::json!({
            "to_address": to_address,
            "amount": amount,
        });

        self.log_event(
            Some(user_id),
            "withdrawal",
            Some("withdrawal"),
            Some(withdrawal_id),
            "create",
            None,
            Some(request_data),
            None,
            Some("pending"),
        )
        .await
    }

    /// 记录提现完成
    pub async fn log_withdrawal_completed(
        &self,
        user_id: Uuid,
        withdrawal_id: Uuid,
        tx_hash: &str,
    ) -> Result<()> {
        let response_data = serde_json::json!({
            "tx_hash": tx_hash,
        });

        self.log_event(
            Some(user_id),
            "withdrawal",
            Some("withdrawal"),
            Some(withdrawal_id),
            "complete",
            None,
            None,
            Some(response_data),
            Some("success"),
        )
        .await
    }

    /// 记录充值
    pub async fn log_deposit(
        &self,
        user_id: Uuid,
        deposit_id: Uuid,
        from_address: &str,
        amount: u64,
        tx_hash: &str,
    ) -> Result<()> {
        let request_data = serde_json::json!({
            "from_address": from_address,
            "amount": amount,
            "tx_hash": tx_hash,
        });

        self.log_event(
            Some(user_id),
            "deposit",
            Some("deposit"),
            Some(deposit_id),
            "receive",
            None,
            Some(request_data),
            None,
            Some("success"),
        )
        .await
    }

    /// 记录钱包创建
    pub async fn log_wallet_creation(
        &self,
        user_id: Uuid,
        wallet_id: Uuid,
        chain: &str,
        address: &str,
    ) -> Result<()> {
        let request_data = serde_json::json!({
            "chain": chain,
            "address": address,
        });

        self.log_event(
            Some(user_id),
            "wallet",
            Some("wallet"),
            Some(wallet_id),
            "create",
            None,
            Some(request_data),
            None,
            Some("success"),
        )
        .await
    }

    /// 记录风控拦截
    pub async fn log_risk_rejection(
        &self,
        user_id: Uuid,
        withdrawal_id: Uuid,
        reason: &str,
        risk_score: f64,
    ) -> Result<()> {
        let response_data = serde_json::json!({
            "reason": reason,
            "risk_score": risk_score,
        });

        self.log_event(
            Some(user_id),
            "risk_control",
            Some("withdrawal"),
            Some(withdrawal_id),
            "reject",
            None,
            None,
            Some(response_data),
            Some("rejected"),
        )
        .await
    }

    /// 查询审计日志
    pub async fn query_logs(
        &self,
        user_id: Option<Uuid>,
        event_type: Option<&str>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<AuditLog>> {
        let start = start_time.unwrap_or_else(|| Utc::now() - chrono::Duration::days(7));
        let end = end_time.unwrap_or_else(Utc::now);

        let records = if let Some(uid) = user_id {
            if let Some(et) = event_type {
                sqlx::query!(
                    r#"
                    SELECT id, user_id, event_type, resource_type, resource_id, action,
                           ip_address, request_data, response_data, status, created_at
                    FROM audit_logs
                    WHERE user_id = $1 AND event_type = $2
                      AND created_at BETWEEN $3 AND $4
                    ORDER BY created_at DESC
                    LIMIT $5
                    "#,
                    uid,
                    et,
                    start,
                    end,
                    limit
                )
                .fetch_all(&self.db)
                .await
            } else {
                sqlx::query!(
                    r#"
                    SELECT id, user_id, event_type, resource_type, resource_id, action,
                           ip_address, request_data, response_data, status, created_at
                    FROM audit_logs
                    WHERE user_id = $1 AND created_at BETWEEN $2 AND $3
                    ORDER BY created_at DESC
                    LIMIT $4
                    "#,
                    uid,
                    start,
                    end,
                    limit
                )
                .fetch_all(&self.db)
                .await
            }
        } else {
            sqlx::query!(
                r#"
                SELECT id, user_id, event_type, resource_type, resource_id, action,
                       ip_address, request_data, response_data, status, created_at
                FROM audit_logs
                WHERE created_at BETWEEN $1 AND $2
                ORDER BY created_at DESC
                LIMIT $3
                "#,
                start,
                end,
                limit
            )
            .fetch_all(&self.db)
            .await
        }
        .map_err(|e| WalletError::Database(e))?;

        let logs = records
            .into_iter()
            .map(|r| AuditLog {
                id: r.id,
                user_id: r.user_id,
                event_type: r.event_type,
                resource_type: r.resource_type,
                resource_id: r.resource_id,
                action: r.action,
                ip_address: r.ip_address.map(|ip| ip.to_string()),
                request_data: r.request_data,
                response_data: r.response_data,
                status: r.status,
                created_at: r.created_at,
            })
            .collect();

        Ok(logs)
    }

    /// 生成合规报告
    pub async fn generate_compliance_report(
        &self,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<ComplianceReport> {
        // 统计提现
        let withdrawal_stats = sqlx::query!(
            r#"
            SELECT COUNT(*) as count, SUM(CAST(amount AS BIGINT)) as total
            FROM withdrawals
            WHERE created_at BETWEEN $1 AND $2
            "#,
            start_date,
            end_date
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        // 统计充值
        let deposit_stats = sqlx::query!(
            r#"
            SELECT COUNT(*) as count, SUM(CAST(amount AS BIGINT)) as total
            FROM deposits
            WHERE created_at BETWEEN $1 AND $2
            "#,
            start_date,
            end_date
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        // 统计风控拦截
        let risk_rejections = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM withdrawals
            WHERE created_at BETWEEN $1 AND $2 AND status = 'rejected'
            "#,
            start_date,
            end_date
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e))?;

        Ok(ComplianceReport {
            period_start: start_date,
            period_end: end_date,
            total_withdrawals: withdrawal_stats.count.unwrap_or(0),
            total_withdrawal_amount: withdrawal_stats.total.unwrap_or(0) as u64,
            total_deposits: deposit_stats.count.unwrap_or(0),
            total_deposit_amount: deposit_stats.total.unwrap_or(0) as u64,
            risk_rejections: risk_rejections.count.unwrap_or(0),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub action: String,
    pub ip_address: Option<String>,
    pub request_data: Option<Value>,
    pub response_data: Option<Value>,
    pub status: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ComplianceReport {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_withdrawals: i64,
    pub total_withdrawal_amount: u64,
    pub total_deposits: i64,
    pub total_deposit_amount: u64,
    pub risk_rejections: i64,
}
