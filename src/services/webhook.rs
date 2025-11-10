// Webhook通知服务
use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use reqwest::Client;

use crate::models::types::WalletError;

/// Webhook事件类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    DepositReceived,
    WithdrawalCompleted,
    TransactionConfirmed,
    BalanceLow,
    RiskAlert,
    Custom(String),
}

/// Webhook配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub id: Uuid,
    pub user_id: Uuid,
    pub url: String,
    pub secret: String,
    pub events: Vec<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Webhook负载
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_type: String,
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
}

/// Webhook服务
pub struct WebhookService {
    db: PgPool,
    client: Client,
}

impl WebhookService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            client: Client::new(),
        }
    }

    /// 创建Webhook
    pub async fn create_webhook(
        &self,
        user_id: Uuid,
        url: String,
        events: Vec<String>,
    ) -> Result<WebhookConfig, WalletError> {
        let id = Uuid::new_v4();
        let secret = format!("whsec_{}", uuid::Uuid::new_v4());

        let webhook = sqlx::query_as!(
            WebhookConfig,
            r#"
            INSERT INTO webhooks (id, user_id, url, secret, events, is_active)
            VALUES ($1, $2, $3, $4, $5, true)
            RETURNING id, user_id, url, secret, events as "events!", is_active, created_at
            "#,
            id,
            user_id,
            url,
            secret,
            &events
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(webhook)
    }

    /// 发送Webhook通知
    pub async fn send_webhook(
        &self,
        user_id: Uuid,
        event_type: WebhookEventType,
        data: serde_json::Value,
    ) -> Result<(), WalletError> {
        let event_type_str = match &event_type {
            WebhookEventType::DepositReceived => "deposit_received",
            WebhookEventType::WithdrawalCompleted => "withdrawal_completed",
            WebhookEventType::TransactionConfirmed => "transaction_confirmed",
            WebhookEventType::BalanceLow => "balance_low",
            WebhookEventType::RiskAlert => "risk_alert",
            WebhookEventType::Custom(s) => s.as_str(),
        };

        // 获取用户的所有激活的Webhook
        let webhooks = sqlx::query_as!(
            WebhookConfig,
            r#"
            SELECT id, user_id, url, secret, events as "events!", is_active, created_at
            FROM webhooks
            WHERE user_id = $1 AND is_active = true AND $2 = ANY(events)
            "#,
            user_id,
            event_type_str
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        let payload = WebhookPayload {
            event_type: event_type_str.to_string(),
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            data,
        };

        for webhook in webhooks {
            self.deliver_webhook(&webhook, &payload).await.ok();
        }

        Ok(())
    }

    /// 投递Webhook
    async fn deliver_webhook(
        &self,
        webhook: &WebhookConfig,
        payload: &WebhookPayload,
    ) -> Result<(), WalletError> {
        // 生成签名
        let signature = self.generate_signature(&webhook.secret, payload);

        let response = self.client
            .post(&webhook.url)
            .header("X-Webhook-Signature", signature)
            .header("Content-Type", "application/json")
            .json(payload)
            .send()
            .await
            .map_err(|e| WalletError::Internal(format!("Webhook delivery failed: {}", e)))?;

        // 记录投递结果
        let status = if response.status().is_success() {
            "delivered"
        } else {
            "failed"
        };

        sqlx::query!(
            r#"
            INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status, response_status)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::new_v4(),
            webhook.id,
            payload.event_type,
            serde_json::to_value(payload).unwrap(),
            status,
            response.status().as_u16() as i32
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(())
    }

    /// 生成Webhook签名
    fn generate_signature(&self, secret: &str, payload: &WebhookPayload) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let payload_str = serde_json::to_string(payload).unwrap_or_default();
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(payload_str.as_bytes());
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    /// 获取用户的Webhooks
    pub async fn get_webhooks(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WebhookConfig>, WalletError> {
        let webhooks = sqlx::query_as!(
            WebhookConfig,
            r#"
            SELECT id, user_id, url, secret, events as "events!", is_active, created_at
            FROM webhooks
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        Ok(webhooks)
    }

    /// 删除Webhook
    pub async fn delete_webhook(
        &self,
        webhook_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), WalletError> {
        let result = sqlx::query!(
            "DELETE FROM webhooks WHERE id = $1 AND user_id = $2",
            webhook_id,
            user_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| WalletError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(WalletError::NotFound("Webhook不存在".to_string()));
        }

        Ok(())
    }
}
