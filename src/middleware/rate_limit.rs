/**
 * 多级速率限制中间件
 *
 * Author: Aitachi
 * Email: 44158892@qq.com
 */

use axum::{
    extract::{Request, State, ConnectInfo},
    http::StatusCode,
    middleware::Next,
    response::Response,
    body::Body,
};
use std::sync::Arc;
use std::net::SocketAddr;
use redis::Client as RedisClient;
use chrono::Utc;
use anyhow::Result;

pub struct MultiLevelRateLimiter {
    redis: Arc<RedisClient>,
}

impl MultiLevelRateLimiter {
    pub fn new(redis: Arc<RedisClient>) -> Self {
        Self { redis }
    }

    /// IP级别限制: 1000 req/hour
    pub async fn check_ip_limit(&self, ip: &str) -> Result<bool> {
        let key = format!("rate_limit:ip:{}", ip);
        let mut conn = self.redis.get_connection()?;

        let count: u64 = redis::cmd("GET")
            .arg(&key)
            .query(&mut conn)
            .unwrap_or(0);

        if count >= 1000 {
            return Ok(false);
        }

        redis::cmd("INCR")
            .arg(&key)
            .query(&mut conn)?;

        redis::cmd("EXPIRE")
            .arg(&key)
            .arg(3600)
            .query(&mut conn)?;

        Ok(true)
    }

    /// 用户级别限制: 5000 req/hour
    pub async fn check_user_limit(&self, user_id: &str) -> Result<bool> {
        let key = format!("rate_limit:user:{}", user_id);
        let mut conn = self.redis.get_connection()?;

        let count: u64 = redis::cmd("GET")
            .arg(&key)
            .query(&mut conn)
            .unwrap_or(0);

        if count >= 5000 {
            return Ok(false);
        }

        redis::cmd("INCR").arg(&key).query(&mut conn)?;
        redis::cmd("EXPIRE").arg(&key).arg(3600).query(&mut conn)?;

        Ok(true)
    }

    /// 操作级别限制: 提现10次/day
    pub async fn check_operation_limit(
        &self,
        user_id: &str,
        operation: &str,
    ) -> Result<bool> {
        let date = Utc::now().format("%Y%m%d").to_string();
        let key = format!("rate_limit:{}:{}:{}", user_id, operation, date);
        let mut conn = self.redis.get_connection()?;

        let count: u64 = redis::cmd("GET")
            .arg(&key)
            .query(&mut conn)
            .unwrap_or(0);

        let limit = match operation {
            "withdrawal" => 10,
            "wallet_create" => 5,
            _ => 100,
        };

        if count >= limit {
            return Ok(false);
        }

        redis::cmd("INCR").arg(&key).query(&mut conn)?;
        redis::cmd("EXPIRE").arg(&key).arg(86400).query(&mut conn)?;

        Ok(true)
    }
}

/// 速率限制中间件
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<MultiLevelRateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = addr.ip().to_string();

    // 检查IP限制
    if !limiter.check_ip_limit(&ip)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        tracing::warn!("Rate limit exceeded for IP: {}", ip);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // 如果有JWT,检查用户限制
    if let Some(claims) = req.extensions().get::<crate::middleware::auth::Claims>() {
        if !limiter.check_user_limit(&claims.sub)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            tracing::warn!("Rate limit exceeded for user: {}", claims.sub);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_key_format() {
        let ip = "192.168.1.1";
        let key = format!("rate_limit:ip:{}", ip);
        assert_eq!(key, "rate_limit:ip:192.168.1.1");

        let user_id = "user123";
        let key = format!("rate_limit:user:{}", user_id);
        assert_eq!(key, "rate_limit:user:user123");

        let operation = "withdrawal";
        let date = "20250110";
        let key = format!("rate_limit:{}:{}:{}", user_id, operation, date);
        assert_eq!(key, "rate_limit:user123:withdrawal:20250110");
    }
}
