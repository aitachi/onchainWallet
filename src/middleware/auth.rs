/**
 * JWT认证授权中间件
 *
 * Author: Aitachi
 * Email: 44158892@qq.com
 */

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
    body::Body,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::{Utc, Duration};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,           // 用户ID
    pub role: String,          // 角色: admin, operator, viewer
    pub exp: usize,            // 过期时间
    pub iat: usize,            // 签发时间
    pub permissions: Vec<String>,  // 权限列表
    pub session_id: String,    // 会话ID(用于主动失效)
}

pub struct JwtAuth {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
}

impl JwtAuth {
    pub fn new(secret: &str, issuer: String) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            issuer,
        }
    }

    /// 生成JWT令牌
    pub fn generate_token(
        &self,
        user_id: &str,
        role: &str,
        permissions: Vec<String>,
    ) -> Result<String> {
        let session_id = uuid::Uuid::new_v4().to_string();

        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(2))
            .unwrap()
            .timestamp() as usize;

        let claims = Claims {
            sub: user_id.to_owned(),
            role: role.to_owned(),
            exp: expiration,
            iat: Utc::now().timestamp() as usize,
            permissions,
            session_id,
        };

        let mut header = Header::default();
        header.kid = Some(self.issuer.clone());

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| anyhow::anyhow!("Failed to generate token: {}", e))
    }

    /// 验证JWT令牌
    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| anyhow::anyhow!("Invalid token: {}", e))
    }

    /// 刷新令牌
    pub fn refresh_token(&self, old_token: &str) -> Result<String> {
        let claims = self.validate_token(old_token)?;

        // 检查是否即将过期(剩余时间<15分钟)
        let now = Utc::now().timestamp() as usize;
        if claims.exp.saturating_sub(now) > 900 {
            anyhow::bail!("Token not eligible for refresh yet");
        }

        self.generate_token(&claims.sub, &claims.role, claims.permissions)
    }
}

/// JWT认证中间件
pub async fn auth_middleware(
    State(jwt_auth): State<Arc<JwtAuth>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let claims = jwt_auth
        .validate_token(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // 注入Claims到请求扩展中
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_generate_and_validate() {
        let jwt_auth = JwtAuth::new("test_secret_key_1234567890", "wallet_system".to_string());

        let token = jwt_auth.generate_token(
            "user123",
            "admin",
            vec!["withdrawal:create".to_string()],
        ).unwrap();

        let claims = jwt_auth.validate_token(&token).unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.role, "admin");
        assert!(claims.permissions.contains(&"withdrawal:create".to_string()));
    }

    #[test]
    fn test_invalid_token() {
        let jwt_auth = JwtAuth::new("test_secret_key_1234567890", "wallet_system".to_string());

        let result = jwt_auth.validate_token("invalid.token.here");
        assert!(result.is_err());
    }
}
