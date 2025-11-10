/**
 * 统一错误处理中间件
 *
 * Author: Aitachi
 * Email: 44158892@qq.com
 */

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Resource not found")]
    NotFound,

    #[error("Invalid input: {0}")]
    ValidationError(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("MFA verification failed")]
    MFAVerificationFailed,

    #[error("Internal server error")]
    InternalError,

    #[error("Database error")]
    DatabaseError,
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::AuthenticationFailed(_) | Self::MFAVerificationFailed => StatusCode::UNAUTHORIZED,
            Self::PermissionDenied => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::ValidationError(_) => StatusCode::BAD_REQUEST,
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::InternalError | Self::DatabaseError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_code(&self) -> &str {
        match self {
            Self::AuthenticationFailed(_) => "AUTH_001",
            Self::PermissionDenied => "AUTH_002",
            Self::NotFound => "RES_001",
            Self::ValidationError(_) => "VAL_001",
            Self::RateLimitExceeded => "RATE_001",
            Self::MFAVerificationFailed => "MFA_001",
            Self::InternalError => "SYS_001",
            Self::DatabaseError => "DB_001",
        }
    }

    pub fn user_message(&self) -> String {
        match self {
            Self::AuthenticationFailed(_) | Self::MFAVerificationFailed => {
                "认证失败,请重新登录".to_string()
            }
            Self::PermissionDenied => "您没有权限执行此操作".to_string(),
            Self::NotFound => "请求的资源不存在".to_string(),
            Self::ValidationError(msg) => format!("输入验证失败: {}", msg),
            Self::RateLimitExceeded => "请求过于频繁,请稍后再试".to_string(),
            Self::InternalError | Self::DatabaseError => {
                "服务器内部错误,请联系管理员".to_string()
            }
        }
    }

    fn log_message(&self) -> String {
        format!("{:?}", self)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 记录详细错误(内部日志)
        tracing::error!(
            error_code = self.error_code(),
            error = self.log_message(),
            "Request failed"
        );

        // 返回用户友好消息
        let body = Json(json!({
            "error": {
                "code": self.error_code(),
                "message": self.user_message(),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }
        }));

        (self.status_code(), body).into_response()
    }
}

// 转换标准错误
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!("Database error: {:?}", err);
        Self::DatabaseError
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!("Internal error: {:?}", err);
        Self::InternalError
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        Self::AuthenticationFailed(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(AppError::AuthenticationFailed("test".to_string()).error_code(), "AUTH_001");
        assert_eq!(AppError::PermissionDenied.error_code(), "AUTH_002");
        assert_eq!(AppError::NotFound.error_code(), "RES_001");
        assert_eq!(AppError::ValidationError("test".to_string()).error_code(), "VAL_001");
        assert_eq!(AppError::RateLimitExceeded.error_code(), "RATE_001");
    }

    #[test]
    fn test_status_codes() {
        assert_eq!(AppError::AuthenticationFailed("test".to_string()).status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(AppError::PermissionDenied.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(AppError::NotFound.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(AppError::RateLimitExceeded.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }
}
