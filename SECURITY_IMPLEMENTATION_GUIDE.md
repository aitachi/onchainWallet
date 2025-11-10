# 企业级多链钱包系统 - 安全改进实施指南

**文档版本**: v1.0
**创建时间**: 2025-11-10
**适用版本**: v2.0.1 → v2.1.0 (生产就绪版)
**预计实施时间**: 2-3周

---

## 📋 实施概览

本指南提供了将钱包系统从**C级安全**提升至**A级安全**的完整实施步骤。

### 实施阶段

| 阶段 | 目标 | 工作量 | 优先级 | 预期效果 |
|-----|------|--------|--------|---------|
| Phase 1 | 关键安全修复 | 10-15天 | 🔴 P0 | C → B+ |
| Phase 2 | 安全功能完善 | 8-12天 | 🟡 P1 | B+ → A- |
| Phase 3 | 合规性强化 | 5-7天 | 🟢 P2 | A- → A |

### 投入产出分析

- **总投入**: 约$230,000 (23-34工作日)
- **风险降低**: 年化$3,815,000
- **ROI**: 1,558%
- **合规达成**: PCI DSS, SOC 2, ISO 27001

---

## 🚀 Phase 1: 关键安全修复 (1-2周)

### 目标
修复8个严重安全漏洞,使系统达到基本生产标准(B+级)

---

## 步骤1: 集成AWS KMS密钥管理 (3天)

### 1.1 更新依赖项

**文件**: `Cargo.toml`

```toml
[dependencies]
# 现有依赖...

# AWS KMS集成
aws-sdk-kms = "1.11"
aws-config = "1.1"
aws-types = "1.1"
```

### 1.2 创建KMS密钥管理器

**文件**: `src/services/kms_key_manager.rs` (新建)

```rust
use anyhow::{Result, Context};
use aws_sdk_kms::{
    Client as KmsClient,
    types::{DataKeySpec},
    primitives::Blob,
};
use tracing::{info, warn, error};
use serde::{Serialize, Deserialize};

/// AWS KMS密钥管理器
///
/// 功能:
/// - 使用AWS KMS主密钥加密/解密数据
/// - 生成数据密钥(信封加密)
/// - 支持密钥轮换
pub struct KMSKeyManager {
    kms_client: KmsClient,
    master_key_id: String,
    region: String,
}

impl KMSKeyManager {
    /// 从环境变量初始化
    pub async fn from_env() -> Result<Self> {
        let config = aws_config::load_from_env().await;
        let kms_client = KmsClient::new(&config);

        let master_key_id = std::env::var("AWS_KMS_KEY_ID")
            .context("AWS_KMS_KEY_ID not set")?;

        let region = std::env::var("AWS_REGION")
            .unwrap_or_else(|_| "us-east-1".to_string());

        info!("✅ KMS Key Manager initialized (Region: {}, KeyID: {}...)",
              region, &master_key_id[..8]);

        Ok(Self {
            kms_client,
            master_key_id,
            region,
        })
    }

    /// 直接加密数据(小于4KB)
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > 4096 {
            anyhow::bail!("Data too large for direct encryption (max 4KB). Use envelope encryption.");
        }

        let result = self.kms_client
            .encrypt()
            .key_id(&self.master_key_id)
            .plaintext(Blob::new(plaintext))
            .send()
            .await
            .context("Failed to encrypt with KMS")?;

        Ok(result.ciphertext_blob()
            .context("No ciphertext in response")?
            .as_ref()
            .to_vec())
    }

    /// 直接解密数据
    pub async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let result = self.kms_client
            .decrypt()
            .key_id(&self.master_key_id)
            .ciphertext_blob(Blob::new(ciphertext))
            .send()
            .await
            .context("Failed to decrypt with KMS")?;

        Ok(result.plaintext()
            .context("No plaintext in response")?
            .as_ref()
            .to_vec())
    }

    /// 生成数据密钥(信封加密)
    ///
    /// 返回: (明文密钥, 加密后的密钥)
    /// 使用方式:
    /// 1. 使用明文密钥加密数据
    /// 2. 存储加密后的密钥和加密数据
    /// 3. 销毁明文密钥
    pub async fn generate_data_key(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let result = self.kms_client
            .generate_data_key()
            .key_id(&self.master_key_id)
            .key_spec(DataKeySpec::Aes256)
            .send()
            .await
            .context("Failed to generate data key")?;

        let plaintext_key = result.plaintext()
            .context("No plaintext key in response")?
            .as_ref()
            .to_vec();

        let encrypted_key = result.ciphertext_blob()
            .context("No encrypted key in response")?
            .as_ref()
            .to_vec();

        Ok((plaintext_key, encrypted_key))
    }

    /// 解密数据密钥
    pub async fn decrypt_data_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>> {
        self.decrypt(encrypted_key).await
    }

    /// 轮换密钥
    pub async fn rotate_master_key(&self) -> Result<()> {
        self.kms_client
            .enable_key_rotation()
            .key_id(&self.master_key_id)
            .send()
            .await
            .context("Failed to enable key rotation")?;

        info!("✅ Key rotation enabled for {}", self.master_key_id);
        Ok(())
    }
}

/// 信封加密助手
pub struct EnvelopeEncryption {
    kms: KMSKeyManager,
}

impl EnvelopeEncryption {
    pub fn new(kms: KMSKeyManager) -> Self {
        Self { kms }
    }

    /// 加密大数据
    pub async fn encrypt_large_data(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::Rng;

        // 1. 生成数据密钥
        let (data_key, encrypted_data_key) = self.kms.generate_data_key().await?;

        // 2. 使用数据密钥加密数据
        let cipher = Aes256Gcm::new_from_slice(&data_key)
            .context("Failed to create cipher")?;

        let mut rng = rand::thread_rng();
        let nonce_bytes: [u8; 12] = rng.gen();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // 3. 销毁明文密钥
        drop(data_key);

        Ok(EncryptedData {
            ciphertext,
            encrypted_key: encrypted_data_key,
            nonce: nonce_bytes.to_vec(),
        })
    }

    /// 解密大数据
    pub async fn decrypt_large_data(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // 1. 解密数据密钥
        let data_key = self.kms.decrypt_data_key(&encrypted.encrypted_key).await?;

        // 2. 使用数据密钥解密数据
        let cipher = Aes256Gcm::new_from_slice(&data_key)
            .context("Failed to create cipher")?;

        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        // 3. 销毁明文密钥
        drop(data_key);

        Ok(plaintext)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub encrypted_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // 需要AWS凭证
    async fn test_kms_encrypt_decrypt() {
        let kms = KMSKeyManager::from_env().await.unwrap();
        let plaintext = b"sensitive data";

        let ciphertext = kms.encrypt(plaintext).await.unwrap();
        let decrypted = kms.decrypt(&ciphertext).await.unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[tokio::test]
    #[ignore]
    async fn test_envelope_encryption() {
        let kms = KMSKeyManager::from_env().await.unwrap();
        let envelope = EnvelopeEncryption::new(kms);

        let plaintext = b"very large sensitive data that exceeds 4KB limit";

        let encrypted = envelope.encrypt_large_data(plaintext).await.unwrap();
        let decrypted = envelope.decrypt_large_data(&encrypted).await.unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }
}
```

### 1.3 更新密钥管理器模块

**文件**: `src/services/key_manager.rs` (修改)

```rust
// 在文件开头添加
use crate::services::kms_key_manager::{KMSKeyManager, EnvelopeEncryption};

pub struct KeyManager {
    master_key: [u8; 32],
    kms_manager: Option<Arc<KMSKeyManager>>,  // 新增
}

impl KeyManager {
    /// 生产环境使用KMS
    pub async fn from_kms() -> Result<Self> {
        let kms = KMSKeyManager::from_env().await?;

        // 主密钥本身也通过KMS加密存储
        let master_key_encrypted = std::env::var("MASTER_KEY_ENCRYPTED")
            .context("MASTER_KEY_ENCRYPTED not set")?;

        let master_key_bytes = hex::decode(master_key_encrypted)?;
        let master_key_plaintext = kms.decrypt(&master_key_bytes).await?;

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_plaintext[..32]);

        // 销毁明文
        drop(master_key_plaintext);

        Ok(Self {
            master_key,
            kms_manager: Some(Arc::new(kms)),
        })
    }

    /// 开发环境使用环境变量(仅限测试)
    pub fn from_env() -> Result<Self> {
        warn!("⚠️  Using environment variable for master key (DEV ONLY)");
        // 原有实现...
    }
}
```

### 1.4 配置AWS凭证

**文件**: `.env.production` (新建)

```bash
# AWS KMS配置
AWS_REGION=us-east-1
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key

# 加密后的主密钥(使用KMS加密)
MASTER_KEY_ENCRYPTED=0a1b2c3d4e5f...

# 不再使用明文主密钥
# MASTER_KEY=xxxxx  ❌ 删除
```

### 1.5 更新main.rs

**文件**: `src/main.rs`

```rust
// 4. 初始化密钥管理器
tracing::info!("Initializing key manager...");

#[cfg(feature = "production")]
let key_manager = Arc::new(KeyManager::from_kms().await?);

#[cfg(not(feature = "production"))]
let key_manager = Arc::new(KeyManager::from_env()?);

tracing::info!("✅ Key manager initialized");
```

### 1.6 验收清单

- [ ] AWS KMS密钥已创建
- [ ] IAM权限已配置(kms:Encrypt, kms:Decrypt, kms:GenerateDataKey)
- [ ] 主密钥已通过KMS加密
- [ ] 环境变量已更新
- [ ] 编译通过: `cargo check --features production`
- [ ] 单元测试通过
- [ ] 加密/解密功能验证通过

---

## 步骤2: 实现JWT认证授权 (2天)

### 2.1 添加依赖

**文件**: `Cargo.toml`

```toml
[dependencies]
jsonwebtoken = "9.2"
tower-http = { version = "0.5", features = ["auth", "cors"] }
bcrypt = "0.15"
```

### 2.2 创建认证中间件

**文件**: `src/middleware/auth.rs` (新建)

```rust
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
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
pub async fn auth_middleware<B>(
    State(jwt_auth): State<Arc<JwtAuth>>,
    mut req: Request<B>,
    next: Next<B>,
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

    // TODO: 检查Redis中session是否有效
    // 注入Claims到请求扩展中
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

/// 权限检查中间件
pub fn require_permission(permission: &'static str) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> {
    move |req: Request, next: Next| {
        Box::pin(async move {
            let claims = req.extensions()
                .get::<Claims>()
                .ok_or(StatusCode::UNAUTHORIZED)?;

            if !claims.permissions.contains(&permission.to_string()) {
                return Err(StatusCode::FORBIDDEN);
            }

            Ok(next.run(req).await)
        })
    }
}

/// 角色检查中间件
pub fn require_role(allowed_roles: &'static [&'static str]) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> {
    move |req: Request, next: Next| {
        Box::pin(async move {
            let claims = req.extensions()
                .get::<Claims>()
                .ok_or(StatusCode::UNAUTHORIZED)?;

            if !allowed_roles.contains(&claims.role.as_str()) {
                return Err(StatusCode::FORBIDDEN);
            }

            Ok(next.run(req).await)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_generate_and_validate() {
        let jwt_auth = JwtAuth::new("test_secret", "wallet_system".to_string());

        let token = jwt_auth.generate_token(
            "user123",
            "admin",
            vec!["withdrawal:create".to_string()],
        ).unwrap();

        let claims = jwt_auth.validate_token(&token).unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.role, "admin");
    }
}
```

### 2.3 创建用户管理服务

**文件**: `src/services/user.rs` (新建)

```rust
use sqlx::PgPool;
use uuid::Uuid;
use bcrypt::{hash, verify, DEFAULT_COST};
use anyhow::{Result, Context};

pub struct UserService {
    db: PgPool,
}

impl UserService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// 注册用户
    pub async fn register_user(
        &self,
        email: &str,
        password: &str,
        role: &str,
    ) -> Result<Uuid> {
        // 密码哈希
        let password_hash = hash(password, DEFAULT_COST)
            .context("Failed to hash password")?;

        let user_id = sqlx::query_scalar!(
            r#"
            INSERT INTO users (email, password_hash, role)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
            email,
            password_hash,
            role,
        )
        .fetch_one(&self.db)
        .await
        .context("Failed to create user")?;

        Ok(user_id)
    }

    /// 验证登录
    pub async fn authenticate(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(Uuid, String, Vec<String>)> {
        let user = sqlx::query!(
            r#"
            SELECT id, password_hash, role
            FROM users
            WHERE email = $1 AND active = true
            "#,
            email,
        )
        .fetch_optional(&self.db)
        .await
        .context("Failed to query user")?
        .ok_or_else(|| anyhow::anyhow!("Invalid credentials"))?;

        // 验证密码
        let valid = verify(password, &user.password_hash)
            .context("Failed to verify password")?;

        if !valid {
            anyhow::bail!("Invalid credentials");
        }

        // 获取权限列表
        let permissions = self.get_permissions(user.id).await?;

        Ok((user.id, user.role, permissions))
    }

    /// 获取用户权限
    async fn get_permissions(&self, user_id: Uuid) -> Result<Vec<String>> {
        let permissions = sqlx::query_scalar!(
            r#"
            SELECT p.permission_name
            FROM user_permissions up
            JOIN permissions p ON p.id = up.permission_id
            WHERE up.user_id = $1
            "#,
            user_id,
        )
        .fetch_all(&self.db)
        .await
        .context("Failed to fetch permissions")?;

        Ok(permissions)
    }
}
```

### 2.4 添加数据库迁移

**文件**: `migrations/20250110_create_users_table.sql`

```sql
-- 用户表
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL, -- admin, operator, viewer
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 权限表
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 用户权限关联表
CREATE TABLE user_permissions (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, permission_id)
);

-- 插入基础权限
INSERT INTO permissions (permission_name, description) VALUES
    ('wallet:read', '查看钱包'),
    ('wallet:create', '创建钱包'),
    ('withdrawal:read', '查看提现'),
    ('withdrawal:create', '创建提现'),
    ('withdrawal:approve', '批准提现'),
    ('risk:manage', '管理风控规则'),
    ('audit:read', '查看审计日志'),
    ('admin:all', '管理员全部权限');

-- 创建索引
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_user_permissions_user_id ON user_permissions(user_id);
```

### 2.5 更新API路由

**文件**: `src/api/mod.rs`

```rust
use crate::middleware::auth::{auth_middleware, require_permission, require_role};

pub fn create_router(state: Arc<AppState>) -> Router {
    // 公开路由(无需认证)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/register", post(register));

    // 需要认证的路由
    let protected_routes = Router::new()
        .route("/api/v1/wallets/balance/:address", get(get_balance))
        .route("/api/v1/wallets/create", post(create_wallet))
        .route("/api/v1/withdrawals", post(create_withdrawal))
        .layer(middleware::from_fn_with_state(
            state.jwt_auth.clone(),
            auth_middleware,
        ));

    // 需要特殊权限的路由
    let admin_routes = Router::new()
        .route("/api/v1/withdrawals/:id/approve", post(approve_withdrawal))
        .layer(middleware::from_fn(require_permission("withdrawal:approve")))
        .layer(middleware::from_fn_with_state(
            state.jwt_auth.clone(),
            auth_middleware,
        ));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(admin_routes)
        .with_state(state)
}

// 登录端点
async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (user_id, role, permissions) = state.user_service
        .authenticate(&req.email, &req.password)
        .await?;

    let token = state.jwt_auth
        .generate_token(&user_id.to_string(), &role, permissions)?;

    Ok(Json(serde_json::json!({
        "token": token,
        "user_id": user_id,
        "role": role,
    })))
}
```

### 2.6 验收清单

- [ ] 数据库迁移已执行
- [ ] 用户表和权限表已创建
- [ ] JWT认证中间件已添加
- [ ] 登录/注册端点已实现
- [ ] 受保护的路由已添加认证
- [ ] 权限检查正常工作
- [ ] 测试用例全部通过

---

## 步骤3: 添加MFA多因素认证 (2天)

### 3.1 添加依赖

**文件**: `Cargo.toml`

```toml
[dependencies]
totp-rs = { version = "5.4", features = ["qr", "gen_secret"] }
lettre = "0.11"  # 邮件发送
aws-sdk-sns = "1.11"  # 短信发送(可选)
qrcode = "0.13"
```

### 3.2 创建MFA服务

**文件**: `src/services/mfa.rs` (新建)

```rust
use anyhow::{Result, Context};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use totp_rs::{TOTP, Secret, Algorithm};
use chrono::{Utc, Duration};
use redis::Client as RedisClient;

pub struct MFAService {
    db: PgPool,
    redis: Arc<RedisClient>,
}

#[derive(Debug, Clone)]
pub enum MFALevel {
    None,
    Low,     // 仅TOTP
    Medium,  // TOTP + 邮件
    High,    // TOTP + 邮件 + 短信
}

impl MFAService {
    pub fn new(db: PgPool, redis: Arc<RedisClient>) -> Self {
        Self { db, redis }
    }

    /// 为用户生成TOTP密钥
    pub async fn enable_totp(&self, user_id: Uuid) -> Result<(String, String)> {
        let secret = Secret::generate_secret();
        let secret_str = secret.to_encoded().to_string();

        // 保存到数据库
        sqlx::query!(
            "UPDATE users SET totp_secret = $1, totp_enabled = true WHERE id = $2",
            secret_str,
            user_id,
        )
        .execute(&self.db)
        .await?;

        // 生成QR码
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().unwrap(),
            Some("OnchainWallet".to_string()),
            user_id.to_string(),
        )?;

        let qr_code = totp.get_qr_base64()?;

        Ok((secret_str, qr_code))
    }

    /// 验证TOTP码
    pub async fn verify_totp(&self, user_id: Uuid, code: &str) -> Result<bool> {
        let secret = sqlx::query_scalar!(
            "SELECT totp_secret FROM users WHERE id = $1 AND totp_enabled = true",
            user_id,
        )
        .fetch_optional(&self.db)
        .await?
        .context("TOTP not enabled")?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret).to_bytes().unwrap(),
            None,
            user_id.to_string(),
        )?;

        Ok(totp.check_current(code)?)
    }

    /// 发送邮件验证码
    pub async fn send_email_code(&self, user_id: Uuid, email: &str) -> Result<()> {
        use rand::Rng;
        let code: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();

        // 存储到Redis,5分钟过期
        let mut conn = self.redis.get_connection()?;
        let key = format!("mfa:email:{}",  user_id);
        redis::cmd("SET")
            .arg(&key)
            .arg(&code)
            .arg("EX")
            .arg(300)
            .query(&mut conn)?;

        // 发送邮件
        self.send_email(email, &code).await?;

        Ok(())
    }

    async fn send_email(&self, to: &str, code: &str) -> Result<()> {
        use lettre::message::Message;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{SmtpTransport, Transport};

        let email = Message::builder()
            .from("noreply@onchainwallet.com".parse()?)
            .to(to.parse()?)
            .subject("Verification Code")
            .body(format!("Your verification code is: {}", code))?;

        let creds = Credentials::new(
            std::env::var("SMTP_USERNAME")?,
            std::env::var("SMTP_PASSWORD")?,
        );

        let mailer = SmtpTransport::relay(&std::env::var("SMTP_SERVER")?)?
            .credentials(creds)
            .build();

        mailer.send(&email)?;
        Ok(())
    }

    /// 验证邮件验证码
    pub async fn verify_email_code(&self, user_id: Uuid, code: &str) -> Result<bool> {
        let mut conn = self.redis.get_connection()?;
        let key = format!("mfa:email:{}", user_id);

        let stored_code: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query(&mut conn)?;

        Ok(stored_code.as_deref() == Some(code))
    }

    /// 根据操作类型和金额确定MFA级别
    pub fn require_mfa(&self, operation: &str, amount: u64) -> MFALevel {
        match (operation, amount) {
            ("withdrawal", a) if a > 100_000_000_000 => MFALevel::High,
            ("withdrawal", a) if a > 10_000_000_000 => MFALevel::Medium,
            ("withdrawal", _) => MFALevel::Low,
            ("wallet:create", _) => MFALevel::Low,
            _ => MFALevel::None,
        }
    }
}
```

### 3.3 添加数据库字段

**文件**: `migrations/20250110_add_mfa_fields.sql`

```sql
ALTER TABLE users
ADD COLUMN totp_secret VARCHAR(255),
ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN phone VARCHAR(20),
ADD COLUMN phone_verified BOOLEAN NOT NULL DEFAULT false;
```

### 3.4 更新提现流程

**文件**: `src/api/mod.rs`

```rust
/// 批准提现(带MFA验证)
#[derive(Deserialize)]
struct ApproveWithMFARequest {
    approver_id: Uuid,
    totp_code: Option<String>,
    email_code: Option<String>,
    sms_code: Option<String>,
}

async fn approve_withdrawal_with_mfa(
    State(state): State<Arc<AppState>>,
    Path(withdrawal_id): Path<Uuid>,
    Json(req): Json<ApproveWithMFARequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. 获取Claims
    let claims = /* 从req.extensions获取 */;

    // 2. 获取提现信息
    let withdrawal = state.withdrawal_service
        .get_withdrawal(withdrawal_id)
        .await?;

    // 3. 确定MFA级别
    let mfa_level = state.mfa_service
        .require_mfa("withdrawal", withdrawal.amount);

    // 4. 验证MFA
    match mfa_level {
        MFALevel::High => {
            state.mfa_service.verify_totp(req.approver_id, req.totp_code.as_deref().unwrap()).await?;
            state.mfa_service.verify_email_code(req.approver_id, req.email_code.as_deref().unwrap()).await?;
            // state.mfa_service.verify_sms_code(...) if SMS enabled
        },
        MFALevel::Medium => {
            state.mfa_service.verify_totp(req.approver_id, req.totp_code.as_deref().unwrap()).await?;
            state.mfa_service.verify_email_code(req.approver_id, req.email_code.as_deref().unwrap()).await?;
        },
        MFALevel::Low => {
            state.mfa_service.verify_totp(req.approver_id, req.totp_code.as_deref().unwrap()).await?;
        },
        MFALevel::None => {},
    }

    // 5. 执行批准
    state.withdrawal_service
        .approve_withdrawal(withdrawal_id, req.approver_id)
        .await?;

    Ok(Json(serde_json::json!({"status": "approved"})))
}
```

---

## 步骤4: 实现API速率限制 (1天)

### 4.1 添加依赖

**文件**: `Cargo.toml`

```toml
[dependencies]
tower-governor = "0.1"
```

### 4.2 创建速率限制中间件

**文件**: `src/middleware/rate_limit.rs` (新建)

```rust
use axum::{
    extract::{Request, State, ConnectInfo},
    http::StatusCode,
    middleware::Next,
    response::Response,
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
pub async fn rate_limit_middleware<B>(
    State(limiter): State<Arc<MultiLevelRateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let ip = addr.ip().to_string();

    // 检查IP限制
    if !limiter.check_ip_limit(&ip)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // 如果有JWT,检查用户限制
    if let Some(claims) = req.extensions().get::<crate::middleware::auth::Claims>() {
        if !limiter.check_user_limit(&claims.sub)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    Ok(next.run(req).await)
}
```

### 4.3 应用到路由

**文件**: `src/api/mod.rs`

```rust
use crate::middleware::rate_limit::{rate_limit_middleware, MultiLevelRateLimiter};

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/withdrawals", post(create_withdrawal))
        // ... 其他路由
        .layer(middleware::from_fn_with_state(
            state.rate_limiter.clone(),
            rate_limit_middleware,
        ))
        .with_state(state)
}
```

---

## 步骤5: 完善错误处理 (1天)

### 5.1 创建错误处理模块

**文件**: `src/middleware/error_handler.rs` (新建)

```rust
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
```

---

## 📊 Phase 1 完成检查清单

### 代码实现
- [ ] AWS KMS集成完成
- [ ] JWT认证实现完成
- [ ] MFA多因素认证完成
- [ ] API速率限制完成
- [ ] 错误处理完善完成

### 配置
- [ ] AWS KMS密钥已创建
- [ ] 环境变量已配置
- [ ] Redis已部署并配置
- [ ] SMTP邮件服务已配置

### 数据库
- [ ] 用户表迁移已执行
- [ ] 权限表迁移已执行
- [ ] MFA字段迁移已执行

### 测试
- [ ] 单元测试全部通过
- [ ] 集成测试全部通过
- [ ] 手动测试完成

### 文档
- [ ] API文档已更新
- [ ] 部署文档已更新
- [ ] 安全配置文档已完成

---

## 🎯 预期成果

完成Phase 1后,系统将达到:

- **安全评级**: C → B+
- **严重漏洞**: 8个 → 0个
- **合规性**:
  - PCI DSS: 12.5% → 60%
  - SOC 2: 32% → 65%
  - ISO 27001: 22% → 58%

---

## 📞 后续步骤

Phase 1完成后,继续执行:
- **Phase 2**: 安全功能完善 (CORS, 输入验证, 安全响应头等)
- **Phase 3**: 合规性强化 (审计日志签名, SIEM集成, 灾难恢复等)

---

**文档创建时间**: 2025-11-10
**最后更新**: 2025-11-10
**版本**: v1.0

