# 企业级多链钱包系统 - 开发计划

## 项目信息
- **项目名称**: 企业级多链钱包系统 (DeFi Summer 2.0)
- **技术栈**: Rust (核心服务) + Go (辅助服务)
- **目标**: 交易所级别的多链钱包系统
- **开发周期**: 32周 (分5个阶段)

---

## Phase 1: 核心钱包系统 (优先级: 最高)

### 1.1 项目基础架构 ✅
- [x] Docker环境搭建
- [x] 数据库配置 (PostgreSQL, Redis, ScyllaDB, Kafka)
- [x] 对象存储配置 (MinIO)
- [x] 日志系统 (Elasticsearch)

### 1.2 冷热钱包分层架构 (2周)
**核心功能**:
- [ ] 热钱包服务 (在线充提, <1%资产)
- [ ] 温钱包服务 (中转归集, 5%资产)
- [ ] 冷钱包服务 (离线签名, 99%资产)
- [ ] 钱包余额监控
- [ ] 钱包间资产转移

**技术实现**:
```rust
// 钱包分层枚举
pub enum WalletTier {
    Hot,    // 热钱包
    Warm,   // 温钱包
    Cold,   // 冷钱包
}

// 钱包管理器
pub struct WalletManager {
    hot_wallets: HashMap<Chain, HotWallet>,
    warm_wallets: HashMap<Chain, WarmWallet>,
    cold_wallets: HashMap<Chain, ColdWallet>,
}
```

### 1.3 密钥管理系统 (2周)
**核心功能**:
- [ ] 助记词生成与存储
- [ ] 分层确定性钱包 (HD Wallet) BIP32/BIP44
- [ ] 密钥加密存储
- [ ] 密钥分片备份 (Shamir Secret Sharing)
- [ ] 硬件钱包集成接口

**技术选型**:
- `bip39` - 助记词
- `bip32` - HD钱包
- `aes-gcm` - 密钥加密
- `shamir-secret-sharing` - 密钥分片

### 1.4 多链抽象层 (3周)
**支持链**:
- [x] Solana (优先级最高)
- [ ] Ethereum (EVM兼容)
- [ ] Bitcoin
- [ ] TRON
- [ ] BSC
- [ ] Polygon
- [ ] Arbitrum / Optimism

**统一接口**:
```rust
#[async_trait]
pub trait BlockchainAdapter {
    async fn generate_address(&self, index: u32) -> Result<Address>;
    async fn get_balance(&self, address: &str) -> Result<Balance>;
    async fn build_transaction(&self, tx: &TxRequest) -> Result<UnsignedTx>;
    async fn sign_transaction(&self, tx: &UnsignedTx) -> Result<SignedTx>;
    async fn broadcast(&self, tx: &SignedTx) -> Result<TxHash>;
    async fn get_transaction(&self, hash: &str) -> Result<Transaction>;
    async fn subscribe_deposits(&self, addresses: Vec<String>) -> Result<DepositStream>;
}
```

### 1.5 基础充提功能 (2周)
- [ ] 充值地址生成与分配
- [ ] 充值监听与确认
- [ ] 提现请求处理
- [ ] 提现签名与广播
- [ ] 交易状态追踪
- [ ] 充提记录查询

---

## Phase 2: 安全与风控 (优先级: 高)

### 2.1 多级权限系统 (1周)
**角色定义**:
```rust
pub enum Role {
    SuperAdmin,      // 超级管理员 - 所有权限
    Compliance,      // 合规审计 - 查看审计日志
    FinanceOps,      // 财务运营 - 处理提现
    RiskControl,     // 风控专员 - 风控规则配置
    Developer,       // 开发者 - API访问
}
```

**权限检查**:
- [ ] RBAC (基于角色)
- [ ] ABAC (基于属性)
- [ ] 操作审计日志
- [ ] IP白名单
- [ ] 多因素认证 (MFA)

### 2.2 风控引擎 (2周)
**规则引擎**:
- [ ] 黑名单地址检查
- [ ] 金额阈值检查
- [ ] 频率限制
- [ ] 异常地址检测
- [ ] 用户行为分析

**机器学习模型**:
- [ ] 异常交易检测 (Isolation Forest)
- [ ] 地址风险评分
- [ ] 特征工程
- [ ] 模型训练与更新

**决策流程**:
```
提现请求 → 规则检查 → ML异常检测 → 地址信誉 → 风险评分
  ↓
[低风险: 自动通过] [中风险: 人工审核] [高风险: 拒绝]
```

### 2.3 实时监控告警 (1周)
- [ ] 余额异常告警
- [ ] 大额交易告警
- [ ] 系统异常告警
- [ ] 多渠道通知 (邮件/短信/Telegram)

### 2.4 审计日志系统 (1周)
- [ ] 全链路日志记录
- [ ] 日志索引与搜索 (Elasticsearch)
- [ ] 日志归档 (MinIO)
- [ ] 日志可视化

---

## Phase 3: 资产调度 (优先级: 中)

### 3.1 自动归集引擎 (2周)
**功能**:
- [ ] 充值地址余额扫描
- [ ] 归集阈值配置
- [ ] 批量归集执行
- [ ] Gas费优化
- [ ] 归集失败重试

**流程**:
```
扫描充值地址 → 筛选余额>阈值 → 批量构建交易 → 签名 → 广播 → 确认
```

### 3.2 余额监控与预警 (1周)
- [ ] 热钱包余额实时监控
- [ ] 余额低于阈值告警
- [ ] 自动从温钱包补充
- [ ] 多链余额统计

### 3.3 流动性优化 (2周)
- [ ] 各链提现需求预测
- [ ] 最优资产分配算法
- [ ] 跨链资产调度
- [ ] 流动性报告生成

### 3.4 批量操作支持 (1周)
- [ ] 批量提现
- [ ] 批量归集
- [ ] 批量地址生成
- [ ] 操作进度追踪

---

## Phase 4: 高级功能 (优先级: 低)

### 4.1 DeFi协议集成 (3周)
- [ ] Uniswap/PancakeSwap交易
- [ ] Lending协议 (Aave/Compound)
- [ ] Staking支持
- [ ] 收益聚合器

### 4.2 NFT资产管理 (2周)
- [ ] NFT资产发现
- [ ] NFT转账
- [ ] NFT批量操作
- [ ] NFT元数据解析

### 4.3 合规报告生成 (2周)
- [ ] 交易报告
- [ ] AML报告
- [ ] 资金流向追踪
- [ ] PDF报告导出

### 4.4 API开放平台 (1周)
- [ ] RESTful API
- [ ] WebSocket实时推送
- [ ] API密钥管理
- [ ] API文档 (Swagger)
- [ ] SDK (Python/JavaScript)

---

## Phase 5: 优化与治理 (持续)

### 5.1 性能优化
- [ ] 数据库查询优化
- [ ] 缓存策略优化
- [ ] 连接池优化
- [ ] 批量操作优化

### 5.2 高可用部署
- [ ] Docker Compose生产配置
- [ ] 多活架构
- [ ] 熔断降级
- [ ] 灰度发布

### 5.3 安全加固
- [ ] 渗透测试
- [ ] 代码审计
- [ ] 漏洞修复
- [ ] 安全更新

### 5.4 文档完善
- [ ] 架构文档
- [ ] API文档
- [ ] 运维文档
- [ ] 开发文档

---

## 当前实施计划 (MVP版本)

基于时间和资源,我们将先实现以下核心功能:

### 第一阶段: 基础钱包功能 (本次实现)
1. **数据库模型设计** ✅
2. **多链适配器** (Solana + ETH)
3. **地址生成与管理**
4. **充值监听**
5. **提现处理**
6. **基础风控**
7. **审计日志**

### 第二阶段: 安全增强
1. 冷热钱包分层
2. 资产自动归集
3. 高级风控引擎
4. MPC签名 (可选)

### 第三阶段: 完善优化
1. 更多链支持
2. DeFi集成
3. 性能优化
4. 压力测试

---

## 技术栈详细说明

### 后端技术
```
核心服务 (Rust):
- tokio: 异步运行时
- axum: Web框架
- sqlx: 数据库 ORM
- redis: 缓存客户端
- kafka-rust: 消息队列

区块链SDK:
- solana-sdk: Solana
- web3: Ethereum
- bitcoin: Bitcoin
- tron-api: TRON

工具库:
- serde: 序列化
- anyhow/thiserror: 错误处理
- tracing: 日志
- prometheus: 监控
```

### 数据库设计
```sql
-- 主要表:
- users (用户)
- wallets (钱包)
- addresses (地址池)
- deposits (充值记录)
- withdrawals (提现记录)
- transactions (交易记录)
- audit_logs (审计日志)
- risk_rules (风控规则)
```

---

## 项目目录结构

```
onchain-wallet/
├── src/
│   ├── main.rs                 # 入口
│   ├── config/                 # 配置
│   ├── models/                 # 数据模型
│   ├── services/               # 业务服务
│   │   ├── wallet/             # 钱包服务
│   │   ├── blockchain/         # 区块链适配器
│   │   ├── deposit/            # 充值服务
│   │   ├── withdrawal/         # 提现服务
│   │   ├── risk/               # 风控服务
│   │   └── audit/              # 审计服务
│   ├── api/                    # API路由
│   ├── middleware/             # 中间件
│   └── utils/                  # 工具函数
├── migrations/                 # 数据库迁移
├── tests/                      # 测试
├── docker-compose.yml          # Docker配置
├── Cargo.toml                  # Rust依赖
└── README.md
```

---

## 下一步行动

1. ✅ 完成Docker环境搭建
2. ⬜ 初始化Rust项目
3. ⬜ 设计数据库Schema
4. ⬜ 实现Solana适配器
5. ⬜ 实现ETH适配器
6. ⬜ 地址生成与管理
7. ⬜ 充值监听服务
8. ⬜ 提现处理服务
9. ⬜ 基础API接口
10. ⬜ 单元测试与集成测试

---

**文档版本**: v1.0
**最后更新**: 2025-11-10
**状态**: Phase 1 进行中
