pub mod models;
pub mod services;
pub mod api;

use anyhow::Result;
use dotenv::dotenv;
use std::sync::Arc;
use sqlx::postgres::PgPoolOptions;
use redis::Client as RedisClient;

use services::{
    blockchain::AdapterRegistry,
    key_manager::KeyManager,
    wallet::WalletService,
    deposit::DepositMonitorService,
    withdrawal::WithdrawalService,
    risk::RiskControlService,
    audit::AuditService,
    scheduler::AssetSchedulerService,
    // 新增服务导入
    nft::NFTService,
    token::TokenService,
    defi::DeFiService,
    transaction_history::TransactionHistoryService,
    gas::GasService,
    address_book::AddressBookService,
    batch_transfer::BatchTransferService,
    webhook::WebhookService,
    multisig::MultisigService,
    analytics::AnalyticsService,
};
use models::types::Chain;
use api::{AppState, create_router};

#[tokio::main]
async fn main() -> Result<()> {
    // 加载环境变量
    dotenv().ok();

    // 初始化日志
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    tracing::info!("🚀 Starting Onchain Wallet System v2.0.0...");

    // 1. 初始化数据库连接
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://wallet_user:wallet_pg_pass_2024@localhost:5432/wallet_db".to_string());

    tracing::info!("Connecting to database...");
    let db = PgPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await?;

    tracing::info!("✅ Database connected");

    // 2. 初始化Redis连接
    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://:redis_pass_2024@localhost:6379".to_string());

    tracing::info!("Connecting to Redis...");
    let redis_client = RedisClient::open(redis_url)?;
    let _redis_conn = redis_client.get_connection()?; // 测试连接
    let redis = Arc::new(redis_client);
    tracing::info!("✅ Redis connected");

    // 3. 初始化区块链适配器
    let solana_rpc = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let ethereum_rpc = std::env::var("ETHEREUM_RPC_URL")
        .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());

    tracing::info!("Initializing blockchain adapters...");
    let adapters = Arc::new(AdapterRegistry::init_all(&solana_rpc, &ethereum_rpc, 1)?);
    tracing::info!("✅ Blockchain adapters initialized");

    // 4. 初始化密钥管理器
    tracing::info!("Initializing key manager...");
    let key_manager = Arc::new(KeyManager::from_env()?);
    tracing::info!("✅ Key manager initialized");

    // 5. 初始化核心服务 (Phase 1 - 8个基础服务)
    tracing::info!("Initializing Phase 1 services (8 core modules)...");

    let wallet_service = Arc::new(WalletService::new(
        db.clone(),
        Arc::clone(&adapters),
        Arc::clone(&key_manager),
    ));
    tracing::info!("  ✅ Wallet service");

    let risk_service = Arc::new(RiskControlService::new(db.clone()));
    risk_service.load_rules().await?;
    tracing::info!("  ✅ Risk control service");

    let audit_service = Arc::new(AuditService::new(db.clone()));
    tracing::info!("  ✅ Audit service");

    let withdrawal_service = Arc::new(WithdrawalService::new(
        db.clone(),
        Arc::clone(&adapters),
        Arc::clone(&key_manager),
        Arc::clone(&risk_service),
        Arc::clone(&audit_service),
    ));
    tracing::info!("  ✅ Withdrawal service");

    let deposit_monitor = Arc::new(DepositMonitorService::new(db.clone(), Arc::clone(&adapters)));

    // 加载监听地址
    deposit_monitor.load_addresses_from_db(Chain::Solana).await?;
    deposit_monitor.load_addresses_from_db(Chain::Ethereum).await?;
    tracing::info!("  ✅ Deposit monitor");

    let scheduler = Arc::new(AssetSchedulerService::new(
        db.clone(),
        Arc::clone(&adapters),
        Arc::clone(&wallet_service),
    ));
    tracing::info!("  ✅ Asset scheduler");

    // 6. 初始化增强服务 (Phase 2 - 10个新增服务)
    tracing::info!("Initializing Phase 2 services (10 enhanced modules)...");

    let nft_service = Arc::new(NFTService::new(
        db.clone(),
        Arc::clone(&adapters),
    ));
    tracing::info!("  ✅ NFT service");

    let token_service = Arc::new(TokenService::new(
        db.clone(),
        Arc::clone(&adapters),
    ));
    tracing::info!("  ✅ Token service");

    let defi_service = Arc::new(DeFiService::new(
        db.clone(),
        Arc::clone(&adapters),
    ));
    tracing::info!("  ✅ DeFi service");

    let tx_history_service = Arc::new(TransactionHistoryService::new(db.clone()));
    tracing::info!("  ✅ Transaction history service");

    let gas_service = Arc::new(GasService::new(
        db.clone(),
        Arc::clone(&adapters),
    ));
    tracing::info!("  ✅ Gas service");

    let address_book_service = Arc::new(AddressBookService::new(db.clone()));
    tracing::info!("  ✅ Address book service");

    let batch_transfer_service = Arc::new(BatchTransferService::new(
        db.clone(),
        Arc::clone(&adapters),
        Arc::clone(&audit_service),
    ));
    tracing::info!("  ✅ Batch transfer service");

    let webhook_service = Arc::new(WebhookService::new(db.clone()));
    tracing::info!("  ✅ Webhook service");

    let multisig_service = Arc::new(MultisigService::new(
        db.clone(),
        Arc::clone(&adapters),
    ));
    tracing::info!("  ✅ Multisig service");

    let analytics_service = Arc::new(AnalyticsService::new(db.clone()));
    tracing::info!("  ✅ Analytics service");

    tracing::info!("✅ All 18 services initialized successfully");

    // 7. 启动后台服务
    tracing::info!("Starting background services...");

    // 启动充值监听 (Solana)
    tokio::spawn({
        let monitor = Arc::clone(&deposit_monitor);
        async move {
            if let Err(e) = monitor.start(Chain::Solana).await {
                tracing::error!("Deposit monitor (Solana) failed: {}", e);
            }
        }
    });

    // 启动充值监听 (Ethereum)
    tokio::spawn({
        let monitor = Arc::clone(&deposit_monitor);
        async move {
            if let Err(e) = monitor.start(Chain::Ethereum).await {
                tracing::error!("Deposit monitor (Ethereum) failed: {}", e);
            }
        }
    });

    // 启动自动归集 (Solana)
    tokio::spawn({
        let sched = Arc::clone(&scheduler);
        async move {
            if let Err(e) = sched.start_auto_collection(Chain::Solana).await {
                tracing::error!("Auto collection (Solana) failed: {}", e);
            }
        }
    });

    // 启动余额监控 (Solana)
    tokio::spawn({
        let sched = Arc::clone(&scheduler);
        async move {
            if let Err(e) = sched.start_balance_monitoring(Chain::Solana).await {
                tracing::error!("Balance monitoring (Solana) failed: {}", e);
            }
        }
    });

    tracing::info!("✅ Background services started");

    // 8. 创建API状态(包含所有18个服务)
    let app_state = Arc::new(AppState {
        // Phase 1 基础服务
        wallet_service,
        withdrawal_service,
        risk_service,
        audit_service,
        // Phase 2 增强服务
        nft_service,
        token_service,
        defi_service,
        tx_history_service,
        gas_service,
        address_book_service,
        batch_transfer_service,
        webhook_service,
        multisig_service,
        analytics_service,
        // 共享资源
        redis,
    });

    // 9. 创建API路由
    let app = create_router(app_state);

    // 10. 启动HTTP服务器
    let addr = std::env::var("SERVER_HOST")
        .unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("SERVER_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", addr, port))
        .await?;

    tracing::info!("✅ API server listening on {}:{}", addr, port);
    tracing::info!("🎉 Onchain Wallet System v2.0.0 started successfully!");
    tracing::info!("📊 Total services: 18 modules");
    tracing::info!("🔗 Supported chains: Solana, Ethereum, BSC, Polygon");
    tracing::info!("🌐 API documentation: http://{}:{}/api/v1/docs", addr, port);

    axum::serve(listener, app).await?;

    Ok(())
}
