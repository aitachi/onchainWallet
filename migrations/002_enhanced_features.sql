-- 新功能数据库迁移
-- 创建时间: 2025-11-10
-- 描述: 添加NFT、代币、DeFi、交易历史、Gas费、地址簿、批量转账、Webhook、多签钱包、分析等功能的表

-- NFT资产表
CREATE TABLE IF NOT EXISTS nft_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain VARCHAR(20) NOT NULL,
    owner_address VARCHAR(255) NOT NULL,
    contract_address VARCHAR(255) NOT NULL,
    token_id VARCHAR(255) NOT NULL,
    metadata JSONB,
    image_url TEXT,
    last_synced TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(contract_address, token_id, chain)
);

CREATE INDEX idx_nft_assets_owner ON nft_assets(owner_address, chain);
CREATE INDEX idx_nft_assets_contract ON nft_assets(contract_address);

-- 代币信息表
CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain VARCHAR(20) NOT NULL,
    contract_address VARCHAR(255) NOT NULL,
    symbol VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    decimals SMALLINT NOT NULL,
    logo_url TEXT,
    is_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(contract_address, chain)
);

CREATE INDEX idx_tokens_chain ON tokens(chain);
CREATE INDEX idx_tokens_symbol ON tokens(symbol);

-- 用户自定义代币表
CREATE TABLE IF NOT EXISTS user_tokens (
    user_address VARCHAR(255) NOT NULL,
    token_id UUID NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    added_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_address, token_id)
);

-- DeFi Swap记录表
CREATE TABLE IF NOT EXISTS defi_swaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_address VARCHAR(255) NOT NULL,
    chain VARCHAR(20) NOT NULL,
    from_token VARCHAR(255) NOT NULL,
    to_token VARCHAR(255) NOT NULL,
    amount_in TEXT NOT NULL,
    amount_out TEXT NOT NULL,
    tx_hash VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_defi_swaps_user ON defi_swaps(user_address);
CREATE INDEX idx_defi_swaps_tx_hash ON defi_swaps(tx_hash);
CREATE INDEX idx_defi_swaps_created ON defi_swaps(created_at DESC);

-- DeFi质押记录表
CREATE TABLE IF NOT EXISTS defi_stakes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_address VARCHAR(255) NOT NULL,
    chain VARCHAR(20) NOT NULL,
    pool_address VARCHAR(255) NOT NULL,
    token_address VARCHAR(255) NOT NULL,
    staked_amount TEXT NOT NULL,
    rewards_earned TEXT DEFAULT '0',
    apy DOUBLE PRECISION,
    tx_hash VARCHAR(255),
    status VARCHAR(20) NOT NULL,
    staked_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_claimed TIMESTAMP,
    unstaked_at TIMESTAMP
);

CREATE INDEX idx_defi_stakes_user ON defi_stakes(user_address);
CREATE INDEX idx_defi_stakes_pool ON defi_stakes(pool_address);
CREATE INDEX idx_defi_stakes_status ON defi_stakes(status);

-- Gas费历史表
CREATE TABLE IF NOT EXISTS gas_history (
    id BIGSERIAL PRIMARY KEY,
    chain VARCHAR(20) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    avg_gas_price TEXT NOT NULL,
    min_gas_price TEXT NOT NULL,
    max_gas_price TEXT NOT NULL,
    network_utilization DOUBLE PRECISION
);

CREATE INDEX idx_gas_history_chain ON gas_history(chain, timestamp DESC);

-- 地址簿表
CREATE TABLE IF NOT EXISTS address_book (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    name VARCHAR(100) NOT NULL,
    address VARCHAR(255) NOT NULL,
    chain VARCHAR(20) NOT NULL,
    labels TEXT[] DEFAULT '{}',
    note TEXT,
    is_favorite BOOLEAN DEFAULT false,
    usage_count INTEGER DEFAULT 0,
    last_used TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, address, chain)
);

CREATE INDEX idx_address_book_user ON address_book(user_id);
CREATE INDEX idx_address_book_usage ON address_book(usage_count DESC);
CREATE INDEX idx_address_book_favorite ON address_book(is_favorite);

-- 批量转账记录表
CREATE TABLE IF NOT EXISTS batch_transfers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    from_address VARCHAR(255) NOT NULL,
    chain VARCHAR(20) NOT NULL,
    total_recipients INTEGER NOT NULL,
    successful INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    total_amount TEXT NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_batch_transfers_user ON batch_transfers(user_id);
CREATE INDEX idx_batch_transfers_created ON batch_transfers(created_at DESC);

-- Webhook配置表
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    url TEXT NOT NULL,
    secret VARCHAR(255) NOT NULL,
    events TEXT[] NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhooks_user ON webhooks(user_id);
CREATE INDEX idx_webhooks_active ON webhooks(is_active);

-- Webhook投递记录表
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(20) NOT NULL,
    response_status INTEGER,
    delivered_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX idx_webhook_deliveries_delivered ON webhook_deliveries(delivered_at DESC);

-- 多签钱包表
CREATE TABLE IF NOT EXISTS multisig_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address VARCHAR(255) NOT NULL,
    chain VARCHAR(20) NOT NULL,
    owners TEXT[] NOT NULL,
    threshold INTEGER NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(address, chain)
);

CREATE INDEX idx_multisig_wallets_owners ON multisig_wallets USING GIN(owners);

-- 多签提案表
CREATE TABLE IF NOT EXISTS multisig_proposals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES multisig_wallets(id) ON DELETE CASCADE,
    proposer VARCHAR(255) NOT NULL,
    to_address VARCHAR(255) NOT NULL,
    amount TEXT NOT NULL,
    token_address VARCHAR(255),
    data BYTEA,
    approvals TEXT[] DEFAULT '{}',
    rejections TEXT[] DEFAULT '{}',
    status VARCHAR(20) NOT NULL,
    tx_hash VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    executed_at TIMESTAMP
);

CREATE INDEX idx_multisig_proposals_wallet ON multisig_proposals(wallet_id);
CREATE INDEX idx_multisig_proposals_status ON multisig_proposals(status);
CREATE INDEX idx_multisig_proposals_created ON multisig_proposals(created_at DESC);

-- 添加transactions表的缺失字段(如果不存在)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='token_symbol') THEN
        ALTER TABLE transactions ADD COLUMN token_symbol VARCHAR(20);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='fee') THEN
        ALTER TABLE transactions ADD COLUMN fee TEXT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='block_number') THEN
        ALTER TABLE transactions ADD COLUMN block_number BIGINT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='confirmations') THEN
        ALTER TABLE transactions ADD COLUMN confirmations INTEGER;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='confirmed_at') THEN
        ALTER TABLE transactions ADD COLUMN confirmed_at TIMESTAMP;
    END IF;
END $$;

-- 创建交易历史视图(用于快速查询)
CREATE OR REPLACE VIEW transaction_summary AS
SELECT
    t.id,
    t.chain,
    t.tx_hash,
    t.from_address,
    t.to_address,
    t.amount,
    t.token_address,
    t.token_symbol,
    t.tx_type,
    t.status,
    t.fee,
    t.block_number,
    t.confirmations,
    t.created_at,
    t.confirmed_at,
    CASE
        WHEN t.from_address = w.address THEN 'sent'
        WHEN t.to_address = w.address THEN 'received'
        ELSE 'unknown'
    END as direction
FROM transactions t
LEFT JOIN wallets w ON (t.from_address = w.address OR t.to_address = w.address);

-- 添加性能优化索引
CREATE INDEX IF NOT EXISTS idx_transactions_addresses ON transactions(from_address, to_address);
CREATE INDEX IF NOT EXISTS idx_transactions_created_desc ON transactions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_chain_type ON transactions(chain, tx_type);
CREATE INDEX IF NOT EXISTS idx_nft_assets_sync ON nft_assets(last_synced DESC);

-- 创建函数: 更新地址簿的updated_at
CREATE OR REPLACE FUNCTION update_address_book_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 创建触发器
DROP TRIGGER IF EXISTS trigger_address_book_updated_at ON address_book;
CREATE TRIGGER trigger_address_book_updated_at
    BEFORE UPDATE ON address_book
    FOR EACH ROW
    EXECUTE FUNCTION update_address_book_updated_at();

-- 插入一些常用代币(示例数据)
INSERT INTO tokens (chain, contract_address, symbol, name, decimals, is_verified) VALUES
    ('ETH', '0xdAC17F958D2ee523a2206206994597C13D831ec7', 'USDT', 'Tether USD', 6, true),
    ('ETH', '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'USDC', 'USD Coin', 6, true),
    ('ETH', '0x6B175474E89094C44Da98b954EedeAC495271d0F', 'DAI', 'Dai Stablecoin', 18, true),
    ('SOL', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'USDC', 'USD Coin', 6, true),
    ('SOL', 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', 'USDT', 'Tether USD', 6, true)
ON CONFLICT (contract_address, chain) DO NOTHING;

COMMENT ON TABLE nft_assets IS 'NFT资产表';
COMMENT ON TABLE tokens IS '代币信息表';
COMMENT ON TABLE defi_swaps IS 'DeFi Swap交易记录';
COMMENT ON TABLE defi_stakes IS 'DeFi质押记录';
COMMENT ON TABLE gas_history IS 'Gas费历史数据';
COMMENT ON TABLE address_book IS '地址簿';
COMMENT ON TABLE batch_transfers IS '批量转账记录';
COMMENT ON TABLE webhooks IS 'Webhook配置';
COMMENT ON TABLE webhook_deliveries IS 'Webhook投递记录';
COMMENT ON TABLE multisig_wallets IS '多签钱包';
COMMENT ON TABLE multisig_proposals IS '多签提案';
