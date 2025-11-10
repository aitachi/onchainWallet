use async_trait::async_trait;
use ethers::{
    prelude::*,
    providers::{Provider, Http},
    types::{Address as EthAddress, TransactionRequest, U256, BlockNumber},
};
use std::str::FromStr;
use crate::models::{Result, WalletError};
use super::adapter::*;

pub struct EthereumAdapter {
    provider: Provider<Http>,
    chain_id: u64,
}

impl EthereumAdapter {
    pub fn new(rpc_url: &str, chain_id: u64) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| WalletError::Config(format!("Invalid RPC URL: {}", e)))?;

        Ok(Self {
            provider,
            chain_id,
        })
    }

    fn parse_address(&self, address: &str) -> Result<EthAddress> {
        EthAddress::from_str(address)
            .map_err(|e| WalletError::InvalidAddress(format!("Invalid Ethereum address: {}", e)))
    }
}

#[async_trait]
impl BlockchainAdapter for EthereumAdapter {
    async fn generate_address(&self, _derivation_path: &str) -> Result<Address> {
        // 生成新的钱包
        let wallet = LocalWallet::new(&mut rand::thread_rng());

        Ok(Address {
            address: format!("{:?}", wallet.address()),
            public_key: Some(hex::encode(wallet.address())),
        })
    }

    async fn get_balance(&self, address: &str) -> Result<Balance> {
        let eth_address = self.parse_address(address)?;

        let balance = self.provider
            .get_balance(eth_address, None)
            .await
            .map_err(|e| WalletError::Blockchain(format!("Failed to get balance: {}", e)))?;

        let balance_u64 = balance.as_u64();

        Ok(Balance {
            confirmed: balance_u64,
            unconfirmed: 0,
            total: balance_u64,
        })
    }

    async fn get_token_balance(&self, address: &str, token: &str) -> Result<Balance> {
        let eth_address = self.parse_address(address)?;
        let token_address = self.parse_address(token)?;

        // ERC20 balanceOf 调用
        abigen!(
            IERC20,
            r#"[
                function balanceOf(address) external view returns (uint256)
            ]"#,
        );

        let contract = IERC20::new(token_address, Arc::new(self.provider.clone()));
        let balance = contract
            .balance_of(eth_address)
            .call()
            .await
            .map_err(|e| WalletError::Blockchain(format!("Failed to get token balance: {}", e)))?;

        Ok(Balance {
            confirmed: balance.as_u64(),
            unconfirmed: 0,
            total: balance.as_u64(),
        })
    }

    async fn build_transfer(
        &self,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<UnsignedTx> {
        let from_address = self.parse_address(from)?;
        let to_address = self.parse_address(to)?;

        // 获取nonce
        let nonce = self.provider
            .get_transaction_count(from_address, None)
            .await
            .map_err(|e| WalletError::Blockchain(format!("Failed to get nonce: {}", e)))?;

        // 获取gas price
        let gas_price = self.provider
            .get_gas_price()
            .await
            .map_err(|e| WalletError::Blockchain(format!("Failed to get gas price: {}", e)))?;

        // 构建交易
        let tx = TransactionRequest::new()
            .from(from_address)
            .to(to_address)
            .value(U256::from(amount))
            .nonce(nonce)
            .gas_price(gas_price)
            .gas(21000); // 标准转账gas限制

        let fee = gas_price.as_u64() * 21000;

        Ok(UnsignedTx {
            from: from.to_string(),
            to: to.to_string(),
            amount,
            fee,
            nonce: Some(nonce.as_u64()),
            data: serde_json::to_vec(&tx)
                .map_err(|e| WalletError::Serialization(e))?,
        })
    }

    async fn sign_transaction(
        &self,
        tx: &UnsignedTx,
        private_key: &[u8],
    ) -> Result<SignedTx> {
        // 从私钥创建钱包
        let wallet = LocalWallet::from_bytes(private_key)
            .map_err(|e| WalletError::Encryption(format!("Invalid private key: {}", e)))?
            .with_chain_id(self.chain_id);

        // 反序列化交易
        let tx_request: TransactionRequest = serde_json::from_slice(&tx.data)
            .map_err(|e| WalletError::Serialization(e))?;

        // 签名交易
        let signature = wallet
            .sign_transaction(&tx_request.into())
            .await
            .map_err(|e| WalletError::Encryption(format!("Failed to sign: {}", e)))?;

        Ok(SignedTx {
            signature: signature.to_vec(),
            raw_tx: vec![], // TODO: 构建原始交易数据
        })
    }

    async fn broadcast(&self, tx: &SignedTx) -> Result<TxHash> {
        // 广播原始交易
        let pending_tx = self.provider
            .send_raw_transaction(Bytes::from(tx.raw_tx.clone()))
            .await
            .map_err(|e| WalletError::Blockchain(format!("Failed to broadcast: {}", e)))?;

        Ok(format!("{:?}", pending_tx.tx_hash()))
    }

    async fn get_transaction(&self, tx_hash: &str) -> Result<Transaction> {
        let hash = tx_hash.parse::<H256>()
            .map_err(|e| WalletError::InvalidAddress(format!("Invalid transaction hash: {}", e)))?;

        let tx = self.provider
            .get_transaction(hash)
            .await
            .map_err(|e| WalletError::Blockchain(format!("Failed to get transaction: {}", e)))?
            .ok_or_else(|| WalletError::TransactionNotFound(tx_hash.to_string()))?;

        let block_number = tx.block_number.map(|b| b.as_u64());
        let current_block = self.get_block_height().await?;
        let confirmations = if let Some(bn) = block_number {
            (current_block - bn) as u32
        } else {
            0
        };

        Ok(Transaction {
            hash: tx_hash.to_string(),
            from: format!("{:?}", tx.from),
            to: tx.to.map(|a| format!("{:?}", a)).unwrap_or_default(),
            amount: tx.value.as_u64(),
            fee: tx.gas_price.unwrap_or_default().as_u64() * tx.gas.as_u64(),
            block_number,
            confirmations,
            status: if block_number.is_some() {
                TxStatus::Confirmed
            } else {
                TxStatus::Pending
            },
            timestamp: None,
        })
    }

    async fn get_confirmations(&self, tx_hash: &str) -> Result<u32> {
        let tx = self.get_transaction(tx_hash).await?;
        Ok(tx.confirmations)
    }

    async fn get_block_height(&self) -> Result<u64> {
        let block = self.provider
            .get_block_number()
            .await
            .map_err(|e| WalletError::Blockchain(format!("Failed to get block height: {}", e)))?;

        Ok(block.as_u64())
    }

    async fn estimate_fee(&self, _from: &str, _to: &str, _amount: u64) -> Result<u64> {
        let gas_price = self.provider
            .get_gas_price()
            .await
            .map_err(|e| WalletError::Blockchain(format!("Failed to get gas price: {}", e)))?;

        Ok(gas_price.as_u64() * 21000)
    }

    fn validate_address(&self, address: &str) -> Result<bool> {
        match EthAddress::from_str(address) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
