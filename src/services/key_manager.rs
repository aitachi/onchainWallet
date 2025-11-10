use bip39::{Mnemonic, Language, MnemonicType};
use bip32::{XPrv, DerivationPath};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};
use rand::RngCore;
use std::str::FromStr;
use crate::models::{Result, WalletError};

/// 密钥管理器
pub struct KeyManager {
    master_key: [u8; 32],
}

impl KeyManager {
    /// 从主密钥创建
    pub fn new(master_key: [u8; 32]) -> Self {
        Self { master_key }
    }

    /// 从环境变量加载
    pub fn from_env() -> Result<Self> {
        let key_hex = std::env::var("ENCRYPTION_KEY")
            .map_err(|_| WalletError::Config("ENCRYPTION_KEY not set".to_string()))?;

        let key_bytes = hex::decode(&key_hex)
            .map_err(|e| WalletError::Config(format!("Invalid encryption key: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(WalletError::Config("Encryption key must be 32 bytes".to_string()));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        Ok(Self::new(key))
    }

    /// 生成新的助记词
    pub fn generate_mnemonic(&self, word_count: usize) -> Result<String> {
        let mnemonic_type = match word_count {
            12 => MnemonicType::Words12,
            15 => MnemonicType::Words15,
            18 => MnemonicType::Words18,
            21 => MnemonicType::Words21,
            24 => MnemonicType::Words24,
            _ => return Err(WalletError::Config("Invalid word count".to_string())),
        };

        let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
        Ok(mnemonic.phrase().to_string())
    }

    /// 从助记词派生种子
    pub fn mnemonic_to_seed(&self, mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
        let mnemonic = Mnemonic::from_phrase(mnemonic, Language::English)
            .map_err(|e| WalletError::Encryption(format!("Invalid mnemonic: {}", e)))?;

        let seed = mnemonic.to_seed(passphrase);
        Ok(seed)
    }

    /// 派生私钥 (BIP32/BIP44)
    pub fn derive_key(&self, seed: &[u8; 64], path: &str) -> Result<Vec<u8>> {
        let derivation_path = DerivationPath::from_str(path)
            .map_err(|e| WalletError::Config(format!("Invalid derivation path: {}", e)))?;

        // 从种子创建主私钥
        let master_key = XPrv::new(seed)
            .map_err(|e| WalletError::Encryption(format!("Failed to create master key: {}", e)))?;

        // 派生子密钥
        let derived_key = master_key.derive_path(&derivation_path)
            .map_err(|e| WalletError::Encryption(format!("Failed to derive key: {}", e)))?;

        Ok(derived_key.to_bytes().to_vec())
    }

    /// 加密私钥
    pub fn encrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.master_key.into());

        // 生成随机nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 加密
        let ciphertext = cipher.encrypt(nonce, private_key)
            .map_err(|e| WalletError::Encryption(format!("Encryption failed: {}", e)))?;

        // 合并nonce和密文
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// 解密私钥
    pub fn decrypt_private_key(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < 12 {
            return Err(WalletError::Encryption("Invalid encrypted data".to_string()));
        }

        let cipher = Aes256Gcm::new(&self.master_key.into());

        // 提取nonce和密文
        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // 解密
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| WalletError::Encryption(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }

    /// 生成密钥哈希 (用于验证)
    pub fn hash_key(&self, key: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    }

    /// Shamir秘密分享 - 分割密钥
    pub fn split_secret(&self, secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<Vec<u8>>> {
        if threshold > shares || threshold == 0 || shares == 0 {
            return Err(WalletError::Config("Invalid threshold or shares".to_string()));
        }

        // 简化的Shamir实现 (生产环境应使用专业库如sharks)
        // 这里使用简单的XOR分片作为示例
        let mut result = Vec::new();
        let mut rng = rand::thread_rng();

        // 生成shares-1个随机分片
        for _ in 0..shares - 1 {
            let mut share = vec![0u8; secret.len()];
            rng.fill_bytes(&mut share);
            result.push(share);
        }

        // 最后一个分片 = secret XOR (所有其他分片)
        let mut last_share = secret.to_vec();
        for share in &result {
            for (i, &byte) in share.iter().enumerate() {
                last_share[i] ^= byte;
            }
        }
        result.push(last_share);

        // 添加阈值信息 (简化版)
        let threshold_info = vec![threshold, shares];
        for share in &mut result {
            share.splice(0..0, threshold_info.iter().copied());
        }

        Ok(result)
    }

    /// Shamir秘密分享 - 恢复密钥
    pub fn recover_secret(&self, shares: &[Vec<u8>]) -> Result<Vec<u8>> {
        if shares.is_empty() {
            return Err(WalletError::Config("No shares provided".to_string()));
        }

        // 提取阈值信息
        let threshold = shares[0][0];
        let _total_shares = shares[0][1];

        if shares.len() < threshold as usize {
            return Err(WalletError::Config(format!(
                "Insufficient shares: need {}, got {}",
                threshold,
                shares.len()
            )));
        }

        // 恢复原始数据 (XOR所有分片)
        let share_len = shares[0].len() - 2;
        let mut secret = vec![0u8; share_len];

        for share in shares.iter().take(threshold as usize) {
            let share_data = &share[2..];
            for (i, &byte) in share_data.iter().enumerate() {
                secret[i] ^= byte;
            }
        }

        Ok(secret)
    }
}

/// HD钱包管理器
pub struct HDWallet {
    seed: [u8; 64],
    key_manager: KeyManager,
}

impl HDWallet {
    /// 从助记词创建
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str, key_manager: KeyManager) -> Result<Self> {
        let seed = key_manager.mnemonic_to_seed(mnemonic, passphrase)?;
        Ok(Self { seed, key_manager })
    }

    /// 派生Solana密钥 (BIP44: m/44'/501'/0'/0')
    pub fn derive_solana_key(&self, account: u32, index: u32) -> Result<Vec<u8>> {
        let path = format!("m/44'/501'/{}'/{}'", account, index);
        self.key_manager.derive_key(&self.seed, &path)
    }

    /// 派生Ethereum密钥 (BIP44: m/44'/60'/0'/0/)
    pub fn derive_ethereum_key(&self, account: u32, index: u32) -> Result<Vec<u8>> {
        let path = format!("m/44'/60'/{}'/{}'", account, index);
        self.key_manager.derive_key(&self.seed, &path)
    }

    /// 派生Bitcoin密钥 (BIP44: m/44'/0'/0'/0/)
    pub fn derive_bitcoin_key(&self, account: u32, index: u32) -> Result<Vec<u8>> {
        let path = format!("m/44'/0'/{}'/{}'", account, index);
        self.key_manager.derive_key(&self.seed, &path)
    }

    /// 加密并存储私钥
    pub fn encrypt_and_store(&self, private_key: &[u8]) -> Result<String> {
        let encrypted = self.key_manager.encrypt_private_key(private_key)?;
        Ok(hex::encode(encrypted))
    }

    /// 从存储中恢复私钥
    pub fn decrypt_from_storage(&self, encrypted_hex: &str) -> Result<Vec<u8>> {
        let encrypted = hex::decode(encrypted_hex)
            .map_err(|e| WalletError::Encryption(format!("Invalid hex: {}", e)))?;
        self.key_manager.decrypt_private_key(&encrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let key_manager = KeyManager::new([0u8; 32]);
        let mnemonic = key_manager.generate_mnemonic(12).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key_manager = KeyManager::new([1u8; 32]);
        let data = b"test private key";

        let encrypted = key_manager.encrypt_private_key(data).unwrap();
        let decrypted = key_manager.decrypt_private_key(&encrypted).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_shamir_split_recover() {
        let key_manager = KeyManager::new([2u8; 32]);
        let secret = b"my secret key";

        let shares = key_manager.split_secret(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = key_manager.recover_secret(&shares[0..3]).unwrap();
        assert_eq!(secret.as_slice(), recovered.as_slice());
    }
}
