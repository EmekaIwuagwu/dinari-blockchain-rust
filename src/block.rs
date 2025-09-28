// src/block.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use anyhow::{Result, anyhow};
use sha2::{Digest, Sha256};
use crate::{
    transaction::Transaction,
    account::AccountManager,
    crypto::{CryptoEngine, Hash, Address},
    utils,
};

/// Block header containing metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    pub block_number: u64,
    pub parent_hash: String,
    pub timestamp: DateTime<Utc>,
    pub state_root: String,        // Merkle root of account states
    pub tx_root: String,           // Merkle root of transactions
    pub validator_address: String,  // DT-prefixed validator address
    pub validator_signature: String, // Hex-encoded signature
    pub nonce: u64,                // For future use (PoW upgrade path)
    
    // Additional fields for compatibility
    pub transactions_root: String, // Alias for tx_root (for genesis compatibility)
}

impl BlockHeader {
    /// Create new block header
    pub fn new(
        block_number: u64,
        parent_hash: String,
        state_root: String,
        tx_root: String,
        validator_address: String,
    ) -> Result<Self> {
        // Validate validator address
        if !utils::validate_address(&validator_address)? {
            return Err(anyhow!("Invalid validator address: {}", validator_address));
        }

        Ok(Self {
            block_number,
            parent_hash: parent_hash.clone(),
            timestamp: Utc::now(),
            state_root,
            tx_root: tx_root.clone(),
            validator_address,
            validator_signature: String::new(),
            nonce: 0,
            transactions_root: tx_root, // Copy for compatibility
        })
    }

    /// Calculate header hash for signing
    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        
        // Include all fields except signature in deterministic order
        hasher.update(&self.block_number.to_be_bytes());
        hasher.update(self.parent_hash.as_bytes());
        hasher.update(&(self.timestamp.timestamp() as u64).to_be_bytes());
        hasher.update(self.state_root.as_bytes());
        hasher.update(self.tx_root.as_bytes());
        hasher.update(self.validator_address.as_bytes());
        hasher.update(&self.nonce.to_be_bytes());
        
        utils::bytes_to_hex(&hasher.finalize())
    }

    /// Calculate header hash as Hash type
    pub fn hash(&self) -> Result<Hash> {
        let hash_string = self.calculate_hash();
        let hash_bytes = utils::hex_to_bytes(&hash_string)?;
        if hash_bytes.len() != 32 {
            return Err(anyhow!("Invalid hash length"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash_bytes);
        Ok(Hash::from_bytes(bytes))
    }

    /// Sign the block header
    pub fn sign(&mut self, crypto: &CryptoEngine, validator_secret: &secp256k1::SecretKey) -> Result<()> {
        if !self.validator_signature.is_empty() {
            return Err(anyhow!("Block header already signed"));
        }

        let hash = self.calculate_hash();
        let signature = crypto.sign_message(hash.as_bytes(), validator_secret)?;
        self.validator_signature = utils::bytes_to_hex(&signature);
        
        Ok(())
    }

    /// Verify the block header signature
    pub fn verify_signature(&self, crypto: &CryptoEngine) -> Result<bool> {
        if self.validator_signature.is_empty() {
            return Ok(false);
        }

        // Decode signature from hex
        let signature = utils::hex_to_bytes(&self.validator_signature)?;
        if signature.len() != 65 {
            return Ok(false);
        }

        // Calculate hash without signature
        let mut temp_header = self.clone();
        temp_header.validator_signature = String::new();
        let hash = temp_header.calculate_hash();

        // Recover public key from signature
        let recovered_pubkey = crypto.recover_public_key(hash.as_bytes(), &signature)?;
        
        // Generate address from recovered public key
        let recovered_address = utils::generate_address(&recovered_pubkey);
        
        // Verify it matches the validator address
        Ok(recovered_address == self.validator_address)
    }

    /// Validate header format and constraints
    pub fn validate_format(&self) -> Result<()> {
        // Validate validator address
        if !utils::validate_address(&self.validator_address)? {
            return Err(anyhow!("Invalid validator address format"));
        }

        // Validate parent hash format (should be hex)
        if !self.parent_hash.is_empty() && utils::hex_to_bytes(&self.parent_hash).is_err() {
            return Err(anyhow!("Invalid parent hash format"));
        }

        // Validate roots are hex strings
        if utils::hex_to_bytes(&self.state_root).is_err() {
            return Err(anyhow!("Invalid state root format"));
        }
        if utils::hex_to_bytes(&self.tx_root).is_err() {
            return Err(anyhow!("Invalid transaction root format"));
        }

        // Validate signature is hex
        if !self.validator_signature.is_empty() && utils::hex_to_bytes(&self.validator_signature).is_err() {
            return Err(anyhow!("Invalid validator signature format"));
        }

        // Validate timestamp
        if !utils::validate_timestamp(self.timestamp.timestamp() as u64) {
            return Err(anyhow!("Invalid timestamp: too old or too far in future"));
        }

        Ok(())
    }
}

/// Complete block containing header and transactions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Create new block
    pub fn new(
        block_number: u64,
        parent_hash: String,
        transactions: Vec<Transaction>,
        validator_address: String,
        account_manager: &AccountManager,
    ) -> Result<Self> {
        // Calculate transaction root
        let tx_root = Self::calculate_transaction_root(&transactions);
        
        // Calculate state root from current account states
        let state_root = Self::calculate_state_root(account_manager)?;
        
        // Create header
        let header = BlockHeader::new(
            block_number,
            parent_hash,
            state_root,
            tx_root,
            validator_address,
        )?;

        Ok(Self {
            header,
            transactions,
        })
    }

    /// Create genesis block (block 0)
    pub fn genesis(
        genesis_accounts: Vec<crate::account::Account>,
        validator_address: String,
    ) -> Result<Self> {
        // Create account manager with genesis accounts
        let mut account_manager = AccountManager::new();
        for account in genesis_accounts {
            account_manager.update_account(account);
        }

        // Genesis block has no transactions
        let transactions = Vec::new();
        
        Self::new(
            0,
            String::new(), // Genesis has no parent
            transactions,
            validator_address,
            &account_manager,
        )
    }

    /// Sign the entire block
    pub fn sign(&mut self, crypto: &CryptoEngine, validator_secret: &secp256k1::SecretKey) -> Result<()> {
        self.header.sign(crypto, validator_secret)
    }

    /// Calculate block hash (hash of header) - returns String
    pub fn calculate_hash(&self) -> String {
        self.header.calculate_hash()
    }

    /// Calculate block hash as Hash type (for compatibility with consensus)
    pub fn hash(&self) -> Result<Hash> {
        self.header.hash()
    }

    /// Calculate Merkle root of transactions
    pub fn calculate_transaction_root(transactions: &[Transaction]) -> String {
        if transactions.is_empty() {
            // Empty transactions get a special empty root
            return crate::utils::bytes_to_hex(&[0u8; 32]);
        }

        // Get transaction hashes as bytes
        let mut tx_hashes: Vec<Vec<u8>> = transactions
            .iter()
            .map(|tx| tx.calculate_hash()) // This returns Vec<u8>
            .collect();

        // Build Merkle tree
        while tx_hashes.len() > 1 {
            let mut next_level = Vec::new();
            
            // Process pairs
            let mut i = 0;
            while i < tx_hashes.len() {
                let left = &tx_hashes[i];
                let right = if i + 1 < tx_hashes.len() {
                    &tx_hashes[i + 1]
                } else {
                    // Odd number: duplicate the last hash
                    &tx_hashes[i]
                };
                
                // Hash the concatenation
                let mut hasher = Sha256::new();
                hasher.update(left);
                hasher.update(right);
                next_level.push(hasher.finalize().to_vec());
                
                i += 2;
            }
            
            tx_hashes = next_level;
        }

        crate::utils::bytes_to_hex(&tx_hashes[0])
    }

    /// Calculate state root from account manager
    pub fn calculate_state_root(account_manager: &AccountManager) -> Result<String> {
        let accounts = account_manager.get_all_accounts();
        
        if accounts.is_empty() {
            return Ok(utils::bytes_to_hex(&[0u8; 32]));
        }

        // Create sorted list of account hashes for deterministic root
        let mut account_hashes: Vec<Vec<u8>> = accounts
            .values()
            .map(|account| {
                let serialized = bincode::serialize(account).unwrap_or_default();
                utils::hash_data(&serialized)
            })
            .collect();

        // Sort for deterministic ordering
        account_hashes.sort();

        // Build Merkle tree
        while account_hashes.len() > 1 {
            let mut next_level = Vec::new();
            
            let mut i = 0;
            while i < account_hashes.len() {
                let left = &account_hashes[i];
                let right = if i + 1 < account_hashes.len() {
                    &account_hashes[i + 1]
                } else {
                    &account_hashes[i]
                };
                
                let mut hasher = Sha256::new();
                hasher.update(left);
                hasher.update(right);
                next_level.push(hasher.finalize().to_vec());
                
                i += 2;
            }
            
            account_hashes = next_level;
        }

        Ok(utils::bytes_to_hex(&account_hashes[0]))
    }

    /// Validate the entire block
    pub fn validate(&self, parent_block: Option<&Block>, account_manager: &AccountManager, crypto: &CryptoEngine) -> Result<()> {
        // Validate header format
        self.header.validate_format()?;

        // Validate parent relationship
        if let Some(parent) = parent_block {
            if self.header.block_number != parent.header.block_number + 1 {
                return Err(anyhow!(
                    "Invalid block number: expected {}, got {}",
                    parent.header.block_number + 1,
                    self.header.block_number
                ));
            }
            
            if self.header.parent_hash != parent.calculate_hash() {
                return Err(anyhow!("Invalid parent hash"));
            }
        } else if self.header.block_number == 0 {
            // Genesis block should have empty parent hash
            if !self.header.parent_hash.is_empty() {
                return Err(anyhow!("Genesis block should have empty parent hash"));
            }
        } else {
            return Err(anyhow!("Non-genesis block must have parent"));
        }

        // Validate header signature
        if !self.header.verify_signature(crypto)? {
            return Err(anyhow!("Invalid block signature"));
        }

        // Validate transaction root
        let calculated_tx_root = Self::calculate_transaction_root(&self.transactions);
        if self.header.tx_root != calculated_tx_root {
            return Err(anyhow!("Invalid transaction root"));
        }

        // Validate state root
        let calculated_state_root = Self::calculate_state_root(account_manager)?;
        if self.header.state_root != calculated_state_root {
            return Err(anyhow!("Invalid state root"));
        }

        // Validate all transactions
        for (i, tx) in self.transactions.iter().enumerate() {
            tx.validate_format().map_err(|e| {
                anyhow!("Transaction {} validation failed: {}", i, e)
            })?;
            
            // Verify transaction signatures
            if !tx.verify_signature(crypto)? {
                return Err(anyhow!("Transaction {} has invalid signature", i));
            }
        }

        Ok(())
    }

    /// Validate transactions against account state (before execution)
    pub fn validate_transactions(&self, account_manager: &AccountManager) -> Result<()> {
        for tx in &self.transactions {
            tx.validate(account_manager).map_err(|e| {
                anyhow!("Transaction {} validation failed: {}", tx.tx_id, e)
            })?;
        }
        Ok(())
    }

    /// Execute all transactions in the block
    pub fn execute_transactions(&self, account_manager: &mut AccountManager) -> Result<()> {
        for tx in &self.transactions {
            tx.execute(account_manager).map_err(|e| {
                anyhow!("Transaction {} execution failed: {}", tx.tx_id, e)
            })?;
        }
        Ok(())
    }

    /// Get block size in bytes
    pub fn size_bytes(&self) -> usize {
        bincode::serialize(self).map(|data| data.len()).unwrap_or(0)
    }

    /// Check if block is genesis
    pub fn is_genesis(&self) -> bool {
        self.header.block_number == 0 && self.header.parent_hash.is_empty()
    }

    /// Get block summary for display
    pub fn summary(&self) -> String {
        format!(
            "Block #{} | {} TXs | Validator: {} | Hash: {} | Size: {} bytes",
            self.header.block_number,
            self.transactions.len(),
            &self.header.validator_address[..10], // First 10 chars
            &self.calculate_hash()[..12],         // First 12 chars
            self.size_bytes()
        )
    }

    /// Serialize block for storage
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Failed to serialize block: {}", e))
    }

    /// Deserialize block from storage
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Failed to deserialize block: {}", e))
    }
}

/// Block builder for easier construction
pub struct BlockBuilder {
    block_number: Option<u64>,
    parent_hash: Option<String>,
    transactions: Vec<Transaction>,
    validator_address: Option<String>,
}

impl BlockBuilder {
    pub fn new() -> Self {
        Self {
            block_number: None,
            parent_hash: None,
            transactions: Vec::new(),
            validator_address: None,
        }
    }

    pub fn block_number(mut self, block_number: u64) -> Self {
        self.block_number = Some(block_number);
        self
    }

    pub fn parent_hash(mut self, parent_hash: String) -> Self {
        self.parent_hash = Some(parent_hash);
        self
    }

    pub fn add_transaction(mut self, transaction: Transaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    pub fn add_transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions.extend(transactions);
        self
    }

    pub fn validator(mut self, validator_address: String) -> Self {
        self.validator_address = Some(validator_address);
        self
    }

    pub fn build(self, account_manager: &AccountManager) -> Result<Block> {
        Block::new(
            self.block_number.ok_or_else(|| anyhow!("Block number required"))?,
            self.parent_hash.unwrap_or_default(),
            self.transactions,
            self.validator_address.ok_or_else(|| anyhow!("Validator address required"))?,
            account_manager,
        )
    }
}

impl Default for BlockBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::Wallet,
        account::{Account, TokenType},
        transaction::Transaction,
    };

    #[test]
    fn test_block_creation() {
        let validator_wallet = Wallet::new();
        let account_manager = AccountManager::new();
        
        let block = Block::new(
            1,
            "parent_hash_123".to_string(),
            Vec::new(),
            validator_wallet.address().to_string(),
            &account_manager,
        ).unwrap();
        
        assert_eq!(block.header.block_number, 1);
        assert_eq!(block.header.parent_hash, "parent_hash_123");
        assert!(block.transactions.is_empty());
        assert_eq!(block.header.validator_address, validator_wallet.address());
    }

    #[test]
    fn test_genesis_block() {
        let validator_wallet = Wallet::new();
        let genesis_account = Account::with_balances(
            "DTgenesis123".to_string(),
            1000000,
            1000000,
        ).unwrap();
        
        let genesis_block = Block::genesis(
            vec![genesis_account],
            validator_wallet.address().to_string(),
        ).unwrap();
        
        assert!(genesis_block.is_genesis());
        assert_eq!(genesis_block.header.block_number, 0);
        assert!(genesis_block.header.parent_hash.is_empty());
        assert!(genesis_block.transactions.is_empty());
    }

    #[test]
    fn test_block_hashing() {
        let validator_wallet = Wallet::new();
        let account_manager = AccountManager::new();
        
        let block = Block::new(
            1,
            "parent_hash_123".to_string(),
            Vec::new(),
            validator_wallet.address().to_string(),
            &account_manager,
        ).unwrap();
        
        // Test both hash methods
        let hash_string = block.calculate_hash();
        let hash_type = block.hash().unwrap();
        
        assert!(!hash_string.is_empty());
        assert_eq!(hash_string.len(), 64); // 32 bytes as hex = 64 chars
        assert_eq!(hash_type.to_hex(), format!("0x{}", hash_string));
    }

    #[test]
    fn test_block_signing_and_verification() {
        let crypto = CryptoEngine::new();
        let (validator_secret, _) = crypto.generate_keypair();
        let validator_address = utils::generate_address_from_secret(&validator_secret);
        let account_manager = AccountManager::new();
        
        let mut block = Block::new(
            1,
            "parent_hash".to_string(),
            Vec::new(),
            validator_address,
            &account_manager,
        ).unwrap();
        
        // Sign block
        block.sign(&crypto, &validator_secret).unwrap();
        assert!(!block.header.validator_signature.is_empty());
        
        // Verify signature
        assert!(block.header.verify_signature(&crypto).unwrap());
    }

    #[test]
    fn test_merkle_root_calculation() {
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::new();
        
        // Create test transactions
        let tx1 = Transaction::new(
            wallet1.address().to_string(),
            wallet2.address().to_string(),
            100,
            TokenType::DINARI,
            1,
            5,
        ).unwrap();
        
        let tx2 = Transaction::new(
            wallet2.address().to_string(),
            wallet1.address().to_string(),
            50,
            TokenType::AFRICOIN,
            1,
            3,
        ).unwrap();
        
        let transactions = vec![tx1, tx2];
        
        // Calculate root
        let root = Block::calculate_transaction_root(&transactions);
        assert!(!root.is_empty());
        assert_eq!(root.len(), 64); // 32 bytes hex = 64 chars
        
        // Empty transactions should give different root
        let empty_root = Block::calculate_transaction_root(&[]);
        assert_ne!(root, empty_root);
    }

    #[test]
    fn test_block_validation() {
        let crypto = CryptoEngine::new();
        let (validator_secret, _) = crypto.generate_keypair();
        let validator_address = utils::generate_address_from_secret(&validator_secret);
        let account_manager = AccountManager::new();
        
        // Create parent block
        let mut parent_block = Block::new(
            0,
            String::new(),
            Vec::new(),
            validator_address.clone(),
            &account_manager,
        ).unwrap();
        parent_block.sign(&crypto, &validator_secret).unwrap();
        
        // Create child block
        let mut child_block = Block::new(
            1,
            parent_block.calculate_hash(),
            Vec::new(),
            validator_address,
            &account_manager,
        ).unwrap();
        child_block.sign(&crypto, &validator_secret).unwrap();
        
        // Should validate successfully
        child_block.validate(Some(&parent_block), &account_manager, &crypto).unwrap();
    }
}