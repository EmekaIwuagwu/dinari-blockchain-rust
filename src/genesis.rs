// src/genesis.rs
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use crate::{
    crypto::{Hash, Address},
    block::{Block, BlockHeader},
    transaction::{Transaction, TransactionType},
    account::{TokenType, Account, AccountManager},
    database::BlockchainDB,
};

/// Genesis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Genesis timestamp
    pub timestamp: DateTime<Utc>,
    /// Initial validator set
    pub validators: Vec<GenesisValidator>,
    /// Initial account balances
    pub balances: HashMap<String, GenesisBalance>,
    /// Network configuration
    pub network: NetworkConfig,
    /// Consensus parameters
    pub consensus: ConsensusParams,
}

/// Genesis validator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub address: String,
    pub stake: u64,
}

/// Genesis account balance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBalance {
    pub dinari: u64,
    pub africoin: u64,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub chain_id: u64,
    pub network_name: String,
}

/// Consensus parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusParams {
    pub block_time_seconds: u64,
    pub max_transactions_per_block: usize,
    pub min_validator_stake: u64,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        let mut balances = HashMap::new();
        
        // Add some initial balances for testing
        balances.insert(
            "DT742d35Cc6634C0532925a3b8D4DBC0f9f2e7C5e9".to_string(),
            GenesisBalance {
                dinari: 1_000_000_000_000, // 1M DINARI
                africoin: 1_000_000_000_000, // 1M AFRICOIN
            }
        );
        
        Self {
            timestamp: Utc::now(),
            validators: vec![
                GenesisValidator {
                    address: "DT742d35Cc6634C0532925a3b8D4DBC0f9f2e7C5e9".to_string(),
                    stake: 100_000_000_000, // 100k stake
                }
            ],
            balances,
            network: NetworkConfig {
                chain_id: 42069, // DinariChain ID
                network_name: "DinariBlockchain".to_string(),
            },
            consensus: ConsensusParams {
                block_time_seconds: 15,
                max_transactions_per_block: 1000,
                min_validator_stake: 10_000_000_000, // 10k minimum stake
            },
        }
    }
}

impl GenesisConfig {
    /// Load genesis config from JSON file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: GenesisConfig = serde_json::from_str(&content)?;
        Ok(config)
    }
    
    /// Save genesis config to JSON file
    pub fn to_file(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    /// Create the genesis block from this configuration
    pub fn create_genesis_block(&self) -> Result<Block> {
        // Create genesis transactions for initial balances
        let mut transactions = Vec::new();
        
        for (address_str, balance) in &self.balances {
            // Create transaction to mint initial DINARI
            if balance.dinari > 0 {
                let address = Address::from_hex(address_str)?;
                let tx = Transaction::mint(
                    address,
                    balance.dinari,
                    TokenType::DINARI,
                )?;
                transactions.push(tx);
            }
            
            // Create transaction to mint initial AFRICOIN  
            if balance.africoin > 0 {
                let address = Address::from_hex(address_str)?;
                let tx = Transaction::mint(
                    address,
                    balance.africoin,
                    TokenType::AFRICOIN,
                )?;
                transactions.push(tx);
            }
        }
        
        // Calculate transaction root
        let transactions_root = self.calculate_transactions_root(&transactions)?;
        
        // Create account manager with genesis balances to calculate state root
        let mut account_manager = AccountManager::new();
        for (address_str, balance) in &self.balances {
            let account = Account::with_balances(
                address_str.clone(),
                balance.dinari,
                balance.africoin,
            )?;
            account_manager.update_account(account);
        }
        let state_root = Block::calculate_state_root(&account_manager)?;
        
        // Get first validator as genesis block producer
        let validator_address = self.validators.first()
            .map(|v| v.address.clone())
            .unwrap_or_else(|| "DT0000000000000000000000000000000000000000".to_string());
        
        // Create genesis block header
        let header = BlockHeader {
            block_number: 0,
            parent_hash: String::new(), // Genesis has no parent
            timestamp: self.timestamp,
            state_root,
            tx_root: transactions_root.clone(),
            validator_address,
            validator_signature: String::new(), // Genesis doesn't need signature
            nonce: 0,
            transactions_root, // Copy for compatibility
        };
        
        // Create genesis block
        let genesis_block = Block {
            header,
            transactions,
        };
        
        Ok(genesis_block)
    }
    
    /// Calculate transactions merkle root
    fn calculate_transactions_root(&self, transactions: &[Transaction]) -> Result<String> {
        if transactions.is_empty() {
            return Ok(crate::utils::bytes_to_hex(&[0u8; 32]));
        }
        
        // Simple implementation - hash all transaction hashes together
        let mut hasher = blake3::Hasher::new();
        for tx in transactions {
            let tx_hash = tx.hash()?;
            hasher.update(tx_hash.as_bytes());
        }
        
        let result = hasher.finalize();
        Ok(crate::utils::bytes_to_hex(result.as_bytes()))
    }
    
    /// Generate a default genesis.json file
    pub fn generate_default_genesis_file(path: &str) -> Result<()> {
        let config = GenesisConfig::default();
        config.to_file(path)?;
        println!("📄 Generated default genesis.json at: {}", path);
        println!("💡 Edit this file to customize validators and initial balances");
        Ok(())
    }
    
    /// Validate the genesis configuration
    pub fn validate(&self) -> Result<()> {
        // Check that we have at least one validator
        if self.validators.is_empty() {
            return Err(anyhow!("Genesis config must have at least one validator"));
        }
        
        // Check validator stakes meet minimum
        for validator in &self.validators {
            if validator.stake < self.consensus.min_validator_stake {
                return Err(anyhow!(
                    "Validator {} stake {} below minimum {}",
                    validator.address,
                    validator.stake,
                    self.consensus.min_validator_stake
                ));
            }
        }
        
        // Check network parameters
        if self.network.chain_id == 0 {
            return Err(anyhow!("Chain ID cannot be zero"));
        }
        
        if self.consensus.block_time_seconds == 0 {
            return Err(anyhow!("Block time must be positive"));
        }
        
        // Validate all addresses
        for (address, _) in &self.balances {
            if !crate::utils::validate_address(address)? {
                return Err(anyhow!("Invalid address in genesis balances: {}", address));
            }
        }
        
        for validator in &self.validators {
            if !crate::utils::validate_address(&validator.address)? {
                return Err(anyhow!("Invalid validator address: {}", validator.address));
            }
        }
        
        Ok(())
    }
    
    /// Get total supply of each token from genesis
    pub fn get_total_supply(&self) -> (u64, u64) {
        let mut total_dinari = 0u64;
        let mut total_africoin = 0u64;
        
        for balance in self.balances.values() {
            total_dinari += balance.dinari;
            total_africoin += balance.africoin;
        }
        
        (total_dinari, total_africoin)
    }
    
    /// Display genesis configuration summary
    pub fn display_summary(&self) {
        println!("📋 Genesis Configuration Summary:");
        println!("   Network: {} (Chain ID: {})", self.network.network_name, self.network.chain_id);
        println!("   Validators: {}", self.validators.len());
        println!("   Genesis Accounts: {}", self.balances.len());
        
        let (total_dinari, total_africoin) = self.get_total_supply();
        println!("   Total DINARI: {}", total_dinari);
        println!("   Total AFRICOIN: {}", total_africoin);
        
        println!("   Block Time: {}s", self.consensus.block_time_seconds);
        println!("   Max Transactions/Block: {}", self.consensus.max_transactions_per_block);
        println!("   Timestamp: {}", self.timestamp);
    }
}

/// Genesis block utilities
pub struct GenesisBuilder;

impl GenesisBuilder {
    /// Initialize blockchain with genesis block
    pub fn initialize_blockchain(
        genesis_config: &GenesisConfig, 
        db: &BlockchainDB
    ) -> Result<Block> {
        println!("🌱 Initializing blockchain with genesis block...");
        
        // Validate genesis config
        genesis_config.validate()?;
        
        // Display summary
        genesis_config.display_summary();
        
        // Create genesis block
        let genesis_block = genesis_config.create_genesis_block()?;
        let genesis_hash = genesis_block.hash()?;
        
        // Store genesis block in database
        db.store_block(&genesis_block)?;
        
        // Set as best block and genesis marker
        db.set_best_block(genesis_hash)?;
        db.set_genesis_block(genesis_hash.as_bytes())?;
        db.set_block_height(0)?;
        
        // Store block by number index
        db.store_block_by_number(0, &genesis_hash)?;
        
        // Initialize account balances from genesis
        for (address_str, balance) in &genesis_config.balances {
            let address = Address::from_hex(address_str)?;
            
            if balance.dinari > 0 {
                db.set_balance(&address, TokenType::DINARI, balance.dinari)?;
            }
            
            if balance.africoin > 0 {
                db.set_balance(&address, TokenType::AFRICOIN, balance.africoin)?;
            }
        }
        
        // Update chain info
        db.update_chain_info_for_block(&genesis_block)?;
        
        println!("✅ Genesis block initialized successfully!");
        println!("   Block Number: {}", genesis_block.header.block_number);
        println!("   Block Hash: {}", genesis_block.calculate_hash());
        println!("   Transactions: {}", genesis_block.transactions.len());
        println!("   Validators: {}", genesis_config.validators.len());
        println!("   Accounts: {}", genesis_config.balances.len());
        
        Ok(genesis_block)
    }
    
    /// Create genesis configuration with custom parameters
    pub fn create_custom_genesis(
        chain_id: u64,
        network_name: String,
        validators: Vec<(String, u64)>, // (address, stake)
        balances: Vec<(String, u64, u64)>, // (address, dinari, africoin)
        block_time_seconds: u64,
    ) -> Result<GenesisConfig> {
        let mut genesis_balances = HashMap::new();
        let mut genesis_validators = Vec::new();
        
        // Add balances
        for (address, dinari, africoin) in balances {
            // Validate address
            if !crate::utils::validate_address(&address)? {
                return Err(anyhow!("Invalid address: {}", address));
            }
            
            genesis_balances.insert(address, GenesisBalance { dinari, africoin });
        }
        
        // Add validators
        for (address, stake) in validators {
            // Validate address
            if !crate::utils::validate_address(&address)? {
                return Err(anyhow!("Invalid validator address: {}", address));
            }
            
            genesis_validators.push(GenesisValidator { address, stake });
        }
        
        let config = GenesisConfig {
            timestamp: Utc::now(),
            validators: genesis_validators,
            balances: genesis_balances,
            network: NetworkConfig {
                chain_id,
                network_name,
            },
            consensus: ConsensusParams {
                block_time_seconds,
                max_transactions_per_block: 1000,
                min_validator_stake: 10_000_000_000,
            },
        };
        
        // Validate the configuration
        config.validate()?;
        
        Ok(config)
    }
    
    /// Create test genesis for development
    pub fn create_test_genesis() -> Result<GenesisConfig> {
        // Create some test wallets
        let test_wallets = vec![
            "DT1111111111111111111111111111111111111111",
            "DT2222222222222222222222222222222222222222", 
            "DT3333333333333333333333333333333333333333",
        ];
        
        let validators = vec![
            (test_wallets[0].to_string(), 50_000_000_000), // 50k stake
            (test_wallets[1].to_string(), 30_000_000_000), // 30k stake
        ];
        
        let balances = vec![
            (test_wallets[0].to_string(), 1_000_000_000, 500_000_000), // 1B DINARI, 500M AFRICOIN
            (test_wallets[1].to_string(), 500_000_000, 1_000_000_000), // 500M DINARI, 1B AFRICOIN
            (test_wallets[2].to_string(), 100_000_000, 100_000_000),   // 100M each
        ];
        
        Self::create_custom_genesis(
            12345, // Test chain ID
            "DinariBlockchain-Testnet".to_string(),
            validators,
            balances,
            10, // 10 second blocks for testing
        )
    }
    
    /// Verify genesis block matches configuration
    pub fn verify_genesis_block(genesis_config: &GenesisConfig, genesis_block: &Block) -> Result<()> {
        // Check block number is 0
        if genesis_block.header.block_number != 0 {
            return Err(anyhow!("Genesis block number must be 0"));
        }
        
        // Check parent hash is empty
        if !genesis_block.header.parent_hash.is_empty() {
            return Err(anyhow!("Genesis block parent hash must be empty"));
        }
        
        // Verify transactions match expected genesis transactions
        let expected_tx_count = genesis_config.balances.values()
            .map(|balance| {
                let mut count = 0;
                if balance.dinari > 0 { count += 1; }
                if balance.africoin > 0 { count += 1; }
                count
            })
            .sum::<usize>();
        
        if genesis_block.transactions.len() != expected_tx_count {
            return Err(anyhow!(
                "Genesis block transaction count mismatch: expected {}, got {}",
                expected_tx_count,
                genesis_block.transactions.len()
            ));
        }
        
        // Verify all transactions are mint transactions
        for tx in &genesis_block.transactions {
            if !tx.is_mint() {
                return Err(anyhow!("Genesis block should only contain mint transactions"));
            }
        }
        
        println!("✅ Genesis block verification passed");
        Ok(())
    }
}

/// Utility functions for genesis system
impl GenesisConfig {
    /// Add validator to genesis config
    pub fn add_validator(&mut self, address: String, stake: u64) -> Result<()> {
        // Validate address
        if !crate::utils::validate_address(&address)? {
            return Err(anyhow!("Invalid validator address: {}", address));
        }
        
        // Check minimum stake
        if stake < self.consensus.min_validator_stake {
            return Err(anyhow!(
                "Validator stake {} below minimum {}",
                stake,
                self.consensus.min_validator_stake
            ));
        }
        
        // Check if validator already exists
        if self.validators.iter().any(|v| v.address == address) {
            return Err(anyhow!("Validator {} already exists", address));
        }
        
        self.validators.push(GenesisValidator { address, stake });
        Ok(())
    }
    
    /// Add initial balance to genesis config
    pub fn add_balance(&mut self, address: String, dinari: u64, africoin: u64) -> Result<()> {
        // Validate address
        if !crate::utils::validate_address(&address)? {
            return Err(anyhow!("Invalid address: {}", address));
        }
        
        self.balances.insert(address, GenesisBalance { dinari, africoin });
        Ok(())
    }
    
    /// Remove validator from genesis config
    pub fn remove_validator(&mut self, address: &str) -> bool {
        let initial_len = self.validators.len();
        self.validators.retain(|v| v.address != address);
        self.validators.len() < initial_len
    }
    
    /// Remove balance from genesis config
    pub fn remove_balance(&mut self, address: &str) -> bool {
        self.balances.remove(address).is_some()
    }
    
    /// Update network configuration
    pub fn update_network(&mut self, chain_id: u64, network_name: String) {
        self.network.chain_id = chain_id;
        self.network.network_name = network_name;
    }
    
    /// Update consensus parameters
    pub fn update_consensus(&mut self, block_time_seconds: u64, max_transactions_per_block: usize, min_validator_stake: u64) {
        self.consensus.block_time_seconds = block_time_seconds;
        self.consensus.max_transactions_per_block = max_transactions_per_block;
        self.consensus.min_validator_stake = min_validator_stake;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_genesis_config_creation() {
        let config = GenesisConfig::default();
        
        assert!(!config.validators.is_empty());
        assert!(!config.balances.is_empty());
        assert_eq!(config.network.chain_id, 42069);
        assert_eq!(config.consensus.block_time_seconds, 15);
        
        // Should validate successfully
        config.validate().unwrap();
    }

    #[test] 
    fn test_genesis_config_file_operations() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_genesis.json");
        let file_path_str = file_path.to_str().unwrap();
        
        let config = GenesisConfig::default();
        
        // Save to file
        config.to_file(file_path_str).unwrap();
        
        // Load from file
        let loaded_config = GenesisConfig::from_file(file_path_str).unwrap();
        
        assert_eq!(config.network.chain_id, loaded_config.network.chain_id);
        assert_eq!(config.validators.len(), loaded_config.validators.len());
        assert_eq!(config.balances.len(), loaded_config.balances.len());
    }

    #[test]
    fn test_genesis_block_creation() {
        let config = GenesisConfig::default();
        let genesis_block = config.create_genesis_block().unwrap();
        
        assert_eq!(genesis_block.header.block_number, 0);
        assert!(genesis_block.header.parent_hash.is_empty());
        assert!(!genesis_block.transactions.is_empty());
        assert!(genesis_block.is_genesis());
        
        // All transactions should be mint transactions
        for tx in &genesis_block.transactions {
            assert!(tx.is_mint());
            assert_eq!(tx.gas_fee, 0); // Genesis mints don't pay gas
        }
    }

    #[test]
    fn test_custom_genesis_creation() {
        let validators = vec![
            ("DT1111111111111111111111111111111111111111".to_string(), 50_000_000_000),
            ("DT2222222222222222222222222222222222222222".to_string(), 30_000_000_000),
        ];
        
        let balances = vec![
            ("DT1111111111111111111111111111111111111111".to_string(), 1_000_000, 500_000),
            ("DT2222222222222222222222222222222222222222".to_string(), 2_000_000, 1_000_000),
        ];
        
        let config = GenesisBuilder::create_custom_genesis(
            9999,
            "TestChain".to_string(), 
            validators,
            balances,
            20,
        ).unwrap();
        
        assert_eq!(config.network.chain_id, 9999);
        assert_eq!(config.network.network_name, "TestChain");
        assert_eq!(config.validators.len(), 2);
        assert_eq!(config.balances.len(), 2);
        assert_eq!(config.consensus.block_time_seconds, 20);
        
        // Should validate successfully
        config.validate().unwrap();
    }

    #[test]
    fn test_test_genesis_creation() {
        let config = GenesisBuilder::create_test_genesis().unwrap();
        
        assert_eq!(config.network.chain_id, 12345);
        assert!(config.network.network_name.contains("Testnet"));
        assert_eq!(config.validators.len(), 2);
        assert_eq!(config.balances.len(), 3);
        assert_eq!(config.consensus.block_time_seconds, 10);
        
        // Should validate successfully
        config.validate().unwrap();
    }

    #[test]
    fn test_genesis_config_validation() {
        let mut config = GenesisConfig::default();
        
        // Should validate initially
        config.validate().unwrap();
        
        // Remove all validators - should fail
        config.validators.clear();
        assert!(config.validate().is_err());
        
        // Add validator back
        config.add_validator("DT1111111111111111111111111111111111111111".to_string(), 50_000_000_000).unwrap();
        
        // Set zero chain ID - should fail
        config.network.chain_id = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_genesis_config_manipulation() {
        let mut config = GenesisConfig::default();
        
        // Add validator
        config.add_validator("DT9999999999999999999999999999999999999999".to_string(), 25_000_000_000).unwrap();
        
        // Add balance
        config.add_balance("DT8888888888888888888888888888888888888888".to_string(), 1_000_000, 2_000_000).unwrap();
        
        // Remove validator
        let removed = config.remove_validator("DT9999999999999999999999999999999999999999");
        assert!(removed);
        
        // Remove balance
        let removed = config.remove_balance("DT8888888888888888888888888888888888888888");
        assert!(removed);
        
        // Should still validate
        config.validate().unwrap();
    }

    #[test]
    fn test_total_supply_calculation() {
        let config = GenesisConfig::default();
        let (total_dinari, total_africoin) = config.get_total_supply();
        
        // Should match the default genesis balances
        assert!(total_dinari > 0);
        assert!(total_africoin > 0);
        
        // Should equal sum of individual balances
        let mut expected_dinari = 0;
        let mut expected_africoin = 0;
        for balance in config.balances.values() {
            expected_dinari += balance.dinari;
            expected_africoin += balance.africoin;
        }
        
        assert_eq!(total_dinari, expected_dinari);
        assert_eq!(total_africoin, expected_africoin);
    }
}