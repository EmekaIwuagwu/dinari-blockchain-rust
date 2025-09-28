// src/database.rs
use rocksdb::{DB, Options, WriteBatch, Direction, IteratorMode};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::path::Path;
use crate::{
    account::{Account, TokenType},
    transaction::Transaction,
    block::Block,
    crypto::Wallet,
};

/// Database key prefixes for organized storage
const BLOCK_PREFIX: &str = "blocks/";
const TRANSACTION_PREFIX: &str = "txs/";
const ACCOUNT_PREFIX: &str = "state/";
const VALIDATORS_KEY: &str = "validators";
const CHAIN_INFO_KEY: &str = "chain_info";
const BLOCK_HASH_PREFIX: &str = "block_hash/";
const BLOCK_BY_NUMBER_PREFIX: &str = "block_num/";
const GENESIS_BLOCK_KEY: &str = "genesis_block";
const BEST_BLOCK_KEY: &str = "best_block";
const BLOCK_HEIGHT_KEY: &str = "block_height";
const BALANCE_PREFIX: &str = "balance/";

/// Chain metadata information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub latest_block_number: u64,
    pub latest_block_hash: String,
    pub total_transactions: u64,
    pub genesis_hash: String,
    pub chain_id: String,
}

impl Default for ChainInfo {
    fn default() -> Self {
        Self {
            latest_block_number: 0,
            latest_block_hash: String::new(),
            total_transactions: 0,
            genesis_hash: String::new(),
            chain_id: "dinari-mainnet".to_string(),
        }
    }
}

/// Validator information for PoA consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<ValidatorInfo>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: String,
    pub public_key: String,
    pub is_active: bool,
    pub added_at: chrono::DateTime<chrono::Utc>,
}

/// RocksDB-based blockchain database
pub struct BlockchainDB {
    db: DB,
    path: String,
}

impl BlockchainDB {
    /// Create or open blockchain database
    pub fn new(path: &str) -> Result<Self> {
        // Create directory if it doesn't exist
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Configure RocksDB options for blockchain use
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        
        // Optimize for SSD and memory efficiency
        opts.set_max_open_files(1000);
        opts.set_use_fsync(false);
        opts.set_bytes_per_sync(1048576);
        opts.set_disable_auto_compactions(false);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        
        // Memory optimization for 1GB nodes
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        opts.set_max_write_buffer_number(3);
        opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB

        let db = DB::open(&opts, path)?;
        
        Ok(Self {
            db,
            path: path.to_string(),
        })
    }

    // === TREASURY OPERATIONS (NEW) ===

    /// Treasury mint operation - directly modify account balance
    pub fn treasury_mint_tokens(
        &self,
        to_address: &str,
        amount: u64,
        token_type: TokenType,
        authorized_by: &str,
    ) -> Result<String> {
        // Validate authorization
        let authorized_addresses = vec![
            "DT53GRdiJrYAjbJbt6QPxcCXcu27xiTenCN".to_string(),
            "DTFoundation1234567890ABCDEF".to_string(),
        ];
        
        if !authorized_addresses.contains(&authorized_by.to_string()) {
            return Err(anyhow!("Address {} not authorized for treasury operations", authorized_by));
        }

        // Get or create recipient account
        let mut account = match self.get_account(to_address)? {
            Some(acc) => acc,
            None => Account::new(to_address.to_string())?,
        };

        // Add minted tokens
        account.add_balance(&token_type, amount)?;
        
        // Store updated account
        self.store_account(&account)?;

        // Generate transaction ID
        let tx_id = crate::utils::generate_transaction_id();
        
        log::info!("Treasury mint: {} {} to {} (authorized by {})", 
              amount, token_type, to_address, authorized_by);

        Ok(tx_id)
    }

    /// Treasury distribute operation
    pub fn treasury_distribute_tokens(
        &self,
        from_treasury: &str,
        to_address: &str,
        amount: u64,
        token_type: TokenType,
        authorized_by: &str,
    ) -> Result<String> {
        // Validate authorization
        let authorized_addresses = vec![
            "DT53GRdiJrYAjbJbt6QPxcCXcu27xiTenCN".to_string(),
        ];
        
        if !authorized_addresses.contains(&authorized_by.to_string()) {
            return Err(anyhow!("Address {} not authorized for treasury operations", authorized_by));
        }

        // Get treasury account
        let mut treasury_account = self.get_account(from_treasury)?
            .ok_or_else(|| anyhow!("Treasury account not found"))?;

        // Check treasury balance
        if treasury_account.get_balance(&token_type) < amount {
            return Err(anyhow!(
                "Insufficient treasury balance: {} < {}",
                treasury_account.get_balance(&token_type),
                amount
            ));
        }

        // Get or create recipient
        let mut recipient_account = match self.get_account(to_address)? {
            Some(acc) => acc,
            None => Account::new(to_address.to_string())?,
        };

        // Transfer tokens
        treasury_account.subtract_balance(&token_type, amount)?;
        recipient_account.add_balance(&token_type, amount)?;

        // Store both accounts
        self.store_account(&treasury_account)?;
        self.store_account(&recipient_account)?;

        let tx_id = crate::utils::generate_transaction_id();
        
        log::info!("Treasury distribution: {} {} from {} to {} (authorized by {})", 
              amount, token_type, from_treasury, to_address, authorized_by);

        Ok(tx_id)
    }

    /// Get treasury balance
    pub fn get_treasury_balance(&self, treasury_address: &str, token_type: TokenType) -> Result<u64> {
        match self.get_account(treasury_address)? {
            Some(account) => Ok(account.get_balance(&token_type)),
            None => Ok(0),
        }
    }

    // === GENESIS OPERATIONS ===

    /// Check if genesis block exists
    pub fn has_genesis_block(&self) -> Result<bool> {
        match self.db.get(GENESIS_BLOCK_KEY)? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// Store genesis block marker
    pub fn set_genesis_block(&self, block_hash: &[u8]) -> Result<()> {
        self.db.put(GENESIS_BLOCK_KEY, block_hash)?;
        Ok(())
    }

    /// Set the current best block hash
    pub fn set_best_block(&self, block_hash: crate::crypto::Hash) -> Result<()> {
        self.db.put(BEST_BLOCK_KEY, block_hash.as_bytes())?;
        Ok(())
    }

    /// Get the current best block hash
    pub fn get_best_block(&self) -> Result<Option<crate::crypto::Hash>> {
        match self.db.get(BEST_BLOCK_KEY)? {
            Some(data) => {
                let bytes: [u8; 32] = data[..32].try_into()
                    .map_err(|_| anyhow!("Invalid best block hash length"))?;
                Ok(Some(crate::crypto::Hash::from_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    /// Get current block height
    pub fn get_block_height(&self) -> Result<u64> {
        match self.db.get(BLOCK_HEIGHT_KEY)? {
            Some(data) => {
                let bytes: [u8; 8] = data[..8].try_into()
                    .map_err(|_| anyhow!("Invalid block height data"))?;
                Ok(u64::from_be_bytes(bytes))
            }
            None => Ok(0),
        }
    }

    /// Set current block height
    pub fn set_block_height(&self, height: u64) -> Result<()> {
        self.db.put(BLOCK_HEIGHT_KEY, &height.to_be_bytes())?;
        Ok(())
    }

    // === BALANCE OPERATIONS ===

    /// Set account balance for a specific token
    pub fn set_balance(&self, address: &crate::crypto::Address, token: TokenType, balance: u64) -> Result<()> {
        let key = format!("{}{}_{}",
                         BALANCE_PREFIX,
                         match token {
                             TokenType::DINARI => "dinari",
                             TokenType::AFRICOIN => "africoin",
                         },
                         address.to_hex());
        self.db.put(key.as_bytes(), &balance.to_be_bytes())?;
        Ok(())
    }

    /// Get account balance for a specific token
    pub fn get_balance(&self, address: &crate::crypto::Address, token: TokenType) -> Result<u64> {
        let key = format!("{}{}_{}",
                         BALANCE_PREFIX,
                         match token {
                             TokenType::DINARI => "dinari",
                             TokenType::AFRICOIN => "africoin",
                         },
                         address.to_hex());
        match self.db.get(key.as_bytes())? {
            Some(data) => {
                let bytes: [u8; 8] = data[..8].try_into()
                    .map_err(|_| anyhow!("Invalid balance data"))?;
                Ok(u64::from_be_bytes(bytes))
            }
            None => Ok(0),
        }
    }

    // === BLOCK OPERATIONS ===

    /// Store a block
    pub fn store_block(&self, block: &Block) -> Result<()> {
        let key = format!("{}{}", BLOCK_PREFIX, block.header.block_number);
        let data = bincode::serialize(block)?;
        self.db.put(key, data)?;
        
        // Also store block hash -> number mapping for lookups
        let hash_key = format!("{}{}", BLOCK_HASH_PREFIX, block.calculate_hash());
        let number_data = bincode::serialize(&block.header.block_number)?;
        self.db.put(hash_key, number_data)?;
        
        Ok(())
    }

    /// Get block by number
    pub fn get_block(&self, block_number: u64) -> Result<Option<Block>> {
        let key = format!("{}{}", BLOCK_PREFIX, block_number);
        match self.db.get(key)? {
            Some(data) => {
                let block: Block = bincode::deserialize(&data)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Get block by number (alias for compatibility)
    pub fn get_block_by_number(&self, number: u64) -> Result<Option<Block>> {
        self.get_block(number)
    }

    /// Store block by number index (for compatibility)
    pub fn store_block_by_number(&self, number: u64, block_hash: &crate::crypto::Hash) -> Result<()> {
        let key = format!("{}{}", BLOCK_BY_NUMBER_PREFIX, number);
        self.db.put(key.as_bytes(), block_hash.as_bytes())?;
        Ok(())
    }

    /// Get block by hash
    pub fn get_block_by_hash(&self, block_hash: &str) -> Result<Option<Block>> {
        let hash_key = format!("{}{}", BLOCK_HASH_PREFIX, block_hash);
        match self.db.get(hash_key)? {
            Some(number_data) => {
                let block_number: u64 = bincode::deserialize(&number_data)?;
                self.get_block(block_number)
            }
            None => Ok(None),
        }
    }

    /// Get latest block
    pub fn get_latest_block(&self) -> Result<Option<Block>> {
        let chain_info = self.get_chain_info()?;
        if chain_info.latest_block_number == 0 {
            return Ok(None);
        }
        self.get_block(chain_info.latest_block_number)
    }

    /// Get blocks in range
    pub fn get_blocks_range(&self, start: u64, end: u64) -> Result<Vec<Block>> {
        let mut blocks = Vec::new();
        for block_number in start..=end {
            if let Some(block) = self.get_block(block_number)? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    // === TRANSACTION OPERATIONS ===

    /// Store a transaction
    pub fn store_transaction(&self, tx: &Transaction) -> Result<()> {
        let key = format!("{}{}", TRANSACTION_PREFIX, tx.tx_id);
        let data = bincode::serialize(tx)?;
        self.db.put(key, data)?;
        Ok(())
    }

    /// Get transaction by ID
    pub fn get_transaction(&self, tx_id: &str) -> Result<Option<Transaction>> {
        let key = format!("{}{}", TRANSACTION_PREFIX, tx_id);
        match self.db.get(key)? {
            Some(data) => {
                let tx: Transaction = bincode::deserialize(&data)?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    /// Store multiple transactions in batch
    pub fn store_transactions_batch(&self, transactions: &[Transaction]) -> Result<()> {
        let mut batch = WriteBatch::default();
        for tx in transactions {
            let key = format!("{}{}", TRANSACTION_PREFIX, tx.tx_id);
            let data = bincode::serialize(tx)?;
            batch.put(key, data);
        }
        self.db.write(batch)?;
        Ok(())
    }

    // === ACCOUNT OPERATIONS ===

    /// Store account state
    pub fn store_account(&self, account: &Account) -> Result<()> {
        let key = format!("{}{}", ACCOUNT_PREFIX, account.address);
        let data = bincode::serialize(account)?;
        self.db.put(key, data)?;
        Ok(())
    }

    /// Get account by address
    pub fn get_account(&self, address: &str) -> Result<Option<Account>> {
        let key = format!("{}{}", ACCOUNT_PREFIX, address);
        match self.db.get(key)? {
            Some(data) => {
                let account: Account = bincode::deserialize(&data)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    /// Store multiple accounts in batch
    pub fn store_accounts_batch(&self, accounts: &[Account]) -> Result<()> {
        let mut batch = WriteBatch::default();
        for account in accounts {
            let key = format!("{}{}", ACCOUNT_PREFIX, account.address);
            let data = bincode::serialize(account)?;
            batch.put(key, data);
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Get all accounts (for genesis or debugging)
    pub fn get_all_accounts(&self) -> Result<Vec<Account>> {
        let mut accounts = Vec::new();
        let iter = self.db.iterator(IteratorMode::From(ACCOUNT_PREFIX.as_bytes(), Direction::Forward));
        
        for item in iter {
            let (key, value) = item?;
            let key_str = String::from_utf8_lossy(&key);
            
            // Break if we've moved past account prefix
            if !key_str.starts_with(ACCOUNT_PREFIX) {
                break;
            }
            
            let account: Account = bincode::deserialize(&value)?;
            accounts.push(account);
        }
        
        Ok(accounts)
    }

    // === VALIDATOR OPERATIONS ===

    /// Store validator set
    pub fn store_validators(&self, validators: &ValidatorSet) -> Result<()> {
        let data = bincode::serialize(validators)?;
        self.db.put(VALIDATORS_KEY, data)?;
        Ok(())
    }

    /// Get validator set
    pub fn get_validators(&self) -> Result<Option<ValidatorSet>> {
        match self.db.get(VALIDATORS_KEY)? {
            Some(data) => {
                let validators: ValidatorSet = bincode::deserialize(&data)?;
                Ok(Some(validators))
            }
            None => Ok(None),
        }
    }

    // === CHAIN INFO OPERATIONS ===

    /// Store chain information
    pub fn store_chain_info(&self, chain_info: &ChainInfo) -> Result<()> {
        let data = bincode::serialize(chain_info)?;
        self.db.put(CHAIN_INFO_KEY, data)?;
        Ok(())
    }

    /// Get chain information
    pub fn get_chain_info(&self) -> Result<ChainInfo> {
        match self.db.get(CHAIN_INFO_KEY)? {
            Some(data) => {
                let chain_info: ChainInfo = bincode::deserialize(&data)?;
                Ok(chain_info)
            }
            None => {
                // Return default if not found
                Ok(ChainInfo::default())
            }
        }
    }

    /// Update chain info after new block
    pub fn update_chain_info_for_block(&self, block: &Block) -> Result<()> {
        let mut chain_info = self.get_chain_info()?;
        chain_info.latest_block_number = block.header.block_number;
        chain_info.latest_block_hash = block.calculate_hash();
        chain_info.total_transactions += block.transactions.len() as u64;
        
        if chain_info.genesis_hash.is_empty() && block.header.block_number == 0 {
            chain_info.genesis_hash = block.calculate_hash();
        }
        
        self.store_chain_info(&chain_info)?;
        Ok(())
    }

    // === UTILITY OPERATIONS ===

    /// Check if database is initialized (has genesis block)
    pub fn is_initialized(&self) -> Result<bool> {
        let chain_info = self.get_chain_info()?;
        Ok(!chain_info.genesis_hash.is_empty())
    }

    /// Get database statistics
    pub fn get_stats(&self) -> Result<DatabaseStats> {
        let chain_info = self.get_chain_info()?;
        
        // Count accounts
        let account_count = self.get_all_accounts()?.len() as u64;
        
        // Get database size (approximate)
        let db_size = self.estimate_db_size()?;
        
        Ok(DatabaseStats {
            total_blocks: chain_info.latest_block_number + 1,
            total_transactions: chain_info.total_transactions,
            total_accounts: account_count,
            database_size_bytes: db_size,
            latest_block_hash: chain_info.latest_block_hash,
            genesis_hash: chain_info.genesis_hash,
        })
    }

    /// Estimate database size
    fn estimate_db_size(&self) -> Result<u64> {
        // This is a rough estimate - RocksDB doesn't provide exact size easily
        let mut total_size = 0u64;
        
        // Iterate through all keys and sum value sizes
        let iter = self.db.iterator(IteratorMode::Start);
        for item in iter {
            let (key, value) = item?;
            total_size += key.len() as u64 + value.len() as u64;
        }
        
        Ok(total_size)
    }

    /// Perform database compaction (for maintenance)
    pub fn compact(&self) -> Result<()> {
        self.db.compact_range::<&[u8], &[u8]>(None, None);
        Ok(())
    }

    /// Close database (called on shutdown)
    pub fn close(self) -> Result<()> {
        // RocksDB closes automatically when dropped
        drop(self.db);
        Ok(())
    }

    /// Get database path
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// Atomic batch operation for block + transactions + account updates
    pub fn store_block_with_state(
        &self,
        block: &Block,
        updated_accounts: &[Account],
    ) -> Result<()> {
        let mut batch = WriteBatch::default();
        
        // Store block
        let block_key = format!("{}{}", BLOCK_PREFIX, block.header.block_number);
        let block_data = bincode::serialize(block)?;
        batch.put(block_key, block_data);
        
        // Store block hash mapping
        let hash_key = format!("{}{}", BLOCK_HASH_PREFIX, block.calculate_hash());
        let number_data = bincode::serialize(&block.header.block_number)?;
        batch.put(hash_key, number_data);
        
        // Store all transactions in the block
        for tx in &block.transactions {
            let tx_key = format!("{}{}", TRANSACTION_PREFIX, tx.tx_id);
            let tx_data = bincode::serialize(tx)?;
            batch.put(tx_key, tx_data);
        }
        
        // Store updated accounts
        for account in updated_accounts {
            let acc_key = format!("{}{}", ACCOUNT_PREFIX, account.address);
            let acc_data = bincode::serialize(account)?;
            batch.put(acc_key, acc_data);
        }
        
        // Update chain info
        let mut chain_info = self.get_chain_info()?;
        chain_info.latest_block_number = block.header.block_number;
        chain_info.latest_block_hash = block.calculate_hash();
        chain_info.total_transactions += block.transactions.len() as u64;
        
        if chain_info.genesis_hash.is_empty() && block.header.block_number == 0 {
            chain_info.genesis_hash = block.calculate_hash();
        }
        
        let chain_data = bincode::serialize(&chain_info)?;
        batch.put(CHAIN_INFO_KEY, chain_data);
        
        // Write entire batch atomically
        self.db.write(batch)?;
        
        Ok(())
    }
}

/// Database statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total_blocks: u64,
    pub total_transactions: u64,
    pub total_accounts: u64,
    pub database_size_bytes: u64,
    pub latest_block_hash: String,
    pub genesis_hash: String,
}