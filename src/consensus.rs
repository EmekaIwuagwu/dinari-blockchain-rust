// src/consensus.rs - WITH TREASURY SYSTEM AND ALGORITHMIC PEG
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{RwLock, Mutex};
use std::time::Duration;
use anyhow::{Result, anyhow};
use log::{info, error, debug, warn};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

use crate::{
    block::Block,
    transaction::{Transaction, TransactionBuilder},
    account::{AccountManager, Account, TokenType},
    mempool::{Mempool, MempoolConfig},
    database::{BlockchainDB, ValidatorSet, ValidatorInfo},
    crypto::{CryptoEngine, Wallet, Address},
    peg::{AlgorithmicPeg, AlgorithmicPegConfig, AlgorithmicPegStats}, // NEW: Import peg
    utils,
};

/// Treasury operation record for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryOperation {
    pub operation_id: String,
    pub operation_type: TreasuryOperationType,
    pub to_address: String,
    pub amount: u64,
    pub token_type: TokenType,
    pub authorized_by: String,
    pub timestamp: DateTime<Utc>,
    pub tx_id: Option<String>,
    pub status: TreasuryOperationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreasuryOperationType {
    Mint,           // Create new tokens
    Distribution,   // Transfer from treasury reserves
    Burn,           // Destroy tokens
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreasuryOperationStatus {
    Pending,
    Executed,
    Failed,
}

/// Treasury/Reserve System for token distribution
#[derive(Debug, Clone)]
pub struct Treasury {
    pub treasury_address: String,
    pub authorized_minters: Vec<String>,
    pub daily_mint_limit: u64,
    pub total_minted_today: u64,
    pub last_reset_date: DateTime<Utc>,
    pub operations_log: Vec<TreasuryOperation>,
}

impl Treasury {
    pub fn new(treasury_address: String, authorized_minters: Vec<String>) -> Self {
        Self {
            treasury_address,
            authorized_minters,
            daily_mint_limit: 1_000_000, // 1M tokens per day limit
            total_minted_today: 0,
            last_reset_date: Utc::now(),
            operations_log: Vec::new(),
        }
    }

    /// Check if an address is authorized to perform treasury operations
    pub fn is_authorized(&self, address: &str) -> bool {
        self.authorized_minters.contains(&address.to_string())
    }

    /// Reset daily limits if a new day has started
    pub fn check_and_reset_daily_limits(&mut self) {
        let now = Utc::now();
        if now.date_naive() > self.last_reset_date.date_naive() {
            self.total_minted_today = 0;
            self.last_reset_date = now;
            info!("Treasury daily limits reset for new day");
        }
    }

    /// Validate a mint operation against limits and authorization
    pub fn validate_mint_operation(
        &mut self,
        amount: u64,
        authorized_by: &str,
    ) -> Result<()> {
        // Check authorization
        if !self.is_authorized(authorized_by) {
            return Err(anyhow!("Address {} not authorized for treasury operations", authorized_by));
        }

        // Reset daily limits if needed
        self.check_and_reset_daily_limits();

        // Check daily mint limit
        if self.total_minted_today + amount > self.daily_mint_limit {
            return Err(anyhow!(
                "Mint amount {} would exceed daily limit. Used: {}, Limit: {}",
                amount,
                self.total_minted_today,
                self.daily_mint_limit
            ));
        }

        Ok(())
    }

    /// Create a mint operation (creates new tokens from nothing)
    pub fn create_mint_operation(
        &mut self,
        to_address: String,
        amount: u64,
        token_type: TokenType,
        authorized_by: String,
    ) -> Result<TreasuryOperation> {
        // Validate the operation
        self.validate_mint_operation(amount, &authorized_by)?;

        // Update daily tracking
        self.total_minted_today += amount;

        // Create operation record
        let operation = TreasuryOperation {
            operation_id: utils::generate_transaction_id(),
            operation_type: TreasuryOperationType::Mint,
            to_address,
            amount,
            token_type,
            authorized_by,
            timestamp: Utc::now(),
            tx_id: None,
            status: TreasuryOperationStatus::Pending,
        };

        // Log the operation
        self.operations_log.push(operation.clone());

        info!("Treasury mint operation created: {} {} to {}", 
              amount, operation.token_type, operation.to_address);

        Ok(operation)
    }

    /// Create a distribution operation (transfer from treasury reserves)
    pub fn create_distribution_operation(
        &self,
        to_address: String,
        amount: u64,
        token_type: TokenType,
        authorized_by: String,
        treasury_balance: u64,
    ) -> Result<TreasuryOperation> {
        // Check authorization
        if !self.is_authorized(&authorized_by) {
            return Err(anyhow!("Address {} not authorized for treasury operations", authorized_by));
        }

        // Check treasury has sufficient balance
        if treasury_balance < amount {
            return Err(anyhow!(
                "Insufficient treasury balance: {} < {}",
                treasury_balance,
                amount
            ));
        }

        let operation = TreasuryOperation {
            operation_id: utils::generate_transaction_id(),
            operation_type: TreasuryOperationType::Distribution,
            to_address,
            amount,
            token_type,
            authorized_by,
            timestamp: Utc::now(),
            tx_id: None,
            status: TreasuryOperationStatus::Pending,
        };

        info!("Treasury distribution operation created: {} {} to {}", 
              amount, operation.token_type, operation.to_address);

        Ok(operation)
    }

    /// Get treasury operation statistics
    pub fn get_stats(&self) -> TreasuryStats {
        let mut stats = TreasuryStats {
            treasury_address: self.treasury_address.clone(),
            authorized_minters: self.authorized_minters.clone(),
            daily_mint_limit: self.daily_mint_limit,
            total_minted_today: self.total_minted_today,
            total_operations: self.operations_log.len(),
            operations_by_type: HashMap::new(),
        };

        // Count operations by type
        for op in &self.operations_log {
            *stats.operations_by_type.entry(format!("{:?}", op.operation_type))
                .or_insert(0) += 1;
        }

        stats
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryStats {
    pub treasury_address: String,
    pub authorized_minters: Vec<String>,
    pub daily_mint_limit: u64,
    pub total_minted_today: u64,
    pub total_operations: usize,
    pub operations_by_type: HashMap<String, usize>,
}

/// Consensus configuration
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    pub block_time_seconds: u64,
    pub max_transactions_per_block: usize,
    pub max_block_gas: u64,
    pub sync_interval_seconds: u64,
    pub min_validator_stake: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            block_time_seconds: 15,
            max_transactions_per_block: 1000,
            max_block_gas: 50_000,
            sync_interval_seconds: 30,
            min_validator_stake: 10_000_000_000,
        }
    }
}

/// Consensus statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusStats {
    pub latest_block_number: u64,
    pub total_transactions: u64,
    pub pending_transactions: usize,
    pub active_validators: usize,
    pub blocks_produced: u64,
    pub is_validator: bool,
    pub current_validator: Option<String>,
    pub peg_enabled: bool, // NEW: Peg status
}

/// Enhanced PoA Consensus Engine with Treasury System and Algorithmic USD Peg
pub struct PoAConsensus {
    config: ConsensusConfig,
    db: Arc<BlockchainDB>,
    account_manager: Arc<RwLock<AccountManager>>,
    crypto: CryptoEngine,
    validator_wallet: Option<Wallet>,
    validators: Vec<ValidatorInfo>,
    mempool: Arc<Mutex<Mempool>>,
    blocks_produced: Arc<Mutex<u64>>,
    
    // Treasury system
    treasury: Arc<RwLock<Treasury>>,
    
    // NEW: Algorithmic USD peg mechanism
    peg_mechanism: Arc<RwLock<AlgorithmicPeg>>,
    peg_enabled: bool,
}

impl PoAConsensus {
    pub fn new(db: Arc<BlockchainDB>) -> Self {
        let config = ConsensusConfig::default();
        let mempool_config = MempoolConfig::default();
        
        // Initialize treasury
        let treasury = Treasury::new(
            String::new(), // Will be set during initialization
            vec![],        // Will be populated with authorized minters
        );
        
        // NEW: Initialize algorithmic peg with default configuration
        let peg_config = AlgorithmicPegConfig::default();
        let peg_mechanism = AlgorithmicPeg::new(peg_config);
        
        Self {
            config,
            db,
            account_manager: Arc::new(RwLock::new(AccountManager::new())),
            crypto: CryptoEngine::new(),
            validator_wallet: None,
            validators: Vec::new(),
            mempool: Arc::new(Mutex::new(Mempool::with_config(mempool_config))),
            blocks_produced: Arc::new(Mutex::new(0)),
            treasury: Arc::new(RwLock::new(treasury)),
            peg_mechanism: Arc::new(RwLock::new(peg_mechanism)), // NEW
            peg_enabled: true, // NEW: Enable peg by default
        }
    }

    /// NEW: Enable/disable the algorithmic peg
    pub async fn set_peg_enabled(&mut self, enabled: bool) -> Result<()> {
        self.peg_enabled = enabled;
        info!("Algorithmic USD peg {}", if enabled { "enabled" } else { "disabled" });
        Ok(())
    }

    /// NEW: Configure the peg mechanism
    pub async fn configure_peg(&self, peg_config: AlgorithmicPegConfig) -> Result<()> {
        let mut peg = self.peg_mechanism.write().await;
        *peg = AlgorithmicPeg::new(peg_config);
        info!("Algorithmic peg reconfigured");
        Ok(())
    }

    /// NEW: Set peg stability wallet
    pub async fn set_peg_stability_wallet(&self, wallet: Wallet) -> Result<()> {
        let mut peg = self.peg_mechanism.write().await;
        peg.set_stability_wallet(wallet)?;
        info!("Peg stability wallet configured");
        Ok(())
    }

    /// NEW: Get peg statistics
    pub async fn get_peg_stats(&self) -> AlgorithmicPegStats {
        let peg = self.peg_mechanism.read().await;
        peg.get_peg_stats()
    }

    /// Set treasury configuration and authorized minters
    pub async fn configure_treasury(&self, treasury_address: String, authorized_minters: Vec<String>) -> Result<()> {
        let mut treasury = self.treasury.write().await;
        treasury.treasury_address = treasury_address.clone();
        treasury.authorized_minters = authorized_minters.clone();
        
        info!("Treasury configured: address={}, authorized_minters={:?}", 
              treasury_address, authorized_minters);
        Ok(())
    }

    /// TREASURY OPERATION: Mint tokens to a user (when they purchase)
    pub async fn treasury_mint_tokens(
        &self,
        to_address: String,
        amount: u64,
        token_type: TokenType,
        authorized_by: String,
    ) -> Result<String> {
        // Create mint operation
        let operation = {
            let mut treasury = self.treasury.write().await;
            treasury.create_mint_operation(to_address.clone(), amount, token_type, authorized_by)?
        };

        // Create mint transaction
        let mint_tx = Transaction::mint(
            Address::from_hex(&to_address)?,
            amount,
            token_type,
        )?;

        // Execute the mint by updating account state
        {
            let mut account_state = self.account_manager.write().await;
            let recipient_account = account_state.get_or_create_account(&to_address)?;
            recipient_account.add_balance(&token_type, amount)?;
        }

        // Update operation status
        {
            let mut treasury = self.treasury.write().await;
            if let Some(last_op) = treasury.operations_log.last_mut() {
                last_op.tx_id = Some(mint_tx.tx_id.clone());
                last_op.status = TreasuryOperationStatus::Executed;
            }
        }

        info!("Treasury mint executed: {} {} to {}", amount, token_type, to_address);
        Ok(mint_tx.tx_id)
    }

    /// TREASURY OPERATION: Distribute from treasury reserves
    pub async fn treasury_distribute_tokens(
        &self,
        to_address: String,
        amount: u64,
        token_type: TokenType,
        authorized_by: String,
    ) -> Result<String> {
        // Get treasury balance
        let treasury_address = {
            let treasury = self.treasury.read().await;
            treasury.treasury_address.clone()
        };

        let treasury_balance = {
            let account_state = self.account_manager.read().await;
            if let Some(treasury_account) = account_state.get_account(&treasury_address) {
                treasury_account.get_balance(&token_type)
            } else {
                0
            }
        };

        // Create distribution operation
        let operation = {
            let treasury = self.treasury.read().await;
            treasury.create_distribution_operation(
                to_address.clone(),
                amount,
                token_type,
                authorized_by,
                treasury_balance,
            )?
        };

        // Create transfer transaction from treasury to user
        let transfer_tx = TransactionBuilder::new()
            .from(treasury_address.clone())
            .to(to_address.clone())
            .amount(amount)
            .token_type(token_type)
            .nonce(0) // Treasury operations use special nonce handling
            .gas_fee(0) // No gas for treasury operations
            .build()?;

        // Execute the transfer
        {
            let mut account_state = self.account_manager.write().await;
            transfer_tx.execute(&mut account_state)?;
        }

        info!("Treasury distribution executed: {} {} to {}", amount, token_type, to_address);
        Ok(transfer_tx.tx_id)
    }

    /// Get treasury statistics
    pub async fn get_treasury_stats(&self) -> TreasuryStats {
        let treasury = self.treasury.read().await;
        treasury.get_stats()
    }

    /// Get treasury balance for a specific token
    pub async fn get_treasury_balance(&self, token_type: TokenType) -> Result<u64> {
        let treasury_address = {
            let treasury = self.treasury.read().await;
            treasury.treasury_address.clone()
        };

        let account_state = self.account_manager.read().await;
        if let Some(treasury_account) = account_state.get_account(&treasury_address) {
            Ok(treasury_account.get_balance(&token_type))
        } else {
            Ok(0)
        }
    }

    // EXISTING METHODS (unchanged)
    pub async fn add_transaction(&mut self, transaction: Transaction) -> Result<()> {
        transaction.validate_format()?;
        
        if !transaction.verify_signature(&self.crypto)? {
            return Err(anyhow!("Invalid transaction signature"));
        }
        
        let account_state = self.account_manager.read().await;
        transaction.validate(&account_state)?;
        
        let mut pool = self.mempool.lock().await;
        pool.add_transaction(transaction, &account_state, &self.crypto)?;
        
        info!("Transaction added to mempool successfully");
        Ok(())
    }

    pub fn set_validator(&mut self, validator_wallet: Wallet) -> Result<()> {
        let address = validator_wallet.address().to_string();
        self.validator_wallet = Some(validator_wallet);
        info!("Node configured as validator: {}", address);
        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting PoA Consensus Engine with Treasury and Peg Systems");
        
        self.initialize().await?;
        
        let mut block_timer = tokio::time::interval(Duration::from_secs(self.config.block_time_seconds));
        
        loop {
            tokio::select! {
                _ = block_timer.tick() => {
                    if let Err(e) = self.try_produce_block().await {
                        error!("Block production error: {}", e);
                    }
                }
            }
        }
    }

    async fn initialize(&mut self) -> Result<()> {
        info!("Initializing consensus state with treasury and peg systems...");
        
        self.load_validators().await?;
        
        let accounts = self.db.get_all_accounts()?;
        {
            let mut account_state = self.account_manager.write().await;
            for account in accounts {
                account_state.update_account(account);
            }
        }
        
        if !self.db.is_initialized()? {
            self.create_genesis_block().await?;
        }

        // Configure treasury with validator as initial authorized minter
        if let Some(ref validator) = self.validator_wallet {
            let foundation_address = "DTFoundation1234567890ABCDEF".to_string(); // Can be any designated treasury address
            self.configure_treasury(
                foundation_address.clone(),
                vec![validator.address().to_string()], // Validator is initially authorized
            ).await?;

            // NEW: Configure peg stability wallet (same as treasury for now)
            let stability_wallet = Wallet::new(); // In production, use deterministic key
            self.set_peg_stability_wallet(stability_wallet).await?;
        }
        
        info!("Consensus initialization complete with treasury and peg systems");
        Ok(())
    }

    async fn load_validators(&mut self) -> Result<()> {
        match self.db.get_validators()? {
            Some(validator_set) => {
                self.validators = validator_set.validators;
                info!("Loaded {} validators", self.validators.len());
            }
            None => {
                self.create_genesis_validators().await?;
            }
        }
        Ok(())
    }

    async fn create_genesis_validators(&mut self) -> Result<()> {
        if let Some(ref wallet) = self.validator_wallet {
            let validator = ValidatorInfo {
                address: wallet.address().to_string(),
                public_key: utils::bytes_to_hex(&wallet.public_key().serialize()),
                is_active: true,
                added_at: chrono::Utc::now(),
            };
            
            let validator_set = ValidatorSet {
                validators: vec![validator],
                updated_at: chrono::Utc::now(),
            };
            
            self.db.store_validators(&validator_set)?;
            self.validators = validator_set.validators;
            
            info!("Genesis validator created: {}", wallet.address());
        }
        Ok(())
    }

    async fn create_genesis_block(&mut self) -> Result<()> {
        info!("Creating genesis block with treasury and peg systems...");
        
        // Create foundation/treasury account with initial reserves
        let foundation_wallet = Wallet::new();
        let foundation_account = Account::with_balances(
            foundation_wallet.address().to_string(),
            1_000_000_000, // 1B DINARI initial reserves
            1_000_000_000, // 1B AFRICOIN initial reserves
        )?;
        
        let updated_accounts = {
            let mut account_state = self.account_manager.write().await;
            account_state.update_account(foundation_account);
            account_state.get_all_accounts().values().cloned().collect::<Vec<_>>()
        };
        
        let genesis_validator = self.validators.first()
            .ok_or_else(|| anyhow!("No validators available"))?;
        
        let genesis_block = Block::genesis(
            updated_accounts,
            genesis_validator.address.clone(),
        )?;
        
        let accounts_for_storage = {
            let account_state = self.account_manager.read().await;
            account_state.get_all_accounts().values().cloned().collect::<Vec<_>>()
        };
        
        self.db.store_block_with_state(&genesis_block, &accounts_for_storage)?;
        
        info!("Genesis block created with treasury and peg systems");
        Ok(())
    }

    // NEW: Enhanced block production with peg integration
    async fn try_produce_block(&mut self) -> Result<()> {
        if let Some(ref validator_wallet) = self.validator_wallet {
            debug!("Attempting to produce block with peg integration...");
            
            // Get pending transactions from mempool
            let selected_transactions = {
                let mempool = self.mempool.lock().await;
                let account_state = self.account_manager.read().await;
                mempool.select_transactions_for_block(
                    &account_state,
                    self.config.max_transactions_per_block,
                    self.config.max_block_gas,
                )
            };

            // Only produce block if we have transactions or if it's been a while
            if selected_transactions.is_empty() {
                debug!("No transactions to include in block");
                return Ok(());
            }

            // Get parent block
            let parent_block = self.db.get_latest_block()?;
            let (block_number, parent_hash) = match parent_block {
                Some(ref block) => (block.header.block_number + 1, block.calculate_hash()),
                None => (0, String::new()),
            };

            // Create block with transactions
            let account_state = self.account_manager.read().await;
            let mut new_block = Block::new(
                block_number,
                parent_hash,
                selected_transactions,
                validator_wallet.address().to_string(),
                &account_state,
            )?;

            // NEW: Process block through peg mechanism
            let mut peg_transactions = Vec::new();
            if self.peg_enabled {
                let mut peg = self.peg_mechanism.write().await;
                
                // Process the block for peg analysis
                peg.process_block(&new_block)?;
                
                // Execute any supply actions
                let mut account_state_mut = self.account_manager.write().await;
                let peg_txs = peg.execute_supply_actions(&mut account_state_mut)?;
                peg_transactions = peg_txs;
                
                if !peg_transactions.is_empty() {
                    info!("Peg mechanism generated {} supply adjustment transactions", peg_transactions.len());
                }
            }

            // Add peg transactions to the block
            if !peg_transactions.is_empty() {
                // Recreate block with peg transactions included
                let mut all_transactions = new_block.transactions;
                all_transactions.extend(peg_transactions.clone());
                
                let account_state = self.account_manager.read().await;
                new_block = Block::new(
                    block_number,
                    new_block.header.parent_hash,
                    all_transactions,
                    validator_wallet.address().to_string(),
                    &account_state,
                )?;
            }

            // Sign the block
            new_block.sign(&self.crypto, validator_wallet.secret_key())?;

            // Validate the block
            let account_state = self.account_manager.read().await;
            new_block.validate(parent_block.as_ref(), &account_state, &self.crypto)?;

            // Execute transactions and update state
            {
                let mut account_state = self.account_manager.write().await;
                new_block.execute_transactions(&mut account_state)?;
                
                // Store updated accounts
                let accounts_for_storage: Vec<Account> = account_state
                    .get_all_accounts()
                    .values()
                    .cloned()
                    .collect();
                
                // Store block with state atomically
                self.db.store_block_with_state(&new_block, &accounts_for_storage)?;
            }

            // Remove confirmed transactions from mempool
            {
                let mut mempool = self.mempool.lock().await;
                for tx in &new_block.transactions {
                    mempool.remove_transaction(&tx.tx_id);
                }
            }

            // Update block count
            {
                let mut count = self.blocks_produced.lock().await;
                *count += 1;
            }

            info!("Block #{} produced successfully with {} transactions (including {} peg adjustments)",
                  new_block.header.block_number,
                  new_block.transactions.len(),
                  peg_transactions.len());

            // Log peg status
            if self.peg_enabled {
                let peg_stats = self.get_peg_stats().await;
                info!("Peg status: demand_score={:.2}, dinari_supply={}, africoin_supply={}", 
                      peg_stats.current_demand_score,
                      peg_stats.current_dinari_supply,
                      peg_stats.current_africoin_supply);
            }
        }
        
        Ok(())
    }

    pub async fn get_stats(&self) -> ConsensusStats {
        let chain_info = self.db.get_chain_info().unwrap_or_default();
        let blocks_produced = *self.blocks_produced.lock().await;
        let is_validator = self.validator_wallet.is_some();
        
        ConsensusStats {
            latest_block_number: chain_info.latest_block_number,
            total_transactions: chain_info.total_transactions,
            pending_transactions: 0,
            active_validators: self.validators.iter().filter(|v| v.is_active).count(),
            blocks_produced,
            is_validator,
            current_validator: self.validator_wallet.as_ref().map(|w| w.address().to_string()),
            peg_enabled: self.peg_enabled, // NEW: Include peg status
        }
    }
}