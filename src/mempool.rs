// src/mempool.rs
use std::collections::{HashMap, BTreeMap, HashSet};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use crate::{
    transaction::{Transaction, TransactionStatus},
    account::{AccountManager, TokenType},
    crypto::CryptoEngine,
};

/// Transaction pool configuration
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    pub max_transactions: usize,
    pub max_transactions_per_account: usize,
    pub transaction_ttl_minutes: i64,
    pub min_gas_fee: u64,
    pub replace_fee_bump_percent: u64, // Minimum fee increase for replacement
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_transactions: 10000,        // Max 10k pending transactions
            max_transactions_per_account: 100, // Max 100 per account
            transaction_ttl_minutes: 60,    // 1 hour TTL
            min_gas_fee: 1,                // Minimum 1 unit gas fee
            replace_fee_bump_percent: 10,   // 10% fee increase for replacement
        }
    }
}

impl Mempool {
    // Add this method:
    pub fn get_pending_transactions(&self, max_count: usize) -> Result<Vec<Transaction>> {
        let mut transactions = Vec::new();
        let mut count = 0;
        
        for (_, tx) in &self.transactions {
            if count >= max_count {
                break;
            }
            transactions.push(tx.transaction.clone());
            count += 1;
        }
        
        Ok(transactions)
    }
}

/// Transaction with mempool metadata
#[derive(Debug, Clone)]
struct MempoolTransaction {
    pub transaction: Transaction,
    pub added_at: DateTime<Utc>,
    pub fee_per_gas: u64,
    pub replacement_count: u32,
}

impl MempoolTransaction {
    pub fn new(transaction: Transaction) -> Self {
        let fee_per_gas = transaction.gas_fee; // Simple fee calculation
        
        Self {
            transaction,
            added_at: Utc::now(),
            fee_per_gas,
            replacement_count: 0,
        }
    }

    pub fn is_expired(&self, ttl_minutes: i64) -> bool {
        let expiry = self.added_at + Duration::minutes(ttl_minutes);
        Utc::now() > expiry
    }

    pub fn can_be_replaced_by(&self, new_tx: &Transaction, min_fee_bump: u64) -> bool {
        // Same sender and nonce
        if self.transaction.from != new_tx.from || self.transaction.nonce != new_tx.nonce {
            return false;
        }

        // New transaction must have higher gas fee
        let min_new_fee = self.transaction.gas_fee + (self.transaction.gas_fee * min_fee_bump / 100);
        new_tx.gas_fee >= min_new_fee
    }
}

/// Transaction mempool for pending transactions
pub struct Mempool {
    config: MempoolConfig,
    
    // Primary storage: tx_id -> transaction
    transactions: HashMap<String, MempoolTransaction>,
    
    // Indexing by sender address: address -> set of tx_ids
    by_sender: HashMap<String, HashSet<String>>,
    
    // Indexing by nonce: (address, nonce) -> tx_id
    by_nonce: HashMap<(String, u64), String>,
    
    // Priority queue by fee (fee -> set of tx_ids)
    by_fee: BTreeMap<u64, HashSet<String>>,
    
    // Recently removed transactions (for duplicate prevention)
    recent_removals: HashMap<String, DateTime<Utc>>,
}

impl Mempool {
    /// Create new mempool with default configuration
    pub fn new() -> Self {
        Self::with_config(MempoolConfig::default())
    }

    /// Create mempool with custom configuration
    pub fn with_config(config: MempoolConfig) -> Self {
        Self {
            config,
            transactions: HashMap::new(),
            by_sender: HashMap::new(),
            by_nonce: HashMap::new(),
            by_fee: BTreeMap::new(),
            recent_removals: HashMap::new(),
        }
    }

    /// Add transaction to mempool
    pub fn add_transaction(
        &mut self,
        mut transaction: Transaction,
        account_manager: &AccountManager,
        crypto: &CryptoEngine,
    ) -> Result<()> {
        // Validate transaction format first
        transaction.validate_format()?;
        
        // Verify signature
        if !transaction.verify_signature(crypto)? {
            return Err(anyhow!("Invalid transaction signature"));
        }

        // Check if already in mempool
        if self.transactions.contains_key(&transaction.tx_id) {
            return Err(anyhow!("Transaction already in mempool"));
        }

        // Check against recent removals (prevent re-adding failed transactions)
        if let Some(removal_time) = self.recent_removals.get(&transaction.tx_id) {
            let cooloff_period = Duration::minutes(5);
            if Utc::now() < *removal_time + cooloff_period {
                return Err(anyhow!("Transaction was recently removed, cooloff period active"));
            }
        }

        // Validate against account state
        transaction.validate(account_manager)?;

        // Check configuration limits
        self.validate_limits(&transaction)?;

        // Handle nonce conflicts (transaction replacement)
        self.handle_nonce_conflict(&transaction)?;

        // Set transaction status to pending
        transaction.set_status(TransactionStatus::Pending);

        // Create mempool transaction
        let mempool_tx = MempoolTransaction::new(transaction.clone());
        
        // Add to all indexes
        self.insert_transaction(mempool_tx)?;

        log::info!("Added transaction {} to mempool", transaction.tx_id);
        Ok(())
    }

    /// Remove transaction from mempool
    pub fn remove_transaction(&mut self, tx_id: &str) -> Option<Transaction> {
        if let Some(mempool_tx) = self.transactions.remove(tx_id) {
            // Remove from all indexes
            self.remove_from_indexes(&mempool_tx.transaction);
            
            // Add to recent removals
            self.recent_removals.insert(tx_id.to_string(), Utc::now());
            
            log::info!("Removed transaction {} from mempool", tx_id);
            Some(mempool_tx.transaction)
        } else {
            None
        }
    }

    /// Get transaction by ID
    pub fn get_transaction(&self, tx_id: &str) -> Option<&Transaction> {
        self.transactions.get(tx_id).map(|mt| &mt.transaction)
    }

    /// Get pending transactions for a specific account
    pub fn get_account_transactions(&self, address: &str) -> Vec<&Transaction> {
        if let Some(tx_ids) = self.by_sender.get(address) {
            tx_ids.iter()
                .filter_map(|tx_id| self.transactions.get(tx_id))
                .map(|mt| &mt.transaction)
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get next valid transactions for block inclusion (ordered by nonce)
    pub fn get_executable_transactions(
        &self,
        address: &str,
        current_nonce: u64,
        max_count: usize,
    ) -> Vec<&Transaction> {
        let mut executable = Vec::new();
        let mut next_nonce = current_nonce + 1;
        
        // Get transactions in nonce order
        while executable.len() < max_count {
            if let Some(tx_id) = self.by_nonce.get(&(address.to_string(), next_nonce)) {
                if let Some(mempool_tx) = self.transactions.get(tx_id) {
                    executable.push(&mempool_tx.transaction);
                    next_nonce += 1;
                } else {
                    break; // Gap in nonce sequence
                }
            } else {
                break; // No transaction with this nonce
            }
        }
        
        executable
    }

    /// Get highest fee transactions for block inclusion
    pub fn get_highest_fee_transactions(&self, max_count: usize) -> Vec<&Transaction> {
        let mut transactions = Vec::new();
        
        // Iterate from highest fee to lowest
        for (_fee, tx_ids) in self.by_fee.iter().rev() {
            if transactions.len() >= max_count {
                break;
            }
            
            for tx_id in tx_ids {
                if transactions.len() >= max_count {
                    break;
                }
                
                if let Some(mempool_tx) = self.transactions.get(tx_id) {
                    transactions.push(&mempool_tx.transaction);
                }
            }
        }
        
        transactions
    }

    /// Get transactions for block production with smart selection
    pub fn select_transactions_for_block(
        &self,
        account_manager: &AccountManager,
        max_transactions: usize,
        max_gas: u64,
    ) -> Vec<Transaction> {
        let mut selected = Vec::new();
        let mut used_gas = 0u64;
        let mut account_nonces: HashMap<String, u64> = HashMap::new();
        
        // Initialize account nonces
        for address in self.by_sender.keys() {
            if let Some(account) = account_manager.get_account(address) {
                account_nonces.insert(address.clone(), account.nonce);
            }
        }
        
        // Get transactions sorted by fee (highest first)
        let candidates = self.get_highest_fee_transactions(max_transactions * 2);
        
        for tx in candidates {
            if selected.len() >= max_transactions {
                break;
            }
            
            if used_gas + tx.gas_fee > max_gas {
                continue; // Would exceed gas limit
            }
            
            // Check if this transaction can be included (nonce sequence)
            let current_nonce = account_nonces.get(&tx.from).copied().unwrap_or(0);
            if tx.nonce != current_nonce + 1 {
                continue; // Wrong nonce, skip
            }
            
            // Check if sender still has sufficient balance
            if let Some(account) = account_manager.get_account(&tx.from) {
                if !account.can_pay_transaction(tx.amount, &tx.token_type, tx.gas_fee) {
                    continue; // Insufficient balance
                }
            } else {
                continue; // Account doesn't exist
            }
            
            // Add transaction
            selected.push(tx.clone());
            used_gas += tx.gas_fee;
            account_nonces.insert(tx.from.clone(), tx.nonce);
        }
        
        selected
    }

    /// Remove expired transactions
    pub fn cleanup_expired_transactions(&mut self) -> usize {
        let expired_tx_ids: Vec<String> = self.transactions
            .iter()
            .filter(|(_, mempool_tx)| mempool_tx.is_expired(self.config.transaction_ttl_minutes))
            .map(|(tx_id, _)| tx_id.clone())
            .collect();
        
        let count = expired_tx_ids.len();
        for tx_id in expired_tx_ids {
            self.remove_transaction(&tx_id);
        }
        
        // Also cleanup old removal records
        let cutoff = Utc::now() - Duration::hours(1);
        self.recent_removals.retain(|_, removal_time| *removal_time > cutoff);
        
        if count > 0 {
            log::info!("Cleaned up {} expired transactions", count);
        }
        
        count
    }

    /// Get mempool statistics
    pub fn get_stats(&self) -> MempoolStats {
        let mut stats = MempoolStats {
            total_transactions: self.transactions.len(),
            by_token: HashMap::new(),
            avg_gas_fee: 0,
            pending_accounts: self.by_sender.len(),
            memory_usage_bytes: self.estimate_memory_usage(),
        };
        
        let mut total_gas = 0u64;
        for mempool_tx in self.transactions.values() {
            let tx = &mempool_tx.transaction;
            
            // Count by token type
            *stats.by_token.entry(tx.token_type.clone()).or_insert(0) += 1;
            
            // Sum gas for average
            total_gas += tx.gas_fee;
        }
        
        if stats.total_transactions > 0 {
            stats.avg_gas_fee = total_gas / stats.total_transactions as u64;
        }
        
        stats
    }

    /// Check if mempool is full
    pub fn is_full(&self) -> bool {
        self.transactions.len() >= self.config.max_transactions
    }

    /// Get mempool configuration
    pub fn get_config(&self) -> &MempoolConfig {
        &self.config
    }

    // === PRIVATE HELPER METHODS ===

    /// Insert transaction into all indexes
    fn insert_transaction(&mut self, mempool_tx: MempoolTransaction) -> Result<()> {
        let tx = &mempool_tx.transaction;
        let tx_id = tx.tx_id.clone();
        
        // Add to sender index
        self.by_sender
            .entry(tx.from.clone())
            .or_insert_with(HashSet::new)
            .insert(tx_id.clone());
        
        // Add to nonce index
        self.by_nonce.insert((tx.from.clone(), tx.nonce), tx_id.clone());
        
        // Add to fee index
        self.by_fee
            .entry(mempool_tx.fee_per_gas)
            .or_insert_with(HashSet::new)
            .insert(tx_id.clone());
        
        // Add to primary storage
        self.transactions.insert(tx_id, mempool_tx);
        
        Ok(())
    }

    /// Remove transaction from all indexes
    fn remove_from_indexes(&mut self, tx: &Transaction) {
        let tx_id = &tx.tx_id;
        
        // Remove from sender index
        if let Some(sender_txs) = self.by_sender.get_mut(&tx.from) {
            sender_txs.remove(tx_id);
            if sender_txs.is_empty() {
                self.by_sender.remove(&tx.from);
            }
        }
        
        // Remove from nonce index
        self.by_nonce.remove(&(tx.from.clone(), tx.nonce));
        
        // Remove from fee index
        if let Some(fee_txs) = self.by_fee.get_mut(&tx.gas_fee) {
            fee_txs.remove(tx_id);
            if fee_txs.is_empty() {
                self.by_fee.remove(&tx.gas_fee);
            }
        }
    }

    /// Validate transaction against mempool limits
    fn validate_limits(&self, tx: &Transaction) -> Result<()> {
        // Check minimum gas fee
        if tx.gas_fee < self.config.min_gas_fee {
            return Err(anyhow!(
                "Gas fee {} below minimum {}",
                tx.gas_fee,
                self.config.min_gas_fee
            ));
        }
        
        // Check total mempool size
        if self.transactions.len() >= self.config.max_transactions {
            return Err(anyhow!("Mempool is full"));
        }
        
        // Check per-account limit
        if let Some(sender_txs) = self.by_sender.get(&tx.from) {
            if sender_txs.len() >= self.config.max_transactions_per_account {
                return Err(anyhow!(
                    "Too many pending transactions for account {}",
                    tx.from
                ));
            }
        }
        
        Ok(())
    }

    /// Handle transaction replacement for same nonce
    fn handle_nonce_conflict(&mut self, new_tx: &Transaction) -> Result<()> {
        let nonce_key = (new_tx.from.clone(), new_tx.nonce);
        
        if let Some(existing_tx_id) = self.by_nonce.get(&nonce_key) {
            if let Some(existing_mempool_tx) = self.transactions.get(existing_tx_id) {
                // Check if replacement is allowed
                if existing_mempool_tx.can_be_replaced_by(new_tx, self.config.replace_fee_bump_percent) {
                    // Remove existing transaction
                    let old_tx_id = existing_tx_id.clone();
                    self.remove_transaction(&old_tx_id);
                    log::info!("Replaced transaction {} with higher fee transaction {}", 
                              old_tx_id, new_tx.tx_id);
                } else {
                    return Err(anyhow!(
                        "Transaction replacement requires {}% higher gas fee",
                        self.config.replace_fee_bump_percent
                    ));
                }
            }
        }
        
        Ok(())
    }

    /// Estimate memory usage of mempool
    fn estimate_memory_usage(&self) -> usize {
        // Rough estimate of memory usage
        let tx_size = std::mem::size_of::<MempoolTransaction>();
        let index_overhead = 100; // Approximate overhead for indexes
        
        self.transactions.len() * (tx_size + index_overhead)
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

/// Mempool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStats {
    pub total_transactions: usize,
    pub by_token: HashMap<TokenType, usize>,
    pub avg_gas_fee: u64,
    pub pending_accounts: usize,
    pub memory_usage_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{Wallet, CryptoEngine},
        account::Account,
        transaction::TransactionBuilder,
    };

    fn create_signed_transaction(crypto: &CryptoEngine, from_secret: &secp256k1::SecretKey, from_addr: &str, to_addr: &str, nonce: u64, gas_fee: u64) -> Transaction {
        let mut tx = TransactionBuilder::new()
            .from(from_addr.to_string())
            .to(to_addr.to_string())
            .amount(100)
            .token_type(TokenType::DINARI)
            .nonce(nonce)
            .gas_fee(gas_fee)
            .build()
            .unwrap();
        tx.sign(crypto, from_secret).unwrap();
        tx
    }

    #[test]
    fn test_mempool_add_transaction() {
        let mut mempool = Mempool::new();
        let crypto = CryptoEngine::new();
        let mut account_manager = AccountManager::new();
        
        let (secret_key, _) = crypto.generate_keypair();
        let from_addr = crate::utils::generate_address_from_secret(&secret_key);
        let wallet2 = Wallet::new();
        
        // Setup sender account
        let account = Account::with_balances(from_addr.clone(), 1000, 0).unwrap();
        account_manager.update_account(account);
        
        // Create and sign transaction
        let tx = create_signed_transaction(&crypto, &secret_key, &from_addr, wallet2.address(), 1, 10);
        
        // Add to mempool
        mempool.add_transaction(tx.clone(), &account_manager, &crypto).unwrap();
        
        // Verify it's in mempool
        assert!(mempool.get_transaction(&tx.tx_id).is_some());
        assert_eq!(mempool.get_stats().total_transactions, 1);
    }

    #[test]
    fn test_transaction_replacement() {
        let mut mempool = Mempool::new();
        let crypto = CryptoEngine::new();
        let mut account_manager = AccountManager::new();
        
        let (secret_key, _) = crypto.generate_keypair();
        let from_addr = crate::utils::generate_address_from_secret(&secret_key);
        let wallet2 = Wallet::new();
        
        // Setup sender account
        let account = Account::with_balances(from_addr.clone(), 1000, 0).unwrap();
        account_manager.update_account(account);
        
        // Create first transaction
        let tx1 = create_signed_transaction(&crypto, &secret_key, &from_addr, wallet2.address(), 1, 10);
        mempool.add_transaction(tx1.clone(), &account_manager, &crypto).unwrap();
        
        // Create replacement transaction with higher fee
        let tx2 = create_signed_transaction(&crypto, &secret_key, &from_addr, wallet2.address(), 1, 15); // 50% higher fee
        
        // Should replace the first transaction
        mempool.add_transaction(tx2.clone(), &account_manager, &crypto).unwrap();
        
        // First transaction should be gone, second should be present
        assert!(mempool.get_transaction(&tx1.tx_id).is_none());
        assert!(mempool.get_transaction(&tx2.tx_id).is_some());
        assert_eq!(mempool.get_stats().total_transactions, 1);
    }

    #[test]
    fn test_transaction_selection_for_block() {
        let mut mempool = Mempool::new();
        let crypto = CryptoEngine::new();
        let mut account_manager = AccountManager::new();
        
        let (secret_key, _) = crypto.generate_keypair();
        let from_addr = crate::utils::generate_address_from_secret(&secret_key);
        let wallet2 = Wallet::new();
        
        // Setup sender account
        let account = Account::with_balances(from_addr.clone(), 1000, 0).unwrap();
        account_manager.update_account(account);
        
        // Add multiple transactions with different fees
        for i in 1..=5 {
            let tx = create_signed_transaction(&crypto, &secret_key, &from_addr, wallet2.address(), i, 10 + i * 5);
            mempool.add_transaction(tx, &account_manager, &crypto).unwrap();
        }
        
        // Select transactions for block (should be in nonce order despite fee priority)
        let selected = mempool.select_transactions_for_block(&account_manager, 3, 1000);
        
        // Should get first 3 transactions in nonce order
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].nonce, 1);
        assert_eq!(selected[1].nonce, 2);
        assert_eq!(selected[2].nonce, 3);
    }

    #[test]
    fn test_expired_transaction_cleanup() {
        let config = MempoolConfig {
            transaction_ttl_minutes: 0, // Immediate expiry for testing
            ..Default::default()
        };
        let mut mempool = Mempool::with_config(config);
        let crypto = CryptoEngine::new();
        let mut account_manager = AccountManager::new();
        
        let (secret_key, _) = crypto.generate_keypair();
        let from_addr = crate::utils::generate_address_from_secret(&secret_key);
        let wallet2 = Wallet::new();
        
        // Setup sender account
        let account = Account::with_balances(from_addr.clone(), 1000, 0).unwrap();
        account_manager.update_account(account);
        
        // Add transaction
        let tx = create_signed_transaction(&crypto, &secret_key, &from_addr, wallet2.address(), 1, 10);
        mempool.add_transaction(tx, &account_manager, &crypto).unwrap();
        
        assert_eq!(mempool.get_stats().total_transactions, 1);
        
        // Cleanup should remove expired transaction
        let cleaned = mempool.cleanup_expired_transactions();
        assert_eq!(cleaned, 1);
        assert_eq!(mempool.get_stats().total_transactions, 0);
    }

    #[test]
    fn test_mempool_limits() {
        let config = MempoolConfig {
            max_transactions: 2,
            max_transactions_per_account: 1,
            min_gas_fee: 5,
            ..Default::default()
        };
        let mut mempool = Mempool::with_config(config);
        let crypto = CryptoEngine::new();
        let mut account_manager = AccountManager::new();
        
        let (secret_key1, _) = crypto.generate_keypair();
        let (secret_key2, _) = crypto.generate_keypair();
        let from_addr1 = crate::utils::generate_address_from_secret(&secret_key1);
        let from_addr2 = crate::utils::generate_address_from_secret(&secret_key2);
        
        // Setup accounts
        let account1 = Account::with_balances(from_addr1.clone(), 1000, 0).unwrap();
        let account2 = Account::with_balances(from_addr2.clone(), 1000, 0).unwrap();
        account_manager.update_account(account1);
        account_manager.update_account(account2);
        
        // Test minimum gas fee
        let low_fee_tx = create_signed_transaction(&crypto, &secret_key1, &from_addr1, &from_addr2, 1, 3);
        assert!(mempool.add_transaction(low_fee_tx, &account_manager, &crypto).is_err());
        
        // Test per-account limit
        let tx1 = create_signed_transaction(&crypto, &secret_key1, &from_addr1, &from_addr2, 1, 10);
        mempool.add_transaction(tx1, &account_manager, &crypto).unwrap();
        
        let tx2 = create_signed_transaction(&crypto, &secret_key1, &from_addr1, &from_addr2, 2, 10);
        assert!(mempool.add_transaction(tx2, &account_manager, &crypto).is_err());
    }
}