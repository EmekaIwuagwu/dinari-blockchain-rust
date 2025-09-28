// src/account.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use crate::utils;

/// Token types supported by DinariBlockchain
/// FIXED: Added Copy trait to prevent move errors
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TokenType {
    DINARI,   // Main token, used for gas fees
    AFRICOIN, // Stable payment token
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenType::DINARI => write!(f, "DINARI"),
            TokenType::AFRICOIN => write!(f, "AFRICOIN"),
        }
    }
}

impl TokenType {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "DINARI" => Ok(TokenType::DINARI),
            "AFRICOIN" => Ok(TokenType::AFRICOIN),
            _ => Err(anyhow!("Unknown token type: {}", s)),
        }
    }

    /// Convert to string for serialization/display
    pub fn to_string(&self) -> String {
        match self {
            TokenType::DINARI => "DINARI".to_string(),
            TokenType::AFRICOIN => "AFRICOIN".to_string(),
        }
    }
}

/// Account state storing balances and nonce
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Account {
    pub address: String,
    pub dinari_balance: u64,
    pub africoin_balance: u64,
    pub nonce: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Account {
    /// Create a new account with zero balances
    pub fn new(address: String) -> Result<Self> {
        // Validate address format
        if !utils::validate_address(&address)? {
            return Err(anyhow!("Invalid address format: {}", address));
        }

        Ok(Self {
            address,
            dinari_balance: 0,
            africoin_balance: 0,
            nonce: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }

    /// Create account with initial balances (for genesis or testing)
    pub fn with_balances(
        address: String,
        dinari_balance: u64,
        africoin_balance: u64,
    ) -> Result<Self> {
        let mut account = Self::new(address)?;
        account.dinari_balance = dinari_balance;
        account.africoin_balance = africoin_balance;
        Ok(account)
    }

    /// Get balance for a specific token type
    pub fn get_balance(&self, token_type: &TokenType) -> u64 {
        match token_type {
            TokenType::DINARI => self.dinari_balance,
            TokenType::AFRICOIN => self.africoin_balance,
        }
    }

    /// Set balance for a specific token type
    pub fn set_balance(&mut self, token_type: &TokenType, amount: u64) {
        match token_type {
            TokenType::DINARI => self.dinari_balance = amount,
            TokenType::AFRICOIN => self.africoin_balance = amount,
        }
        self.updated_at = Utc::now();
    }

    /// Add to balance
    pub fn add_balance(&mut self, token_type: &TokenType, amount: u64) -> Result<()> {
        let current = self.get_balance(token_type);
        let new_balance = current.checked_add(amount)
            .ok_or_else(|| anyhow!("Balance overflow for {}", token_type))?;
        self.set_balance(token_type, new_balance);
        Ok(())
    }

    /// Subtract from balance
    pub fn subtract_balance(&mut self, token_type: &TokenType, amount: u64) -> Result<()> {
        let current = self.get_balance(token_type);
        if current < amount {
            return Err(anyhow!(
                "Insufficient balance: {} < {} for token {}",
                current, amount, token_type
            ));
        }
        self.set_balance(token_type, current - amount);
        Ok(())
    }

    /// Check if account has sufficient balance
    pub fn has_sufficient_balance(&self, token_type: &TokenType, amount: u64) -> bool {
        self.get_balance(token_type) >= amount
    }

    /// Check if account can pay for transaction (amount + gas)
    pub fn can_pay_transaction(&self, amount: u64, token_type: &TokenType, gas_fee: u64) -> bool {
        match token_type {
            TokenType::DINARI => {
                // For DINARI transfers, check if balance >= amount + gas
                self.dinari_balance >= amount.saturating_add(gas_fee)
            }
            TokenType::AFRICOIN => {
                // For AFRICOIN transfers, need enough AFRICOIN + DINARI for gas
                self.africoin_balance >= amount && self.dinari_balance >= gas_fee
            }
        }
    }

    /// Process transaction debit (subtract amount + gas)
    pub fn process_transaction_debit(&mut self, amount: u64, token_type: &TokenType, gas_fee: u64) -> Result<()> {
        // Check if can pay first
        if !self.can_pay_transaction(amount, token_type, gas_fee) {
            return Err(anyhow!("Insufficient balance for transaction"));
        }

        match token_type {
            TokenType::DINARI => {
                // Deduct both amount and gas from DINARI
                self.subtract_balance(token_type, amount.saturating_add(gas_fee))?;
            }
            TokenType::AFRICOIN => {
                // Deduct amount from AFRICOIN
                self.subtract_balance(token_type, amount)?;
                // Deduct gas from DINARI
                self.subtract_balance(&TokenType::DINARI, gas_fee)?;
            }
        }

        Ok(())
    }

    /// Process transaction credit (add amount)
    pub fn process_transaction_credit(&mut self, amount: u64, token_type: &TokenType) -> Result<()> {
        self.add_balance(token_type, amount)
    }

    /// Increment nonce (for transaction ordering)
    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
        self.updated_at = Utc::now();
    }

    /// Validate nonce for new transaction
    pub fn validate_nonce(&self, transaction_nonce: u64) -> bool {
        transaction_nonce == self.nonce + 1
    }

    /// Get total account value in DINARI equivalent (both tokens pegged 1:1 to USD)
    pub fn total_value(&self) -> u64 {
        self.dinari_balance.saturating_add(self.africoin_balance)
    }

    /// Check if account is empty (zero balances)
    pub fn is_empty(&self) -> bool {
        self.dinari_balance == 0 && self.africoin_balance == 0
    }

    /// Serialize account for storage
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Failed to serialize account: {}", e))
    }

    /// Deserialize account from storage
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Failed to deserialize account: {}", e))
    }
}

/// Account manager for handling multiple accounts
#[derive(Debug, Clone)]
pub struct AccountManager {
    accounts: HashMap<String, Account>,
}

impl AccountManager {
    /// Create new account manager
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    /// Get account by address, create if doesn't exist
    pub fn get_or_create_account(&mut self, address: &str) -> Result<&mut Account> {
        if !self.accounts.contains_key(address) {
            let account = Account::new(address.to_string())?;
            self.accounts.insert(address.to_string(), account);
        }
        Ok(self.accounts.get_mut(address).unwrap())
    }

    /// Get account by address (read-only)
    pub fn get_account(&self, address: &str) -> Option<&Account> {
        self.accounts.get(address)
    }

    /// Get mutable account by address
    pub fn get_account_mut(&mut self, address: &str) -> Option<&mut Account> {
        self.accounts.get_mut(address)
    }

    /// Update or insert account
    pub fn update_account(&mut self, account: Account) {
        self.accounts.insert(account.address.clone(), account);
    }

    /// Process a transfer between accounts
    pub fn process_transfer(
        &mut self,
        from_address: &str,
        to_address: &str,
        amount: u64,
        token_type: &TokenType,
        gas_fee: u64,
    ) -> Result<()> {
        // Validate addresses
        if from_address == to_address {
            return Err(anyhow!("Cannot transfer to same address"));
        }

        // Get or create accounts
        let from_account = self.get_or_create_account(from_address)?;
        
        // Process debit (will fail if insufficient balance)
        from_account.process_transaction_debit(amount, token_type, gas_fee)?;
        from_account.increment_nonce();
        
        // Get/create recipient account
        let to_account = self.get_or_create_account(to_address)?;
        
        // Process credit
        to_account.process_transaction_credit(amount, token_type)?;
        
        Ok(())
    }

    /// Get all accounts
    pub fn get_all_accounts(&self) -> &HashMap<String, Account> {
        &self.accounts
    }

    /// Get total supply of a token across all accounts
    pub fn get_total_supply(&self, token_type: &TokenType) -> u64 {
        self.accounts
            .values()
            .map(|account| account.get_balance(token_type))
            .sum()
    }

    /// Load accounts from serialized data
    pub fn load_accounts(&mut self, accounts_data: Vec<(String, Vec<u8>)>) -> Result<()> {
        for (address, data) in accounts_data {
            let account = Account::deserialize(&data)?;
            if account.address != address {
                return Err(anyhow!("Address mismatch in account data"));
            }
            self.accounts.insert(address, account);
        }
        Ok(())
    }

    /// Serialize all accounts for storage
    pub fn serialize_all_accounts(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let mut results = Vec::new();
        for (address, account) in &self.accounts {
            let data = account.serialize()?;
            results.push((address.clone(), data));
        }
        Ok(results)
    }
}

impl Default for AccountManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Wallet;

    #[test]
    fn test_account_creation() {
        let wallet = Wallet::new();
        let address = wallet.address().to_string();
        
        let account = Account::new(address.clone()).unwrap();
        
        assert_eq!(account.address, address);
        assert_eq!(account.dinari_balance, 0);
        assert_eq!(account.africoin_balance, 0);
        assert_eq!(account.nonce, 0);
        assert!(account.is_empty());
    }

    #[test]
    fn test_balance_operations() {
        let wallet = Wallet::new();
        let address = wallet.address().to_string();
        let mut account = Account::new(address).unwrap();
        
        // Add DINARI
        account.add_balance(&TokenType::DINARI, 1000).unwrap();
        assert_eq!(account.get_balance(&TokenType::DINARI), 1000);
        
        // Add AFRICOIN
        account.add_balance(&TokenType::AFRICOIN, 500).unwrap();
        assert_eq!(account.get_balance(&TokenType::AFRICOIN), 500);
        
        // Subtract DINARI
        account.subtract_balance(&TokenType::DINARI, 200).unwrap();
        assert_eq!(account.get_balance(&TokenType::DINARI), 800);
        
        // Total value
        assert_eq!(account.total_value(), 1300); // 800 + 500
        assert!(!account.is_empty());
    }

    #[test]
    fn test_transaction_payment_validation() {
        let wallet = Wallet::new();
        let address = wallet.address().to_string();
        let mut account = Account::with_balances(address, 1000, 500).unwrap();
        
        // DINARI transfer (amount + gas both from DINARI)
        assert!(account.can_pay_transaction(800, &TokenType::DINARI, 10));
        assert!(!account.can_pay_transaction(995, &TokenType::DINARI, 10)); // 995 + 10 > 1000
        
        // AFRICOIN transfer (amount from AFRICOIN, gas from DINARI)
        assert!(account.can_pay_transaction(400, &TokenType::AFRICOIN, 50));
        assert!(!account.can_pay_transaction(600, &TokenType::AFRICOIN, 50)); // Not enough AFRICOIN
        assert!(!account.can_pay_transaction(400, &TokenType::AFRICOIN, 1500)); // Not enough DINARI for gas
    }

    #[test]
    fn test_transaction_processing() {
        let wallet = Wallet::new();
        let address = wallet.address().to_string();
        let mut account = Account::with_balances(address, 1000, 500).unwrap();
        
        // Process DINARI debit
        account.process_transaction_debit(700, &TokenType::DINARI, 20).unwrap();
        assert_eq!(account.dinari_balance, 280); // 1000 - 700 - 20
        assert_eq!(account.africoin_balance, 500); // Unchanged
        
        // Process AFRICOIN credit
        account.process_transaction_credit(300, &TokenType::AFRICOIN).unwrap();
        assert_eq!(account.africoin_balance, 800); // 500 + 300
    }

    #[test]
    fn test_account_manager() {
        let mut manager = AccountManager::new();
        
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::new();
        let addr1 = wallet1.address().to_string();
        let addr2 = wallet2.address().to_string();
        
        // Create account with initial balance
        let account1 = Account::with_balances(addr1.clone(), 1000, 0).unwrap();
        manager.update_account(account1);
        
        // Process transfer
        manager.process_transfer(&addr1, &addr2, 300, &TokenType::DINARI, 10).unwrap();
        
        // Check results
        let from_account = manager.get_account(&addr1).unwrap();
        assert_eq!(from_account.dinari_balance, 690); // 1000 - 300 - 10
        assert_eq!(from_account.nonce, 1);
        
        let to_account = manager.get_account(&addr2).unwrap();
        assert_eq!(to_account.dinari_balance, 300);
        assert_eq!(to_account.nonce, 0); // Recipients don't increment nonce
    }

    #[test]
    fn test_nonce_validation() {
        let wallet = Wallet::new();
        let address = wallet.address().to_string();
        let mut account = Account::new(address).unwrap();
        
        assert_eq!(account.nonce, 0);
        assert!(account.validate_nonce(1)); // Next valid nonce
        assert!(!account.validate_nonce(0)); // Current nonce invalid
        assert!(!account.validate_nonce(2)); // Too high
        
        account.increment_nonce();
        assert_eq!(account.nonce, 1);
        assert!(account.validate_nonce(2)); // Next valid nonce
    }

    #[test]
    fn test_serialization() {
        let wallet = Wallet::new();
        let address = wallet.address().to_string();
        let account = Account::with_balances(address, 1000, 500).unwrap();
        
        let serialized = account.serialize().unwrap();
        let deserialized = Account::deserialize(&serialized).unwrap();
        
        assert_eq!(account, deserialized);
    }
}