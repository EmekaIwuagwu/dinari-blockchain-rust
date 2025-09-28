// src/transaction.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use anyhow::{Result, anyhow};
use crate::{
    account::{AccountManager, TokenType},
    crypto::{CryptoEngine, TransactionSigningData, Hash, Address, Signature},
    utils,
};

/// Transaction status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
}

/// Transaction type for genesis compatibility
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    Transfer { from: Address, to: Address, amount: u64, token: TokenType },
    Mint { to: Address, amount: u64, token: TokenType },
}

/// Transaction structure with DTx prefix and full validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub tx_id: String,        // Format: DTx{32-char-hex}
    pub from: String,         // Format: DTxxxxx... (DT prefix)
    pub to: String,           // Format: DTxxxxx...
    pub amount: u64,          // Amount to transfer (in smallest unit)
    pub token_type: TokenType,
    pub nonce: u64,           // Account nonce to prevent replay attacks
    pub gas_fee: u64,         // Gas fee in DINARI (always DINARI)
    pub signature: Vec<u8>,   // 65-byte signature
    pub timestamp: DateTime<Utc>,
    pub status: TransactionStatus,
    
    // Additional fields for genesis compatibility
    pub transaction_type: TransactionType,
}

impl Transaction {
    /// Create new transaction (unsigned)
    pub fn new(
        from: String,
        to: String,
        amount: u64,
        token_type: TokenType,
        nonce: u64,
        gas_fee: u64,
    ) -> Result<Self> {
        // Validate addresses
        if !utils::validate_address(&from)? {
            return Err(anyhow!("Invalid sender address: {}", from));
        }
        if !utils::validate_address(&to)? {
            return Err(anyhow!("Invalid recipient address: {}", to));
        }
        
        // Validate amounts
        if amount == 0 {
            return Err(anyhow!("Transfer amount must be greater than zero"));
        }
        if gas_fee == 0 {
            return Err(anyhow!("Gas fee must be greater than zero"));
        }
        
        // Cannot send to self
        if from == to {
            return Err(anyhow!("Cannot send transaction to self"));
        }

        // Create transaction type
        let from_addr = Address::from_hex(&from)?;
        let to_addr = Address::from_hex(&to)?;
        // FIXED: Clone token_type to avoid move
        let transaction_type = TransactionType::Transfer { 
            from: from_addr, 
            to: to_addr, 
            amount, 
            token: token_type.clone() // Clone here to avoid the move
        };

        Ok(Self {
            tx_id: utils::generate_transaction_id(),
            from,
            to,
            amount,
            token_type, // Use original value here
            nonce,
            gas_fee,
            signature: Vec::new(),
            timestamp: Utc::now(),
            status: TransactionStatus::Pending,
            transaction_type,
        })
    }

    /// Create a mint transaction (for genesis)
    pub fn mint(to: Address, amount: u64, token: TokenType) -> Result<Self> {
        // FIXED: Clone token to avoid move error
        let transaction_type = TransactionType::Mint { to, amount, token: token.clone() };
        
        Ok(Self {
            tx_id: utils::generate_transaction_id(),
            from: "0x0000000000000000000000000000000000000000".to_string(), // Zero address for minting
            to: to.to_hex(),
            amount,
            token_type: token, // Use original value here
            nonce: 0, // Genesis transactions don't use nonce
            gas_fee: 0, // Genesis transactions don't pay gas
            signature: Vec::new(), // Genesis transactions don't need signatures
            timestamp: Utc::now(),
            status: TransactionStatus::Confirmed, // Genesis transactions are pre-confirmed
            transaction_type,
        })
    }

    /// Sign the transaction with a private key
    pub fn sign(&mut self, crypto: &CryptoEngine, secret_key: &secp256k1::SecretKey) -> Result<()> {
        if !self.signature.is_empty() {
            return Err(anyhow!("Transaction already signed"));
        }

        let signing_data = self.create_signing_data();
        let signature = crypto.sign_message(&crypto.create_transaction_message(&signing_data), secret_key)?;
        
        if signature.len() != 65 {
            return Err(anyhow!("Invalid signature length: expected 65 bytes"));
        }
        
        self.signature = signature;
        Ok(())
    }

    /// Verify the transaction signature
    pub fn verify_signature(&self, crypto: &CryptoEngine) -> Result<bool> {
        // Genesis mint transactions don't need signature verification
        if matches!(self.transaction_type, TransactionType::Mint { .. }) {
            return Ok(true);
        }

        if self.signature.is_empty() {
            return Ok(false);
        }

        if self.signature.len() != 65 {
            return Ok(false);
        }

        // Create the message that was signed
        let signing_data = self.create_signing_data();
        let message = crypto.create_transaction_message(&signing_data);
        
        // Recover public key from signature
        let recovered_pubkey = crypto.recover_public_key(&message, &self.signature)?;
        
        // Generate address from recovered public key
        let recovered_address = utils::generate_address(&recovered_pubkey);
        
        // Verify it matches the sender address
        Ok(recovered_address == self.from)
    }

    /// Validate transaction against account state
    pub fn validate(&self, account_manager: &AccountManager) -> Result<()> {
        // Genesis mint transactions skip most validation
        if matches!(self.transaction_type, TransactionType::Mint { .. }) {
            return self.validate_format_mint();
        }

        // Basic validation
        self.validate_format()?;
        
        // Check if sender account exists and has sufficient balance
        let sender_account = account_manager.get_account(&self.from)
            .ok_or_else(|| anyhow!("Sender account not found: {}", self.from))?;
        
        // Validate nonce
        if !sender_account.validate_nonce(self.nonce) {
            return Err(anyhow!(
                "Invalid nonce: expected {}, got {}",
                sender_account.nonce + 1,
                self.nonce
            ));
        }
        
        // Check if sender can pay for transaction
        if !sender_account.can_pay_transaction(self.amount, &self.token_type, self.gas_fee) {
            return Err(anyhow!(
                "Insufficient balance: need {} {} + {} DINARI gas, but sender has {} DINARI, {} AFRICOIN",
                self.amount,
                self.token_type,
                self.gas_fee,
                sender_account.dinari_balance,
                sender_account.africoin_balance
            ));
        }
        
        // Validate timestamp (not too old or too far in future)
        if !utils::validate_timestamp(self.timestamp.timestamp() as u64) {
            return Err(anyhow!("Invalid timestamp: transaction too old or too far in future"));
        }
        
        Ok(())
    }

    /// Validate mint transaction format
    fn validate_format_mint(&self) -> Result<()> {
        // Validate transaction ID format
        if !utils::validate_transaction_id(&self.tx_id) {
            return Err(anyhow!("Invalid transaction ID format: {}", self.tx_id));
        }
        
        // Validate recipient address
        if !utils::validate_address(&self.to)? {
            return Err(anyhow!("Invalid recipient address: {}", self.to));
        }
        
        // Validate amount
        if self.amount == 0 {
            return Err(anyhow!("Mint amount must be greater than zero"));
        }
        
        Ok(())
    }

    /// Validate transaction format (addresses, IDs, basic rules)
    pub fn validate_format(&self) -> Result<()> {
        // Check if this is a mint transaction
        if matches!(self.transaction_type, TransactionType::Mint { .. }) {
            return self.validate_format_mint();
        }

        // Validate transaction ID format
        if !utils::validate_transaction_id(&self.tx_id) {
            return Err(anyhow!("Invalid transaction ID format: {}", self.tx_id));
        }
        
        // Validate addresses
        if !utils::validate_address(&self.from)? {
            return Err(anyhow!("Invalid sender address: {}", self.from));
        }
        if !utils::validate_address(&self.to)? {
            return Err(anyhow!("Invalid recipient address: {}", self.to));
        }
        
        // Validate amounts
        if self.amount == 0 {
            return Err(anyhow!("Transfer amount must be greater than zero"));
        }
        if self.gas_fee == 0 {
            return Err(anyhow!("Gas fee must be greater than zero"));
        }
        
        // Check self-transfer
        if self.from == self.to {
            return Err(anyhow!("Cannot send transaction to self"));
        }
        
        // Validate signature presence (not required for mint)
        if self.signature.is_empty() {
            return Err(anyhow!("Transaction not signed"));
        }
        if self.signature.len() != 65 {
            return Err(anyhow!("Invalid signature length: {}", self.signature.len()));
        }
        
        Ok(())
    }

    /// Execute the transaction (update account states)
    pub fn execute(&self, account_manager: &mut AccountManager) -> Result<()> {
        match &self.transaction_type {
            TransactionType::Transfer { .. } => {
                // Final validation before execution
                self.validate(account_manager)?;
                
                // Process the transfer
                account_manager.process_transfer(
                    &self.from,
                    &self.to,
                    self.amount,
                    &self.token_type,
                    self.gas_fee,
                )?;
            }
            TransactionType::Mint { to, amount, token } => {
                // FIXED: Create a copy of the recipient address to avoid borrowing conflicts
                let recipient_address_str = to.to_hex();
                
                // FIXED: Create account and update balance, then clone before updating manager
                {
                    let recipient_account = account_manager.get_or_create_account(&recipient_address_str)?;
                    
                    // Add minted tokens to recipient
                    match token {
                        TokenType::DINARI => {
                            recipient_account.dinari_balance += amount;
                        }
                        TokenType::AFRICOIN => {
                            recipient_account.africoin_balance += amount;
                        }
                    }
                    // Account is automatically updated when the mutable reference is dropped
                }
            }
        }
        
        Ok(())
    }

    /// Create signing data for this transaction
    fn create_signing_data(&self) -> TransactionSigningData {
        TransactionSigningData {
            from: self.from.clone(),
            to: self.to.clone(),
            amount: self.amount,
            token_type: self.token_type.to_string(),
            nonce: self.nonce,
            gas_fee: self.gas_fee,
        }
    }

    /// Calculate transaction hash for indexing (returns Vec<u8>)
    pub fn calculate_hash(&self) -> Vec<u8> {
        let data = bincode::serialize(self).unwrap_or_default();
        utils::hash_data(&data)
    }

    /// Calculate transaction hash as Hash type (for consensus compatibility)
    pub fn hash(&self) -> Result<Hash> {
        let hash_bytes = self.calculate_hash();
        if hash_bytes.len() != 32 {
            return Err(anyhow!("Invalid hash length"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash_bytes);
        Ok(Hash::from_bytes(bytes))
    }

    /// Calculate transaction hash as hex string
    pub fn hash_hex(&self) -> String {
        let hash_bytes = self.calculate_hash();
        utils::bytes_to_hex(&hash_bytes)
    }

    /// Set transaction status
    pub fn set_status(&mut self, status: TransactionStatus) {
        self.status = status;
    }

    /// Check if transaction is confirmed
    pub fn is_confirmed(&self) -> bool {
        self.status == TransactionStatus::Confirmed
    }

    /// Check if transaction is pending
    pub fn is_pending(&self) -> bool {
        self.status == TransactionStatus::Pending
    }

    /// Check if transaction failed
    pub fn is_failed(&self) -> bool {
        self.status == TransactionStatus::Failed
    }

    /// Check if transaction is a mint transaction
    pub fn is_mint(&self) -> bool {
        matches!(self.transaction_type, TransactionType::Mint { .. })
    }

    /// Check if transaction is a transfer transaction
    pub fn is_transfer(&self) -> bool {
        matches!(self.transaction_type, TransactionType::Transfer { .. })
    }

    /// Serialize transaction for storage
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Failed to serialize transaction: {}", e))
    }

    /// Deserialize transaction from storage
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Failed to deserialize transaction: {}", e))
    }

    /// Get transaction summary for display
    pub fn summary(&self) -> String {
        match &self.transaction_type {
            TransactionType::Transfer { .. } => {
                format!(
                    "TX {} | {} → {} | {} {} + {} DINARI gas | Status: {:?}",
                    &self.tx_id[..12], // Show first 12 chars
                    &self.from[..10],   // Show first 10 chars
                    &self.to[..10],     // Show first 10 chars  
                    self.amount,
                    self.token_type,
                    self.gas_fee,
                    self.status
                )
            }
            TransactionType::Mint { to, amount, token } => {
                format!(
                    "MINT {} | → {} | {} {} | Status: {:?}",
                    &self.tx_id[..12],
                    &to.to_hex()[..10],
                    amount,
                    token,
                    self.status
                )
            }
        }
    }
}

/// Transaction builder for easier creation
pub struct TransactionBuilder {
    from: Option<String>,
    to: Option<String>,
    amount: Option<u64>,
    token_type: Option<TokenType>,
    nonce: Option<u64>,
    gas_fee: Option<u64>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            from: None,
            to: None,
            amount: None,
            token_type: None,
            nonce: None,
            gas_fee: None,
        }
    }

    pub fn from(mut self, from: String) -> Self {
        self.from = Some(from);
        self
    }

    pub fn to(mut self, to: String) -> Self {
        self.to = Some(to);
        self
    }

    pub fn amount(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }

    pub fn token_type(mut self, token_type: TokenType) -> Self {
        self.token_type = Some(token_type);
        self
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn gas_fee(mut self, gas_fee: u64) -> Self {
        self.gas_fee = Some(gas_fee);
        self
    }

    pub fn build(self) -> Result<Transaction> {
        Transaction::new(
            self.from.ok_or_else(|| anyhow!("From address required"))?,
            self.to.ok_or_else(|| anyhow!("To address required"))?,
            self.amount.ok_or_else(|| anyhow!("Amount required"))?,
            self.token_type.ok_or_else(|| anyhow!("Token type required"))?,
            self.nonce.ok_or_else(|| anyhow!("Nonce required"))?,
            self.gas_fee.ok_or_else(|| anyhow!("Gas fee required"))?,
        )
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Wallet;

    #[test]
    fn test_transaction_creation() {
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::new();
        
        let tx = Transaction::new(
            wallet1.address().to_string(),
            wallet2.address().to_string(),
            1000,
            TokenType::DINARI,
            1,
            10,
        ).unwrap();
        
        assert!(tx.tx_id.starts_with("DTx"));
        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.token_type, TokenType::DINARI);
        assert_eq!(tx.gas_fee, 10);
        assert_eq!(tx.status, TransactionStatus::Pending);
        assert!(tx.signature.is_empty()); // Not signed yet
        assert!(tx.is_transfer());
        assert!(!tx.is_mint());
    }

    #[test]
    fn test_mint_transaction_creation() {
        let wallet = Wallet::new();
        let address = Address::from_hex(&wallet.address()).unwrap();
        
        let mint_tx = Transaction::mint(address, 1000000, TokenType::DINARI).unwrap();
        
        assert!(mint_tx.tx_id.starts_with("DTx"));
        assert_eq!(mint_tx.amount, 1000000);
        assert_eq!(mint_tx.token_type, TokenType::DINARI);
        assert_eq!(mint_tx.gas_fee, 0); // Mint transactions don't pay gas
        assert_eq!(mint_tx.status, TransactionStatus::Confirmed);
        assert!(mint_tx.is_mint());
        assert!(!mint_tx.is_transfer());
    }

    #[test]
    fn test_transaction_hashing() {
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::new();
        
        let tx = Transaction::new(
            wallet1.address().to_string(),
            wallet2.address().to_string(),
            1000,
            TokenType::DINARI,
            1,
            10,
        ).unwrap();
        
        // Test different hash methods
        let hash_vec = tx.calculate_hash();
        let hash_type = tx.hash().unwrap();
        let hash_hex = tx.hash_hex();
        
        assert_eq!(hash_vec.len(), 32);
        assert_eq!(hash_type.as_bytes(), &hash_vec[..]);
        assert_eq!(hash_hex.len(), 64); // 32 bytes as hex = 64 chars
    }

    #[test]
    fn test_transaction_signing_and_verification() {
        let crypto = CryptoEngine::new();
        let (secret_key, _) = crypto.generate_keypair();
        let sender_address = utils::generate_address_from_secret(&secret_key);
        let wallet2 = Wallet::new();
        
        let mut tx = Transaction::new(
            sender_address,
            wallet2.address().to_string(),
            500,
            TokenType::AFRICOIN,
            0,
            5,
        ).unwrap();
        
        // Sign transaction
        tx.sign(&crypto, &secret_key).unwrap();
        assert!(!tx.signature.is_empty());
        assert_eq!(tx.signature.len(), 65);
        
        // Verify signature
        let is_valid = tx.verify_signature(&crypto).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_mint_transaction_validation() {
        let wallet = Wallet::new();
        let address = Address::from_hex(&wallet.address()).unwrap();
        let account_manager = AccountManager::new();
        
        let mint_tx = Transaction::mint(address, 1000000, TokenType::DINARI).unwrap();
        
        // Mint transactions should validate without signature
        mint_tx.validate(&account_manager).unwrap();
        
        // Mint transactions should verify signature (returns true for mints)
        let crypto = CryptoEngine::new();
        assert!(mint_tx.verify_signature(&crypto).unwrap());
    }

    #[test]
    fn test_transaction_validation() {
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::new();
        let mut account_manager = AccountManager::new();
        
        // Create sender account with balance
        let sender_account = crate::account::Account::with_balances(
            wallet1.address().to_string(),
            1000,
            500,
        ).unwrap();
        account_manager.update_account(sender_account);
        
        // Create valid transaction
        let tx = Transaction::new(
            wallet1.address().to_string(),
            wallet2.address().to_string(),
            300,
            TokenType::AFRICOIN,
            1, // Next nonce should be 1 (account nonce is 0)
            20,
        ).unwrap();
        
        // Should validate successfully
        tx.validate(&account_manager).unwrap();
    }

    #[test]
    fn test_transaction_execution() {
        let crypto = CryptoEngine::new();
        let (secret_key, _) = crypto.generate_keypair();
        let sender_address = utils::generate_address_from_secret(&secret_key);
        let wallet2 = Wallet::new();
        let mut account_manager = AccountManager::new();
        
        // Setup sender account
        let sender_account = crate::account::Account::with_balances(
            sender_address.clone(),
            1000,
            500,
        ).unwrap();
        account_manager.update_account(sender_account);
        
        // Create and sign transaction
        let mut tx = Transaction::new(
            sender_address.clone(),
            wallet2.address().to_string(),
            200,
            TokenType::AFRICOIN,
            1,
            15,
        ).unwrap();
        tx.sign(&crypto, &secret_key).unwrap();
        
        // Execute transaction
        tx.execute(&mut account_manager).unwrap();
        
        // Check balances
        let sender = account_manager.get_account(&sender_address).unwrap();
        assert_eq!(sender.africoin_balance, 300); // 500 - 200
        assert_eq!(sender.dinari_balance, 985);   // 1000 - 15 (gas)
        assert_eq!(sender.nonce, 1);
        
        let recipient = account_manager.get_account(wallet2.address()).unwrap();
        assert_eq!(recipient.africoin_balance, 200);
        assert_eq!(recipient.dinari_balance, 0);
        assert_eq!(recipient.nonce, 0); // Recipients don't increment nonce
    }

    #[test]
    fn test_mint_transaction_execution() {
        let wallet = Wallet::new();
        let address = Address::from_hex(&wallet.address()).unwrap();
        let mut account_manager = AccountManager::new();
        
        let mint_tx = Transaction::mint(address, 1000000, TokenType::DINARI).unwrap();
        
        // Execute mint transaction
        mint_tx.execute(&mut account_manager).unwrap();
        
        // Check that recipient account was created and has balance
        let recipient = account_manager.get_account(&wallet.address()).unwrap();
        assert_eq!(recipient.dinari_balance, 1000000);
        assert_eq!(recipient.africoin_balance, 0);
    }

    #[test]
    fn test_transaction_builder() {
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::new();
        
        let tx = TransactionBuilder::new()
            .from(wallet1.address().to_string())
            .to(wallet2.address().to_string())
            .amount(750)
            .token_type(TokenType::DINARI)
            .nonce(2)
            .gas_fee(25)
            .build()
            .unwrap();
        
        assert_eq!(tx.amount, 750);
        assert_eq!(tx.token_type, TokenType::DINARI);
        assert_eq!(tx.nonce, 2);
        assert_eq!(tx.gas_fee, 25);
        assert!(tx.is_transfer());
    }

    #[test]
    fn test_transaction_serialization() {
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::new();
        
        let tx = Transaction::new(
            wallet1.address().to_string(),
            wallet2.address().to_string(),
            1000,
            TokenType::DINARI,
            1,
            10,
        ).unwrap();
        
        let serialized = tx.serialize().unwrap();
        let deserialized = Transaction::deserialize(&serialized).unwrap();
        
        assert_eq!(tx.tx_id, deserialized.tx_id);
        assert_eq!(tx.from, deserialized.from);
        assert_eq!(tx.to, deserialized.to);
        assert_eq!(tx.amount, deserialized.amount);
        assert_eq!(tx.token_type, deserialized.token_type);
    }
}