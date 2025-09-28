// src/crypto.rs
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, SecretKey, Secp256k1, All,
};
use sha2::{Digest, Sha256};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// 32-byte hash type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Create zero hash
    pub fn zero() -> Self {
        Hash([0u8; 32])
    }

    /// Create hash from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Create hash from hex string
    pub fn from_string(hash_str: &str) -> Result<Self> {
        let hex_str = hash_str.strip_prefix("0x").unwrap_or(hash_str);
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            return Err(anyhow!("Invalid hash length: expected 32 bytes, got {}", bytes.len()));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);
        Ok(Hash(hash_bytes))
    }

    /// FIXED: Added from_hex method that was missing
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        Self::from_string(hex_str)
    }

    /// Get hash as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// FIXED: Added to_bytes method that was missing
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Convert to hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Convert to hex string without 0x prefix
    pub fn to_hex_no_prefix(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

/// 20-byte address type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Create address from hex string

    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        
        // Handle DT prefix for DinariBlockchain addresses
        let hex_str = if hex_str.starts_with("DT") {
            // For DT addresses, we need to convert them to 20-byte addresses
            // This is a simplified conversion - in production you'd have proper address encoding
            let addr_part = &hex_str[2..]; // Remove DT prefix
            if addr_part.len() >= 40 {
                &addr_part[..40] // Take first 40 hex chars (20 bytes)
            } else {
                // Pad with zeros if too short
                return Ok(Address::zero());
            }
        } else {
            hex_str
        };
        
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 20 {
            return Err(anyhow!("Invalid address length: expected 20 bytes, got {}", bytes.len()));
        }
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&bytes);
        Ok(Address(addr_bytes))
    }

    /// Convert address to hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Convert address to hex string without 0x prefix
    pub fn to_hex_no_prefix(&self) -> String {
        hex::encode(self.0)
    }

    /// Create zero address
    pub fn zero() -> Self {
        Address([0u8; 20])
    }

    /// Convert to DT-prefixed address string (for compatibility)
    pub fn to_dt_address(&self) -> String {
        format!("DT{}", hex::encode(self.0))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }
}

/// Signature type wrapper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(pub Vec<u8>);

impl Signature {
    /// Create signature from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Signature(bytes)
    }

    /// Get signature as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Create signature from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)?;
        Ok(Signature(bytes))
    }

    /// Check if signature is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get signature length
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature(vec![0u8; 65])
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

/// Cryptographic engine for DinariBlockchain
#[derive(Debug, Clone)]
pub struct CryptoEngine {
    secp: Secp256k1<All>,
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> (SecretKey, PublicKey) {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&self.secp, &secret_key);
        (secret_key, public_key)
    }

    /// Sign a message with a secret key
    pub fn sign_message(&self, message: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>> {
        // Hash the message
        let message_hash = self.hash_message(message);
        
        // Create secp256k1 message from hash
        let msg = Message::from_slice(&message_hash)
            .map_err(|e| anyhow!("Failed to create message from hash: {}", e))?;

        // Create recoverable signature
        let signature = self.secp.sign_ecdsa_recoverable(&msg, secret_key);
        
        // Serialize signature with recovery ID
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let mut result = signature_bytes.to_vec();
        result.push(recovery_id.to_i32() as u8);
        
        Ok(result)
    }

    /// Verify a signature against a message and public key
    pub fn verify_signature(&self, message: &[u8], signature: &[u8], public_key: &PublicKey) -> Result<bool> {
        if signature.len() != 65 {
            return Ok(false);
        }

        // Hash the message
        let message_hash = self.hash_message(message);
        
        // Create secp256k1 message from hash
        let msg = Message::from_slice(&message_hash)
            .map_err(|e| anyhow!("Failed to create message from hash: {}", e))?;

        // Parse signature
        let signature_bytes = &signature[..64];
        let recovery_id = signature[64];
        
        let recovery_id = RecoveryId::from_i32(recovery_id as i32)
            .map_err(|e| anyhow!("Invalid recovery ID: {}", e))?;
            
        let recoverable_sig = RecoverableSignature::from_compact(signature_bytes, recovery_id)
            .map_err(|e| anyhow!("Failed to parse recoverable signature: {}", e))?;

        // Recover public key from signature
        let recovered_pubkey = self.secp.recover_ecdsa(&msg, &recoverable_sig)
            .map_err(|e| anyhow!("Failed to recover public key: {}", e))?;

        // Compare recovered public key with provided public key
        Ok(recovered_pubkey == *public_key)
    }

    /// Recover public key from message and signature
    pub fn recover_public_key(&self, message: &[u8], signature: &[u8]) -> Result<PublicKey> {
        if signature.len() != 65 {
            return Err(anyhow!("Invalid signature length"));
        }

        // Hash the message
        let message_hash = self.hash_message(message);
        
        // Create secp256k1 message from hash
        let msg = Message::from_slice(&message_hash)
            .map_err(|e| anyhow!("Failed to create message from hash: {}", e))?;

        // Parse signature
        let signature_bytes = &signature[..64];
        let recovery_id = signature[64];
        
        let recovery_id = RecoveryId::from_i32(recovery_id as i32)
            .map_err(|e| anyhow!("Invalid recovery ID: {}", e))?;
            
        let recoverable_sig = RecoverableSignature::from_compact(signature_bytes, recovery_id)
            .map_err(|e| anyhow!("Failed to parse recoverable signature: {}", e))?;

        // Recover public key from signature
        self.secp.recover_ecdsa(&msg, &recoverable_sig)
            .map_err(|e| anyhow!("Failed to recover public key: {}", e).into())
    }

    /// Hash a message using SHA256
    pub fn hash_message(&self, message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    /// Create a signable message for a transaction
    pub fn create_transaction_message(&self, tx_data: &TransactionSigningData) -> Vec<u8> {
        let mut message = Vec::new();
        
        // Add transaction fields in deterministic order
        message.extend_from_slice(tx_data.from.as_bytes());
        message.extend_from_slice(tx_data.to.as_bytes());
        message.extend_from_slice(&tx_data.amount.to_be_bytes());
        message.extend_from_slice(tx_data.token_type.as_bytes());
        message.extend_from_slice(&tx_data.nonce.to_be_bytes());
        message.extend_from_slice(&tx_data.gas_fee.to_be_bytes());
        
        message
    }

    /// Generate random hash (for testing)
    pub fn random_hash(&self) -> Hash {
        let random_bytes: [u8; 32] = rand::random();
        Hash::from_bytes(random_bytes)
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Data structure for transaction signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSigningData {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub token_type: String,
    pub nonce: u64,
    pub gas_fee: u64,
}

/// Wallet for managing keys and signing
#[derive(Debug)]
pub struct Wallet {
    crypto: CryptoEngine,
    secret_key: SecretKey,
    public_key: PublicKey,
    address: String,
}

impl Wallet {
    /// Create a new wallet with random keys
    pub fn new() -> Self {
        let crypto = CryptoEngine::new();
        let (secret_key, public_key) = crypto.generate_keypair();
        let address = crate::utils::generate_address(&public_key);
        
        Self {
            crypto,
            secret_key,
            public_key,
            address,
        }
    }

    /// Generate a random wallet (alias for new)
    pub fn generate_random() -> Self {
        Self::new()
    }

    /// Create wallet from existing secret key
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let crypto = CryptoEngine::new();
        let public_key = PublicKey::from_secret_key(&crypto.secp, &secret_key);
        let address = crate::utils::generate_address(&public_key);
        
        Self {
            crypto,
            secret_key,
            public_key,
            address,
        }
    }

    /// Get wallet address
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Get wallet address as Address type
    pub fn address_typed(&self) -> Result<Address> {
        Address::from_hex(&self.address)
    }

    /// Get public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get secret key (use carefully - needed for signing)
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Sign transaction data
    pub fn sign_transaction(&self, tx_data: &TransactionSigningData) -> Result<Vec<u8>> {
        let message = self.crypto.create_transaction_message(tx_data);
        self.crypto.sign_message(&message, &self.secret_key)
    }

    /// Sign arbitrary message
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.crypto.sign_message(message, &self.secret_key)
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for hex encoding/decoding signatures
pub fn signature_to_hex(signature: &[u8]) -> String {
    hex::encode(signature)
}

pub fn signature_from_hex(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex).map_err(|e| anyhow!("Invalid hex signature: {}", e))
}

/// Utility function to convert bytes to hash
pub fn bytes_to_hash(bytes: &[u8]) -> Result<Hash> {
    if bytes.len() != 32 {
        return Err(anyhow!("Invalid hash length: expected 32 bytes, got {}", bytes.len()));
    }
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(bytes);
    Ok(Hash::from_bytes(hash_bytes))
}

/// Utility function to convert bytes to address
pub fn bytes_to_address(bytes: &[u8]) -> Result<Address> {
    if bytes.len() != 20 {
        return Err(anyhow!("Invalid address length: expected 20 bytes, got {}", bytes.len()));
    }
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(bytes);
    Ok(Address::from_bytes(addr_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_operations() {
        // Test zero hash
        let zero_hash = Hash::zero();
        assert_eq!(zero_hash.as_bytes(), &[0u8; 32]);
        assert_eq!(zero_hash.to_hex(), "0x0000000000000000000000000000000000000000000000000000000000000000");

        // Test hash from bytes
        let test_bytes = [1u8; 32];
        let hash = Hash::from_bytes(test_bytes);
        assert_eq!(hash.as_bytes(), &test_bytes);

        // Test hex conversion
        let hex_str = hash.to_hex();
        let hash_from_hex = Hash::from_string(&hex_str).unwrap();
        assert_eq!(hash, hash_from_hex);

        // Test display
        assert_eq!(format!("{}", hash), hex_str);
    }

    #[test]
    fn test_address_operations() {
        // Test zero address
        let zero_addr = Address::zero();
        assert_eq!(zero_addr.0, [0u8; 20]);
        assert_eq!(zero_addr.to_hex(), "0x0000000000000000000000000000000000000000");

        // Test address from bytes
        let test_bytes = [1u8; 20];
        let addr = Address::from_bytes(test_bytes);
        assert_eq!(addr.0, test_bytes);

        // Test hex conversion
        let hex_str = addr.to_hex();
        let addr_from_hex = Address::from_hex(&hex_str).unwrap();
        assert_eq!(addr, addr_from_hex);

        // Test DT address conversion
        let dt_addr = addr.to_dt_address();
        assert!(dt_addr.starts_with("DT"));

        // Test display
        assert_eq!(format!("{}", addr), hex_str);
    }

    #[test]
    fn test_signature_operations() {
        let sig_bytes = vec![1u8, 2u8, 3u8, 4u8, 5u8];
        let signature = Signature::from_bytes(sig_bytes.clone());
        
        assert_eq!(signature.as_bytes(), &sig_bytes);
        assert_eq!(signature.len(), 5);
        assert!(!signature.is_empty());

        let hex_str = signature.to_hex();
        let sig_from_hex = Signature::from_hex(&hex_str).unwrap();
        assert_eq!(signature, sig_from_hex);

        // Test default signature
        let default_sig = Signature::default();
        assert_eq!(default_sig.len(), 65);
    }

    #[test]
    fn test_keypair_generation() {
        let crypto = CryptoEngine::new();
        let (secret1, public1) = crypto.generate_keypair();
        let (secret2, public2) = crypto.generate_keypair();
        
        // Keys should be different
        assert_ne!(secret1, secret2);
        assert_ne!(public1, public2);
        
        // Public key should derive from secret key
        let derived_public = PublicKey::from_secret_key(&crypto.secp, &secret1);
        assert_eq!(public1, derived_public);
    }

    #[test]
    fn test_message_signing_and_verification() {
        let crypto = CryptoEngine::new();
        let (secret_key, public_key) = crypto.generate_keypair();
        let message = b"Hello DinariBlockchain!";
        
        // Sign message
        let signature = crypto.sign_message(message, &secret_key).unwrap();
        assert_eq!(signature.len(), 65); // 64 bytes + 1 recovery ID
        
        // Verify signature
        let is_valid = crypto.verify_signature(message, &signature, &public_key).unwrap();
        assert!(is_valid);
        
        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        let is_valid_wrong = crypto.verify_signature(wrong_message, &signature, &public_key).unwrap();
        assert!(!is_valid_wrong);
    }

    #[test]
    fn test_public_key_recovery() {
        let crypto = CryptoEngine::new();
        let (secret_key, original_pubkey) = crypto.generate_keypair();
        let message = b"Test recovery";
        
        // Sign message
        let signature = crypto.sign_message(message, &secret_key).unwrap();
        
        // Recover public key
        let recovered_pubkey = crypto.recover_public_key(message, &signature).unwrap();
        
        // Should match original public key
        assert_eq!(original_pubkey, recovered_pubkey);
    }

    #[test]
    fn test_transaction_signing() {
        let crypto = CryptoEngine::new();
        let (secret_key, public_key) = crypto.generate_keypair();
        
        let tx_data = TransactionSigningData {
            from: "DTsender123".to_string(),
            to: "DTreceiver456".to_string(),
            amount: 1000,
            token_type: "DINARI".to_string(),
            nonce: 1,
            gas_fee: 10,
        };
        
        // Create message and sign
        let message = crypto.create_transaction_message(&tx_data);
        let signature = crypto.sign_message(&message, &secret_key).unwrap();
        
        // Verify signature
        let is_valid = crypto.verify_signature(&message, &signature, &public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_wallet_operations() {
        let wallet = Wallet::new();
        
        // Address should start with DT
        assert!(wallet.address().starts_with("DT"));
        
        // Test address conversion
        let typed_addr = wallet.address_typed().unwrap();
        assert_eq!(typed_addr.to_dt_address(), wallet.address());
        
        // Test transaction signing
        let tx_data = TransactionSigningData {
            from: wallet.address().to_string(),
            to: "DTreceiver456".to_string(),
            amount: 500,
            token_type: "AFRICOIN".to_string(),
            nonce: 0,
            gas_fee: 5,
        };
        
        let signature = wallet.sign_transaction(&tx_data).unwrap();
        assert_eq!(signature.len(), 65);
        
        // Verify the signature works
        let crypto = CryptoEngine::new();
        let message = crypto.create_transaction_message(&tx_data);
        let is_valid = crypto.verify_signature(&message, &signature, wallet.public_key()).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_signature_hex_conversion() {
        let crypto = CryptoEngine::new();
        let (secret_key, _) = crypto.generate_keypair();
        let message = b"Test message";
        
        let signature = crypto.sign_message(message, &secret_key).unwrap();
        let hex_signature = signature_to_hex(&signature);
        let decoded_signature = signature_from_hex(&hex_signature).unwrap();
        
        assert_eq!(signature, decoded_signature);
        assert_eq!(hex_signature.len(), 130); // 65 bytes * 2 hex chars
    }

    #[test]
    fn test_utility_functions() {
        let hash_bytes = [42u8; 32];
        let hash = bytes_to_hash(&hash_bytes).unwrap();
        assert_eq!(hash.as_bytes(), &hash_bytes);

        let addr_bytes = [24u8; 20];
        let addr = bytes_to_address(&addr_bytes).unwrap();
        assert_eq!(addr.0, addr_bytes);

        // Test invalid lengths
        assert!(bytes_to_hash(&[1u8; 31]).is_err()); // Wrong length
        assert!(bytes_to_address(&[1u8; 19]).is_err()); // Wrong length
    }
}