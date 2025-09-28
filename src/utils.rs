// src/utils.rs
use sha2::{Digest, Sha256};
use bs58;
use uuid::Uuid;
use secp256k1::{PublicKey, SecretKey};
use anyhow::{Result, anyhow};

// Constants for prefixes
pub const ADDRESS_PREFIX: &str = "DT";
pub const TRANSACTION_PREFIX: &str = "DTx";
pub const ADDRESS_LENGTH: usize = 34; // DT + 32 chars
pub const CHECKSUM_LENGTH: usize = 4;

/// Generate DT-prefixed address from public key
pub fn generate_address(public_key: &PublicKey) -> String {
    // Get public key bytes
    let pubkey_bytes = public_key.serialize();
    
    // Hash the public key with SHA256
    let mut hasher = Sha256::new();
    hasher.update(&pubkey_bytes);
    let hash = hasher.finalize();
    
    // Take first 20 bytes of hash
    let payload = &hash[..20];
    
    // Add checksum (first 4 bytes of double SHA256)
    let checksum = calculate_checksum(payload);
    
    // Combine payload + checksum
    let mut full_payload = payload.to_vec();
    full_payload.extend_from_slice(&checksum);
    
    // Encode with Base58 and add DT prefix
    format!("{}{}", ADDRESS_PREFIX, bs58::encode(full_payload).into_string())
}

/// Generate DT-prefixed address from secret key
pub fn generate_address_from_secret(secret_key: &SecretKey) -> String {
    let secp = secp256k1::Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, secret_key);
    generate_address(&public_key)
}

/// Validate DT-prefixed address format
pub fn validate_address(address: &str) -> Result<bool> {
    // Check prefix
    if !address.starts_with(ADDRESS_PREFIX) {
        return Ok(false);
    }
    
    // Check minimum length
    if address.len() < ADDRESS_LENGTH {
        return Ok(false);
    }
    
    // Extract base58 part (remove DT prefix)
    let base58_part = &address[ADDRESS_PREFIX.len()..];
    
    // Decode base58
    let decoded = bs58::decode(base58_part)
        .into_vec()
        .map_err(|_| anyhow!("Invalid base58 encoding"))?;
    
    // Check decoded length (20 bytes payload + 4 bytes checksum)
    if decoded.len() != 24 {
        return Ok(false);
    }
    
    // Verify checksum
    let (payload, checksum) = decoded.split_at(20);
    let calculated_checksum = calculate_checksum(payload);
    
    Ok(checksum == calculated_checksum)
}

/// Generate DTx-prefixed transaction ID (no dashes)
pub fn generate_transaction_id() -> String {
    let uuid = Uuid::new_v4();
    let uuid_str = uuid.to_string().replace("-", ""); // Remove all dashes
    format!("{}{}", TRANSACTION_PREFIX, uuid_str)
}

/// Validate DTx-prefixed transaction ID format
pub fn validate_transaction_id(tx_id: &str) -> bool {
    if !tx_id.starts_with(TRANSACTION_PREFIX) {
        return false;
    }
    
    // Extract the UUID part (should be 32 hex chars after DTx)
    let uuid_part = &tx_id[TRANSACTION_PREFIX.len()..];
    
    // Should be exactly 32 hex characters
    if uuid_part.len() != 32 {
        return false;
    }
    
    // Check if all characters are valid hex
    uuid_part.chars().all(|c| c.is_ascii_hexdigit())
}

/// Calculate 4-byte checksum using double SHA256
fn calculate_checksum(payload: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let first_hash = hasher.finalize();
    
    let mut second_hasher = Sha256::new();
    second_hasher.update(&first_hash);
    let second_hash = second_hasher.finalize();
    
    second_hash[..CHECKSUM_LENGTH].to_vec()
}

/// Hash data using SHA256
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex).map_err(|e| anyhow!("Invalid hex string: {}", e))
}

/// Validate timestamp (not too far in past/future)
pub fn validate_timestamp(timestamp: u64) -> bool {
    let now = chrono::Utc::now().timestamp() as u64;
    let max_drift = 300; // 5 minutes
    
    timestamp <= now + max_drift && timestamp >= now.saturating_sub(max_drift)
}

/// Generate random secret key for testing
pub fn generate_random_keypair() -> (SecretKey, PublicKey) {
    let secp = secp256k1::Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_address_generation() {
        let (secret_key, public_key) = generate_random_keypair();
        
        // Generate address from public key
        let address1 = generate_address(&public_key);
        
        // Generate address from secret key
        let address2 = generate_address_from_secret(&secret_key);
        
        // Should be identical
        assert_eq!(address1, address2);
        
        // Should start with DT
        assert!(address1.starts_with("DT"));
        
        // Should be valid
        assert!(validate_address(&address1).unwrap());
    }
    
    #[test]
    fn test_transaction_id_generation() {
        let tx_id = generate_transaction_id();
        
        // Should start with DTx
        assert!(tx_id.starts_with("DTx"));
        
        // Should be exactly DTx + 32 hex chars (no dashes)
        assert_eq!(tx_id.len(), 3 + 32); // DTx + 32 hex chars
        
        // Should be valid format
        assert!(validate_transaction_id(&tx_id));
        
        // Should generate unique IDs
        let tx_id2 = generate_transaction_id();
        assert_ne!(tx_id, tx_id2);
    }
    
    #[test]
    fn test_address_validation() {
        // Valid address
        let (_, public_key) = generate_random_keypair();
        let valid_address = generate_address(&public_key);
        assert!(validate_address(&valid_address).unwrap());
        
        // Invalid addresses
        assert!(!validate_address("InvalidAddress").unwrap());
        assert!(!validate_address("DT123").unwrap()); // Too short
        assert!(!validate_address("BT1234567890abcdef").unwrap()); // Wrong prefix
    }
    
    #[test]
    fn test_transaction_id_validation() {
        // Valid transaction ID
        let valid_tx_id = generate_transaction_id();
        assert!(validate_transaction_id(&valid_tx_id));
        
        // Invalid transaction IDs
        assert!(!validate_transaction_id("InvalidTxId"));
        assert!(!validate_transaction_id("DTxinvaliduuid"));  // Not hex
        assert!(!validate_transaction_id("TX12345"));         // Wrong prefix
        assert!(!validate_transaction_id("DTx123"));          // Too short
    }
}