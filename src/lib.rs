//! DinariBlockchain - A Proof of Authority blockchain implementation in Rust
//! 
//! DinariBlockchain supports two tokens:
//! - DINARI: Main token pegged to USD at 1:1, used for gas fees
//! - AFRICOIN: Stable payment token pegged to USD at 1:1
//! 
//! Features:
//! - Proof of Authority consensus with round-robin validator selection
//! - Dual-token economy with gas fee mechanism
//! - Algorithmic USD peg mechanism (1 USD = 1 DINARI/AFRICOIN)
//! - RocksDB persistence layer optimized for 1GB memory constraint
//! - JSON-RPC API server for external integration
//! - secp256k1 cryptographic signatures
//! - DT-prefixed addresses with Base58 encoding
//! - DTx-prefixed transaction IDs with UUID generation
//! - Genesis block system for blockchain initialization

pub mod block;
pub mod transaction;
pub mod account;
pub mod consensus;
pub mod database;
pub mod crypto;
pub mod mempool;
pub mod rpc;
pub mod genesis;
pub mod utils;
pub mod peg; // NEW: Algorithmic USD peg module

// Re-export main types for easy access
pub use block::{Block, BlockHeader, BlockBuilder};
pub use transaction::{Transaction, TransactionBuilder, TransactionStatus};
pub use account::{Account, AccountManager, TokenType};
pub use consensus::{PoAConsensus, ConsensusConfig, ConsensusStats, Treasury, TreasuryStats}; // Added Treasury types
pub use database::{BlockchainDB, ValidatorSet, ValidatorInfo, ChainInfo, DatabaseStats};
pub use crypto::{CryptoEngine, Wallet, TransactionSigningData};
pub use mempool::{Mempool, MempoolConfig, MempoolStats};
pub use rpc::{RpcServer, RpcConfig};
pub use genesis::{GenesisConfig, GenesisBuilder};
pub use peg::{AlgorithmicPeg, AlgorithmicPegConfig, AlgorithmicPegStats, BlockActivity}; // NEW: Peg exports

// Re-export utility functions
pub use utils::{
    generate_address, 
    generate_address_from_secret, 
    validate_address,
    generate_transaction_id,
    validate_transaction_id,
    hash_data,
    bytes_to_hex,
    hex_to_bytes
};

// Additional re-exports for compatibility with main.rs
pub mod blockchain {
    //! Compatibility module - re-exports block types as blockchain types
    pub use crate::block::{Block, BlockHeader};
}

pub mod token {
    //! Compatibility module - re-exports account types as token types  
    pub use crate::account::TokenType;
}

/// DinariBlockchain version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Network constants
pub const CHAIN_ID: &str = "dinari-mainnet";
pub const GENESIS_BLOCK_REWARD: u64 = 1_000_000_000; // 1B tokens
pub const VALIDATOR_INITIAL_REWARD: u64 = 10_000_000; // 10M tokens

/// Address and transaction prefixes
pub const ADDRESS_PREFIX: &str = "DT";
pub const TRANSACTION_PREFIX: &str = "DTx";

/// Default network configuration
pub const DEFAULT_BLOCK_TIME: u64 = 15; // 15 seconds
pub const DEFAULT_MAX_TXS_PER_BLOCK: usize = 1000;
pub const DEFAULT_GAS_LIMIT: u64 = 50_000;

/// Token unit conversions (for future decimal support)
pub const DINARI_DECIMALS: u8 = 18;
pub const AFRICOIN_DECIMALS: u8 = 18;

/// USD Peg constants
pub const USD_PEG_TARGET: f64 = 1.0; // Always $1.00
pub const PEG_ENABLED_BY_DEFAULT: bool = true;