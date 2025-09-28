// src/config/consensus.rs
use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Proof of Authority consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Target time between blocks in seconds
    pub block_time_seconds: u64,
    
    /// Maximum number of transactions per block
    pub max_transactions_per_block: usize,
    
    /// Maximum gas limit per block
    pub max_block_gas: u64,
    
    /// Minimum gas fee required for transactions
    pub min_gas_fee: u64,
    
    /// Block finality confirmations (for safety)
    pub finality_confirmations: u64,
    
    /// Maximum block size in bytes
    pub max_block_size: usize,
    
    /// Validator configuration
    pub validator: ValidatorConfig,
    
    /// Block production configuration
    pub production: ProductionConfig,
    
    /// Synchronization configuration
    pub sync: SyncConfig,
    
    /// Fee configuration
    pub fees: FeeConfig,
    
    /// Emergency configuration
    pub emergency: EmergencyConfig,
}

/// Validator-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Enable validator mode
    pub enabled: bool,
    
    /// Validator private key file path (optional, can use CLI)
    pub private_key_file: Option<String>,
    
    /// Validator address (derived from private key)
    pub address: Option<String>,
    
    /// Minimum stake required to be a validator (for future upgrades)
    pub min_stake: u64,
    
    /// Validator timeout before being considered offline (seconds)
    pub timeout_seconds: u64,
    
    /// Maximum consecutive failed blocks before removal
    pub max_failed_blocks: u32,
    
    /// Validator rotation interval in blocks (0 = no rotation)
    pub rotation_interval_blocks: u64,
    
    /// Enable validator performance tracking
    pub track_performance: bool,
    
    /// Reward configuration
    pub rewards: RewardConfig,
}

/// Block production configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionConfig {
    /// Enable block production
    pub enabled: bool,
    
    /// Wait time before producing empty blocks (seconds)
    pub empty_block_delay_seconds: u64,
    
    /// Maximum wait time for transactions before forcing block (seconds)
    pub max_tx_wait_seconds: u64,
    
    /// Minimum transactions before producing block
    pub min_transactions: usize,
    
    /// Enable mempool pre-validation
    pub enable_mempool_validation: bool,
    
    /// Maximum time to spend validating transactions (milliseconds)
    pub validation_timeout_ms: u64,
    
    /// Enable transaction ordering by gas price
    pub enable_gas_price_ordering: bool,
    
    /// Block template cache duration (seconds)
    pub template_cache_seconds: u64,
}

/// Blockchain synchronization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Enable blockchain synchronization
    pub enabled: bool,
    
    /// Maximum blocks to request in one sync batch
    pub max_blocks_per_request: u64,
    
    /// Sync request timeout in seconds
    pub request_timeout_seconds: u64,
    
    /// Maximum number of concurrent sync requests
    pub max_concurrent_requests: usize,
    
    /// Sync retry attempts for failed requests
    pub max_retry_attempts: u32,
    
    /// Backoff delay between retries (seconds)
    pub retry_backoff_seconds: u64,
    
    /// Fast sync configuration
    pub fast_sync: FastSyncConfig,
    
    /// State sync configuration (for large blockchains)
    pub state_sync: StateSyncConfig,
}

/// Fast synchronization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastSyncConfig {
    /// Enable fast sync (sync headers first, then bodies)
    pub enabled: bool,
    
    /// Maximum headers to request per batch
    pub max_headers_per_request: u64,
    
    /// Minimum peers required for fast sync
    pub min_peers: usize,
    
    /// Header validation mode: "full", "light", "checkpoint"
    pub validation_mode: String,
    
    /// Checkpoint blocks for validation (block_number -> hash)
    pub checkpoints: Vec<(u64, String)>,
}

/// State synchronization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncConfig {
    /// Enable state sync
    pub enabled: bool,
    
    /// State sync interval in blocks
    pub interval_blocks: u64,
    
    /// Maximum state chunks per request
    pub max_chunks_per_request: usize,
    
    /// State verification mode: "full", "light", "merkle"
    pub verification_mode: String,
}

/// Fee calculation and management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    /// Base gas fee (minimum fee per transaction)
    pub base_gas_fee: u64,
    
    /// Gas price adjustment algorithm: "fixed", "dynamic", "auction"
    pub price_algorithm: String,
    
    /// Dynamic fee configuration
    pub dynamic_fees: DynamicFeeConfig,
    
    /// Fee distribution
    pub distribution: FeeDistributionConfig,
    
    /// Enable fee burning (deflationary mechanism)
    pub enable_burning: bool,
    
    /// Percentage of fees to burn (0-100)
    pub burn_percentage: u8,
}

/// Dynamic fee adjustment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicFeeConfig {
    /// Enable dynamic fee adjustment
    pub enabled: bool,
    
    /// Target block utilization percentage (0-100)
    pub target_utilization: u8,
    
    /// Fee adjustment per block (percentage)
    pub adjustment_rate: f64,
    
    /// Maximum fee multiplier
    pub max_multiplier: f64,
    
    /// Minimum fee multiplier
    pub min_multiplier: f64,
    
    /// Window size for utilization calculation (blocks)
    pub utilization_window: u64,
}

/// Fee distribution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistributionConfig {
    /// Percentage to validator (0-100)
    pub validator_percentage: u8,
    
    /// Percentage to treasury (0-100)
    pub treasury_percentage: u8,
    
    /// Percentage to stakers (0-100, for future staking)
    pub staker_percentage: u8,
    
    /// Treasury address
    pub treasury_address: Option<String>,
}

/// Validator rewards configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    /// Block reward amount
    pub block_reward: u64,
    
    /// Enable performance-based rewards
    pub performance_based: bool,
    
    /// Minimum performance score for full rewards (0-100)
    pub min_performance_score: u8,
    
    /// Reward reduction for poor performance (percentage)
    pub performance_penalty: u8,
    
    /// Uncle block rewards (for handling forks)
    pub uncle_rewards: bool,
    
    /// Uncle block reward percentage of main reward
    pub uncle_reward_percentage: u8,
}

/// Emergency and safety configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyConfig {
    /// Enable emergency stop mechanism
    pub enable_emergency_stop: bool,
    
    /// Emergency stop trigger addresses
    pub emergency_addresses: Vec<String>,
    
    /// Enable governance pause
    pub enable_governance_pause: bool,
    
    /// Maximum chain reorganization depth before alert
    pub max_reorg_depth: u64,
    
    /// Enable automatic recovery
    pub enable_auto_recovery: bool,
    
    /// Recovery checkpoint interval (blocks)
    pub recovery_checkpoint_interval: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            block_time_seconds: 15,
            max_transactions_per_block: 1000,
            max_block_gas: 50000,
            min_gas_fee: 1,
            finality_confirmations: 12,
            max_block_size: 10 * 1024 * 1024, // 10MB
            validator: ValidatorConfig::default(),
            production: ProductionConfig::default(),
            sync: SyncConfig::default(),
            fees: FeeConfig::default(),
            emergency: EmergencyConfig::default(),
        }
    }
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            private_key_file: None,
            address: None,
            min_stake: 10_000_000_000, // 10k tokens
            timeout_seconds: 300, // 5 minutes
            max_failed_blocks: 10,
            rotation_interval_blocks: 0, // No rotation by default
            track_performance: true,
            rewards: RewardConfig::default(),
        }
    }
}

impl Default for ProductionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            empty_block_delay_seconds: 30,
            max_tx_wait_seconds: 10,
            min_transactions: 1,
            enable_mempool_validation: true,
            validation_timeout_ms: 5000, // 5 seconds
            enable_gas_price_ordering: true,
            template_cache_seconds: 60,
        }
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_blocks_per_request: 128,
            request_timeout_seconds: 30,
            max_concurrent_requests: 5,
            max_retry_attempts: 3,
            retry_backoff_seconds: 5,
            fast_sync: FastSyncConfig::default(),
            state_sync: StateSyncConfig::default(),
        }
    }
}

impl Default for FastSyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_headers_per_request: 256,
            min_peers: 3,
            validation_mode: "checkpoint".to_string(),
            checkpoints: vec![], // To be populated with known good blocks
        }
    }
}

impl Default for StateSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for simpler setup
            interval_blocks: 10000,
            max_chunks_per_request: 50,
            verification_mode: "merkle".to_string(),
        }
    }
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            base_gas_fee: 1,
            price_algorithm: "fixed".to_string(),
            dynamic_fees: DynamicFeeConfig::default(),
            distribution: FeeDistributionConfig::default(),
            enable_burning: false,
            burn_percentage: 0,
        }
    }
}

impl Default for DynamicFeeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_utilization: 70,
            adjustment_rate: 0.1,
            max_multiplier: 10.0,
            min_multiplier: 0.1,
            utilization_window: 20,
        }
    }
}

impl Default for FeeDistributionConfig {
    fn default() -> Self {
        Self {
            validator_percentage: 100,
            treasury_percentage: 0,
            staker_percentage: 0,
            treasury_address: None,
        }
    }
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            block_reward: 1000000, // 1M tokens per block
            performance_based: true,
            min_performance_score: 80,
            performance_penalty: 50,
            uncle_rewards: false,
            uncle_reward_percentage: 50,
        }
    }
}

impl Default for EmergencyConfig {
    fn default() -> Self {
        Self {
            enable_emergency_stop: false,
            emergency_addresses: vec![],
            enable_governance_pause: false,
            max_reorg_depth: 20,
            enable_auto_recovery: true,
            recovery_checkpoint_interval: 1000,
        }
    }
}

impl ConsensusConfig {
    /// Get block time as Duration
    pub fn block_time(&self) -> Duration {
        Duration::from_secs(self.block_time_seconds)
    }
    
    /// Get validator timeout as Duration
    pub fn validator_timeout(&self) -> Duration {
        Duration::from_secs(self.validator.timeout_seconds)
    }
    
    /// Get sync request timeout as Duration
    pub fn sync_timeout(&self) -> Duration {
        Duration::from_secs(self.sync.request_timeout_seconds)
    }
    
    /// Check if validator mode is enabled
    pub fn is_validator(&self) -> bool {
        self.validator.enabled
    }
    
    /// Check if fast sync is enabled
    pub fn is_fast_sync_enabled(&self) -> bool {
        self.sync.enabled && self.sync.fast_sync.enabled
    }
    
    /// Check if dynamic fees are enabled
    pub fn has_dynamic_fees(&self) -> bool {
        self.fees.dynamic_fees.enabled
    }
    
    /// Calculate gas price based on block utilization
    pub fn calculate_gas_price(&self, block_utilization: f64) -> u64 {
        if !self.has_dynamic_fees() {
            return self.fees.base_gas_fee;
        }
        
        let config = &self.fees.dynamic_fees;
        let target = config.target_utilization as f64 / 100.0;
        
        if block_utilization > target {
            // Increase fees
            let multiplier = 1.0 + (block_utilization - target) * config.adjustment_rate;
            let multiplier = multiplier.min(config.max_multiplier);
            (self.fees.base_gas_fee as f64 * multiplier) as u64
        } else {
            // Decrease fees
            let multiplier = 1.0 - (target - block_utilization) * config.adjustment_rate;
            let multiplier = multiplier.max(config.min_multiplier);
            (self.fees.base_gas_fee as f64 * multiplier) as u64
        }
    }
    
    /// Get testnet configuration
    pub fn testnet() -> Self {
        let mut config = Self::default();
        config.block_time_seconds = 5; // Faster blocks for testing
        config.max_transactions_per_block = 100;
        config.validator.min_stake = 1_000_000; // Lower stake for testing
        config.fees.base_gas_fee = 1;
        config.finality_confirmations = 3; // Faster finality
        config
    }
    
    /// Get development configuration
    pub fn development() -> Self {
        let mut config = Self::default();
        config.block_time_seconds = 3; // Very fast blocks
        config.max_transactions_per_block = 50;
        config.validator.min_stake = 0; // No stake required
        config.fees.base_gas_fee = 1;
        config.finality_confirmations = 1; // Instant finality
        config.production.empty_block_delay_seconds = 5;
        config.sync.enabled = false; // No sync needed for dev
        config
    }
    
    /// Validate consensus configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate basic parameters
        if self.block_time_seconds == 0 {
            return Err(anyhow::anyhow!("block_time_seconds must be greater than 0"));
        }
        
        if self.max_transactions_per_block == 0 {
            return Err(anyhow::anyhow!("max_transactions_per_block must be greater than 0"));
        }
        
        if self.max_block_gas == 0 {
            return Err(anyhow::anyhow!("max_block_gas must be greater than 0"));
        }
        
        if self.max_block_size == 0 {
            return Err(anyhow::anyhow!("max_block_size must be greater than 0"));
        }
        
        // Validate validator configuration
        if self.validator.enabled {
            if self.validator.timeout_seconds == 0 {
                return Err(anyhow::anyhow!("validator.timeout_seconds must be greater than 0"));
            }
            
            if self.validator.max_failed_blocks == 0 {
                return Err(anyhow::anyhow!("validator.max_failed_blocks must be greater than 0"));
            }
        }
        
        // Validate fee distribution
        let total_percentage = self.fees.distribution.validator_percentage +
                             self.fees.distribution.treasury_percentage +
                             self.fees.distribution.staker_percentage;
        
        if total_percentage != 100 {
            return Err(anyhow::anyhow!("fee distribution percentages must sum to 100, got {}", total_percentage));
        }
        
        if self.fees.burn_percentage > 100 {
            return Err(anyhow::anyhow!("burn_percentage cannot exceed 100"));
        }
        
        // Validate dynamic fees
        if self.fees.dynamic_fees.enabled {
            if self.fees.dynamic_fees.target_utilization > 100 {
                return Err(anyhow::anyhow!("dynamic_fees.target_utilization cannot exceed 100"));
            }
            
            if self.fees.dynamic_fees.max_multiplier <= self.fees.dynamic_fees.min_multiplier {
                return Err(anyhow::anyhow!("dynamic_fees.max_multiplier must be greater than min_multiplier"));
            }
        }
        
        // Validate sync configuration
        if self.sync.enabled {
            if self.sync.max_blocks_per_request == 0 {
                return Err(anyhow::anyhow!("sync.max_blocks_per_request must be greater than 0"));
            }
            
            if self.sync.max_concurrent_requests == 0 {
                return Err(anyhow::anyhow!("sync.max_concurrent_requests must be greater than 0"));
            }
            
            if self.sync.fast_sync.enabled {
                if self.sync.fast_sync.min_peers == 0 {
                    return Err(anyhow::anyhow!("fast_sync.min_peers must be greater than 0"));
                }
                
                if !["full", "light", "checkpoint"].contains(&self.sync.fast_sync.validation_mode.as_str()) {
                    return Err(anyhow::anyhow!("fast_sync.validation_mode must be one of: full, light, checkpoint"));
                }
            }
        }
        
        // Validate emergency configuration
        if self.emergency.enable_emergency_stop && self.emergency.emergency_addresses.is_empty() {
            return Err(anyhow::anyhow!("emergency_addresses cannot be empty when emergency_stop is enabled"));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_consensus_config() {
        let config = ConsensusConfig::default();
        assert!(config.validate().is_ok());
        assert!(!config.is_validator());
        assert!(!config.has_dynamic_fees());
    }
    
    #[test]
    fn test_testnet_config() {
        let config = ConsensusConfig::testnet();
        assert!(config.validate().is_ok());
        assert_eq!(config.block_time_seconds, 5);
        assert_eq!(config.finality_confirmations, 3);
    }
    
    #[test]
    fn test_development_config() {
        let config = ConsensusConfig::development();
        assert!(config.validate().is_ok());
        assert_eq!(config.block_time_seconds, 3);
        assert_eq!(config.finality_confirmations, 1);
        assert!(!config.sync.enabled);
    }
    
    #[test]
    fn test_gas_price_calculation() {
        let mut config = ConsensusConfig::default();
        config.fees.dynamic_fees.enabled = true;
        config.fees.base_gas_fee = 100;
        
        // Low utilization should reduce price
        let low_price = config.calculate_gas_price(0.3);
        assert!(low_price <= config.fees.base_gas_fee);
        
        // High utilization should increase price
        let high_price = config.calculate_gas_price(0.9);
        assert!(high_price >= config.fees.base_gas_fee);
        
        // Fixed pricing when dynamic fees disabled
        config.fees.dynamic_fees.enabled = false;
        assert_eq!(config.calculate_gas_price(0.9), config.fees.base_gas_fee);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = ConsensusConfig::default();
        
        // Valid config should pass
        assert!(config.validate().is_ok());
        
        // Invalid block time
        config.block_time_seconds = 0;
        assert!(config.validate().is_err());
        
        // Invalid fee distribution
        config.block_time_seconds = 15;
        config.fees.distribution.validator_percentage = 50;
        config.fees.distribution.treasury_percentage = 30;
        config.fees.distribution.staker_percentage = 30; // Sum = 110
        assert!(config.validate().is_err());
    }
}