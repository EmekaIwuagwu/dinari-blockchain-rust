// src/config/node.rs
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Node-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node identifier (generated if not provided)
    pub node_id: Option<String>,
    
    /// Human-readable node name
    pub node_name: String,
    
    /// Node environment: "mainnet", "testnet", "devnet", "local"
    pub environment: String,
    
    /// Working directory for all node data
    pub data_dir: PathBuf,
    
    /// Node operational mode
    pub mode: NodeMode,
    
    /// Resource limits and performance settings
    pub resources: ResourceConfig,
    
    /// Telemetry and monitoring
    pub telemetry: TelemetryConfig,
    
    /// Node identity and keys
    pub identity: IdentityConfig,
    
    /// Startup and shutdown configuration
    pub lifecycle: LifecycleConfig,
    
    /// Feature flags
    pub features: FeatureFlags,
    
    /// Performance optimization settings
    pub optimization: OptimizationConfig,
}

/// Node operational modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeMode {
    /// Full node (validator + full blockchain)
    Full {
        enable_validator: bool,
        enable_rpc: bool,
        enable_p2p: bool,
    },
    
    /// Light client (headers only + on-demand data)
    Light {
        enable_rpc: bool,
        trusted_peers: Vec<String>,
    },
    
    /// Archive node (stores all historical data)
    Archive {
        enable_validator: bool,
        enable_rpc: bool,
        enable_p2p: bool,
        prune_older_than_days: Option<u64>,
    },
    
    /// RPC-only node (no P2P, serves API only)
    RpcOnly {
        upstream_nodes: Vec<String>,
    },
    
    /// Bootstrap node (helps with peer discovery)
    Bootstrap {
        enable_metrics: bool,
    },
}

/// Resource limits and performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    /// Maximum memory usage in MB (0 = unlimited)
    pub max_memory_mb: u64,
    
    /// Maximum disk usage in MB (0 = unlimited)
    pub max_disk_mb: u64,
    
    /// Maximum CPU usage percentage (1-100)
    pub max_cpu_percent: u8,
    
    /// Number of worker threads (0 = auto-detect)
    pub worker_threads: usize,
    
    /// Enable resource monitoring
    pub enable_monitoring: bool,
    
    /// Resource check interval in seconds
    pub check_interval_secs: u64,
    
    /// Action when limits exceeded: "warn", "throttle", "shutdown"
    pub limit_action: String,
    
    /// Memory configuration
    pub memory: MemoryConfig,
    
    /// Disk configuration
    pub disk: DiskConfig,
}

/// Memory management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Cache size for blocks in MB
    pub block_cache_mb: u64,
    
    /// Cache size for transactions in MB
    pub tx_cache_mb: u64,
    
    /// Cache size for account states in MB
    pub state_cache_mb: u64,
    
    /// Enable memory compaction
    pub enable_compaction: bool,
    
    /// Compaction interval in seconds
    pub compaction_interval_secs: u64,
    
    /// Memory pool size for P2P messages in MB
    pub message_pool_mb: u64,
}

/// Disk management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskConfig {
    /// Enable automatic cleanup
    pub enable_cleanup: bool,
    
    /// Cleanup interval in seconds
    pub cleanup_interval_secs: u64,
    
    /// Keep logs for this many days
    pub log_retention_days: u64,
    
    /// Keep temporary files for this many hours
    pub temp_file_retention_hours: u64,
    
    /// Enable disk compression
    pub enable_compression: bool,
    
    /// Compression algorithm: "lz4", "zstd", "snappy"
    pub compression_algorithm: String,
}

/// Telemetry and monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Enable telemetry collection
    pub enabled: bool,
    
    /// Telemetry endpoint URL
    pub endpoint: Option<String>,
    
    /// Collection interval in seconds
    pub interval_secs: u64,
    
    /// Enable metrics export
    pub enable_metrics: bool,
    
    /// Metrics export format: "prometheus", "json", "csv"
    pub metrics_format: String,
    
    /// Metrics export port
    pub metrics_port: Option<u16>,
    
    /// Enable health checks
    pub enable_health_checks: bool,
    
    /// Health check port
    pub health_check_port: Option<u16>,
    
    /// Include sensitive data in telemetry
    pub include_sensitive_data: bool,
    
    /// Node performance tracking
    pub performance: PerformanceConfig,
}

/// Performance tracking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable performance tracking
    pub enabled: bool,
    
    /// Track block production times
    pub track_block_times: bool,
    
    /// Track transaction processing times
    pub track_tx_times: bool,
    
    /// Track network latency
    pub track_network_latency: bool,
    
    /// Track database performance
    pub track_db_performance: bool,
    
    /// Performance data retention in hours
    pub retention_hours: u64,
    
    /// Export performance data
    pub export_data: bool,
    
    /// Performance alert thresholds
    pub alerts: AlertConfig,
}

/// Performance alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable performance alerts
    pub enabled: bool,
    
    /// Alert when block time exceeds threshold (seconds)
    pub block_time_threshold_secs: u64,
    
    /// Alert when memory usage exceeds percentage
    pub memory_threshold_percent: u8,
    
    /// Alert when disk usage exceeds percentage
    pub disk_threshold_percent: u8,
    
    /// Alert when peer count drops below threshold
    pub min_peer_threshold: usize,
    
    /// Alert webhook URL
    pub webhook_url: Option<String>,
    
    /// Alert cooldown period in minutes
    pub cooldown_minutes: u64,
}

/// Node identity and cryptographic keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Node private key file path
    pub private_key_file: Option<PathBuf>,
    
    /// Auto-generate keys if not found
    pub auto_generate_keys: bool,
    
    /// Key derivation method: "random", "deterministic"
    pub key_derivation: String,
    
    /// Seed for deterministic key generation
    pub deterministic_seed: Option<String>,
    
    /// Enable key rotation
    pub enable_key_rotation: bool,
    
    /// Key rotation interval in days
    pub rotation_interval_days: u64,
    
    /// Backup old keys
    pub backup_old_keys: bool,
}

/// Node startup and shutdown configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleConfig {
    /// Startup timeout in seconds
    pub startup_timeout_secs: u64,
    
    /// Graceful shutdown timeout in seconds
    pub shutdown_timeout_secs: u64,
    
    /// Enable fast startup (skip some validations)
    pub enable_fast_startup: bool,
    
    /// Auto-restart on critical errors
    pub auto_restart: bool,
    
    /// Maximum restart attempts
    pub max_restart_attempts: u32,
    
    /// Restart cooldown period in seconds
    pub restart_cooldown_secs: u64,
    
    /// PID file location
    pub pid_file: Option<PathBuf>,
    
    /// Lock file location
    pub lock_file: Option<PathBuf>,
    
    /// Enable crash dumps
    pub enable_crash_dumps: bool,
    
    /// Crash dump directory
    pub crash_dump_dir: Option<PathBuf>,
}

/// Feature flags for experimental functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    /// Enable experimental P2P features
    pub experimental_p2p: bool,
    
    /// Enable advanced metrics
    pub advanced_metrics: bool,
    
    /// Enable state pruning
    pub state_pruning: bool,
    
    /// Enable transaction pool optimization
    pub tx_pool_optimization: bool,
    
    /// Enable parallel block processing
    pub parallel_processing: bool,
    
    /// Enable WebSocket API
    pub websocket_api: bool,
    
    /// Enable GraphQL API
    pub graphql_api: bool,
    
    /// Enable REST API
    pub rest_api: bool,
    
    /// Enable developer tools
    pub dev_tools: bool,
    
    /// Enable debug endpoints
    pub debug_endpoints: bool,
}

/// Performance optimization settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationConfig {
    /// Enable CPU optimizations
    pub enable_cpu_optimizations: bool,
    
    /// Enable memory optimizations
    pub enable_memory_optimizations: bool,
    
    /// Enable network optimizations
    pub enable_network_optimizations: bool,
    
    /// Enable database optimizations
    pub enable_db_optimizations: bool,
    
    /// Use async I/O where possible
    pub prefer_async_io: bool,
    
    /// Enable zero-copy optimizations
    pub enable_zero_copy: bool,
    
    /// Enable SIMD instructions
    pub enable_simd: bool,
    
    /// Target CPU architecture: "generic", "native", "specific"
    pub target_cpu: String,
    
    /// Optimization level: "none", "basic", "aggressive"
    pub optimization_level: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: None,
            node_name: "dinari-node".to_string(),
            environment: "mainnet".to_string(),
            data_dir: PathBuf::from("./data"),
            mode: NodeMode::default(),
            resources: ResourceConfig::default(),
            telemetry: TelemetryConfig::default(),
            identity: IdentityConfig::default(),
            lifecycle: LifecycleConfig::default(),
            features: FeatureFlags::default(),
            optimization: OptimizationConfig::default(),
        }
    }
}

impl Default for NodeMode {
    fn default() -> Self {
        NodeMode::Full {
            enable_validator: false,
            enable_rpc: true,
            enable_p2p: true,
        }
    }
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 2048, // 2GB default
            max_disk_mb: 0, // Unlimited
            max_cpu_percent: 80,
            worker_threads: 0, // Auto-detect
            enable_monitoring: true,
            check_interval_secs: 60,
            limit_action: "warn".to_string(),
            memory: MemoryConfig::default(),
            disk: DiskConfig::default(),
        }
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            block_cache_mb: 256,
            tx_cache_mb: 128,
            state_cache_mb: 512,
            enable_compaction: true,
            compaction_interval_secs: 3600, // 1 hour
            message_pool_mb: 64,
        }
    }
}

impl Default for DiskConfig {
    fn default() -> Self {
        Self {
            enable_cleanup: true,
            cleanup_interval_secs: 86400, // 24 hours
            log_retention_days: 7,
            temp_file_retention_hours: 24,
            enable_compression: true,
            compression_algorithm: "lz4".to_string(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: None,
            interval_secs: 300, // 5 minutes
            enable_metrics: true,
            metrics_format: "prometheus".to_string(),
            metrics_port: Some(9090),
            enable_health_checks: true,
            health_check_port: Some(8080),
            include_sensitive_data: false,
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            track_block_times: true,
            track_tx_times: true,
            track_network_latency: true,
            track_db_performance: true,
            retention_hours: 168, // 1 week
            export_data: false,
            alerts: AlertConfig::default(),
        }
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            block_time_threshold_secs: 30,
            memory_threshold_percent: 90,
            disk_threshold_percent: 85,
            min_peer_threshold: 3,
            webhook_url: None,
            cooldown_minutes: 15,
        }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            private_key_file: None,
            auto_generate_keys: true,
            key_derivation: "random".to_string(),
            deterministic_seed: None,
            enable_key_rotation: false,
            rotation_interval_days: 365,
            backup_old_keys: true,
        }
    }
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            startup_timeout_secs: 120,
            shutdown_timeout_secs: 30,
            enable_fast_startup: false,
            auto_restart: false,
            max_restart_attempts: 3,
            restart_cooldown_secs: 60,
            pid_file: None,
            lock_file: None,
            enable_crash_dumps: true,
            crash_dump_dir: None,
        }
    }
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            experimental_p2p: false,
            advanced_metrics: false,
            state_pruning: false,
            tx_pool_optimization: true,
            parallel_processing: false,
            websocket_api: false,
            graphql_api: false,
            rest_api: true,
            dev_tools: false,
            debug_endpoints: false,
        }
    }
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            enable_cpu_optimizations: true,
            enable_memory_optimizations: true,
            enable_network_optimizations: true,
            enable_db_optimizations: true,
            prefer_async_io: true,
            enable_zero_copy: false,
            enable_simd: false,
            target_cpu: "generic".to_string(),
            optimization_level: "basic".to_string(),
        }
    }
}

impl NodeConfig {
    /// Create configuration for testnet
    pub fn testnet() -> Self {
        let mut config = Self::default();
        config.environment = "testnet".to_string();
        config.node_name = "dinari-testnet-node".to_string();
        config.data_dir = PathBuf::from("./testnet-data");
        config.telemetry.interval_secs = 60; // More frequent telemetry
        config.features.debug_endpoints = true;
        config.features.dev_tools = true;
        config
    }
    
    /// Create configuration for development
    pub fn development() -> Self {
        let mut config = Self::default();
        config.environment = "devnet".to_string();
        config.node_name = "dinari-dev-node".to_string();
        config.data_dir = PathBuf::from("./dev-data");
        config.lifecycle.enable_fast_startup = true;
        config.features.debug_endpoints = true;
        config.features.dev_tools = true;
        config.features.experimental_p2p = true;
        config.telemetry.include_sensitive_data = true;
        config.optimization.optimization_level = "none".to_string();
        config
    }
    
    /// Create configuration for archive node
    pub fn archive() -> Self {
        let mut config = Self::default();
        config.mode = NodeMode::Archive {
            enable_validator: false,
            enable_rpc: true,
            enable_p2p: true,
            prune_older_than_days: None, // Keep everything
        };
        config.resources.max_memory_mb = 8192; // 8GB for archive
        config.resources.max_disk_mb = 0; // Unlimited disk
        config.features.state_pruning = false;
        config
    }
    
    /// Create configuration for light client
    pub fn light_client(trusted_peers: Vec<String>) -> Self {
        let mut config = Self::default();
        config.mode = NodeMode::Light {
            enable_rpc: true,
            trusted_peers,
        };
        config.resources.max_memory_mb = 512; // 512MB for light client
        config.features.state_pruning = true;
        config
    }
    
    /// Check if node is running as validator
    pub fn is_validator(&self) -> bool {
        match &self.mode {
            NodeMode::Full { enable_validator, .. } => *enable_validator,
            NodeMode::Archive { enable_validator, .. } => *enable_validator,
            _ => false,
        }
    }
    
    /// Check if P2P is enabled
    pub fn is_p2p_enabled(&self) -> bool {
        match &self.mode {
            NodeMode::Full { enable_p2p, .. } => *enable_p2p,
            NodeMode::Archive { enable_p2p, .. } => *enable_p2p,
            NodeMode::Bootstrap { .. } => true,
            _ => false,
        }
    }
    
    /// Check if RPC is enabled
    pub fn is_rpc_enabled(&self) -> bool {
        match &self.mode {
            NodeMode::Full { enable_rpc, .. } => *enable_rpc,
            NodeMode::Light { enable_rpc, .. } => *enable_rpc,
            NodeMode::Archive { enable_rpc, .. } => *enable_rpc,
            NodeMode::RpcOnly { .. } => true,
            _ => false,
        }
    }
    
    /// Get worker thread count (0 = auto-detect)
    pub fn worker_threads(&self) -> usize {
        if self.resources.worker_threads == 0 {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4)
        } else {
            self.resources.worker_threads
        }
    }
    
    /// Validate node configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate resource limits
        if self.resources.max_cpu_percent == 0 || self.resources.max_cpu_percent > 100 {
            return Err(anyhow::anyhow!("max_cpu_percent must be between 1 and 100"));
        }
        
        // Validate telemetry ports
        if let Some(port) = self.telemetry.metrics_port {
            if port == 0 {
                return Err(anyhow::anyhow!("metrics_port cannot be 0"));
            }
        }
        
        if let Some(port) = self.telemetry.health_check_port {
            if port == 0 {
                return Err(anyhow::anyhow!("health_check_port cannot be 0"));
            }
        }
        
        // Validate lifecycle settings
        if self.lifecycle.startup_timeout_secs == 0 {
            return Err(anyhow::anyhow!("startup_timeout_secs must be greater than 0"));
        }
        
        if self.lifecycle.shutdown_timeout_secs == 0 {
            return Err(anyhow::anyhow!("shutdown_timeout_secs must be greater than 0"));
        }
        
        // Validate optimization settings
        if !["none", "basic", "aggressive"].contains(&self.optimization.optimization_level.as_str()) {
            return Err(anyhow::anyhow!("optimization_level must be one of: none, basic, aggressive"));
        }
        
        if !["generic", "native", "specific"].contains(&self.optimization.target_cpu.as_str()) {
            return Err(anyhow::anyhow!("target_cpu must be one of: generic, native, specific"));
        }
        
        // Validate mode-specific settings
        match &self.mode {
            NodeMode::Light { trusted_peers, .. } => {
                if trusted_peers.is_empty() {
                    return Err(anyhow::anyhow!("Light client mode requires at least one trusted peer"));
                }
            }
            NodeMode::RpcOnly { upstream_nodes, .. } => {
                if upstream_nodes.is_empty() {
                    return Err(anyhow::anyhow!("RPC-only mode requires at least one upstream node"));
                }
            }
            _ => {}
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_node_config() {
        let config = NodeConfig::default();
        assert!(config.validate().is_ok());
        assert!(!config.is_validator());
        assert!(config.is_rpc_enabled());
        assert!(config.is_p2p_enabled());
    }
    
    #[test]
    fn test_testnet_config() {
        let config = NodeConfig::testnet();
        assert!(config.validate().is_ok());
        assert_eq!(config.environment, "testnet");
        assert!(config.features.debug_endpoints);
    }
    
    #[test]
    fn test_light_client_config() {
        let peers = vec!["peer1".to_string(), "peer2".to_string()];
        let config = NodeConfig::light_client(peers);
        assert!(config.validate().is_ok());
        assert!(config.is_rpc_enabled());
        assert!(!config.is_p2p_enabled());
    }
    
    #[test]
    fn test_worker_threads() {
        let mut config = NodeConfig::default();
        
        // Auto-detect should return available parallelism
        config.resources.worker_threads = 0;
        assert!(config.worker_threads() >= 1);
        
        // Manual setting should be returned
        config.resources.worker_threads = 8;
        assert_eq!(config.worker_threads(), 8);
    }
}