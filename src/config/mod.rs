// src/config/mod.rs
use std::path::PathBuf;
use std::fs;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

pub mod network;
pub mod consensus;
pub mod node;
pub mod rpc;

pub use network::NetworkConfig;
pub use consensus::ConsensusConfig;
pub use node::NodeConfig;
pub use rpc::RpcConfig;

/// Main configuration structure combining all subsystem configs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DinariConfig {
    /// Node-specific configuration
    pub node: NodeConfig,
    
    /// Network and P2P configuration
    pub network: NetworkConfig,
    
    /// Consensus algorithm configuration
    pub consensus: ConsensusConfig,
    
    /// RPC server configuration
    pub rpc: RpcConfig,
    
    /// Database configuration
    pub database: DatabaseConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
    
    /// Security configuration
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Path to the database directory
    pub path: PathBuf,
    
    /// Maximum database size in MB
    pub max_size_mb: u64,
    
    /// Enable database compression
    pub compression: bool,
    
    /// Cache size in MB
    pub cache_size_mb: u64,
    
    /// Write buffer size in MB
    pub write_buffer_mb: u64,
    
    /// Maximum number of open files
    pub max_open_files: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: error, warn, info, debug, trace
    pub level: String,
    
    /// Enable structured JSON logging
    pub json_format: bool,
    
    /// Log file path (None for stdout only)
    pub file_path: Option<PathBuf>,
    
    /// Maximum log file size in MB before rotation
    pub max_file_size_mb: u64,
    
    /// Number of rotated log files to keep
    pub max_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    
    /// Maximum requests per minute per IP
    pub max_requests_per_minute: u32,
    
    /// Enable CORS
    pub enable_cors: bool,
    
    /// Allowed CORS origins
    pub cors_origins: Vec<String>,
    
    /// Enable request authentication
    pub enable_auth: bool,
    
    /// API key for authenticated requests
    pub api_key: Option<String>,
    
    /// Maximum request size in bytes
    pub max_request_size: usize,
}

impl Default for DinariConfig {
    fn default() -> Self {
        Self {
            node: NodeConfig::default(),
            network: NetworkConfig::default(),
            consensus: ConsensusConfig::default(),
            rpc: RpcConfig::default(),
            database: DatabaseConfig::default(),
            logging: LoggingConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./data/dinari_chain.db"),
            max_size_mb: 1024, // 1GB
            compression: true,
            cache_size_mb: 128,
            write_buffer_mb: 64,
            max_open_files: 1000,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json_format: false,
            file_path: None,
            max_file_size_mb: 100,
            max_files: 5,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_rate_limiting: true,
            max_requests_per_minute: 100,
            enable_cors: true,
            cors_origins: vec!["*".to_string()],
            enable_auth: false,
            api_key: None,
            max_request_size: 1024 * 1024, // 1MB
        }
    }
}

impl DinariConfig {
    /// Load configuration from TOML file
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| anyhow!("Failed to read config file {}: {}", path.as_ref().display(), e))?;
        
        let config: DinariConfig = toml::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse config file: {}", e))?;
        
        config.validate()?;
        Ok(config)
    }
    
    /// Save configuration to TOML file
    pub fn to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        self.validate()?;
        
        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize config: {}", e))?;
        
        // Create directory if it doesn't exist
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)
                .map_err(|e| anyhow!("Failed to create config directory: {}", e))?;
        }
        
        fs::write(path.as_ref(), content)
            .map_err(|e| anyhow!("Failed to write config file {}: {}", path.as_ref().display(), e))?;
        
        Ok(())
    }
    
    /// Load configuration from environment variables and CLI args
    pub fn from_env() -> Self {
        let mut config = DinariConfig::default();
        
        // Override with environment variables
        if let Ok(db_path) = std::env::var("DINARI_DB_PATH") {
            config.database.path = PathBuf::from(db_path);
        }
        
        if let Ok(rpc_port) = std::env::var("DINARI_RPC_PORT") {
            if let Ok(port) = rpc_port.parse() {
                config.rpc.port = port;
            }
        }
        
        if let Ok(log_level) = std::env::var("DINARI_LOG_LEVEL") {
            config.logging.level = log_level;
        }
        
        if let Ok(max_peers) = std::env::var("DINARI_MAX_PEERS") {
            if let Ok(peers) = max_peers.parse() {
                config.network.max_peers = peers;
            }
        }
        
        if let Ok(enable_cors) = std::env::var("DINARI_ENABLE_CORS") {
            config.security.enable_cors = enable_cors.to_lowercase() == "true";
        }
        
        config
    }
    
    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        // Validate database configuration
        if self.database.max_size_mb == 0 {
            return Err(anyhow!("Database max_size_mb must be greater than 0"));
        }
        
        if self.database.cache_size_mb > self.database.max_size_mb {
            return Err(anyhow!("Database cache_size_mb cannot exceed max_size_mb"));
        }
        
        // Validate RPC configuration
        if self.rpc.port == 0 || self.rpc.port > 65535 {
            return Err(anyhow!("RPC port must be between 1 and 65535"));
        }
        
        // Validate network configuration
        if self.network.max_peers == 0 {
            return Err(anyhow!("Network max_peers must be greater than 0"));
        }
        
        if self.network.listen_port == 0 || self.network.listen_port > 65535 {
            return Err(anyhow!("Network listen_port must be between 1 and 65535"));
        }
        
        // Validate logging configuration
        let valid_levels = ["error", "warn", "info", "debug", "trace"];
        if !valid_levels.contains(&self.logging.level.as_str()) {
            return Err(anyhow!("Invalid log level: {}. Must be one of: {:?}", 
                              self.logging.level, valid_levels));
        }
        
        // Validate consensus configuration
        if self.consensus.block_time_seconds == 0 {
            return Err(anyhow!("Consensus block_time_seconds must be greater than 0"));
        }
        
        if self.consensus.max_transactions_per_block == 0 {
            return Err(anyhow!("Consensus max_transactions_per_block must be greater than 0"));
        }
        
        // Validate security configuration
        if self.security.max_requests_per_minute == 0 {
            return Err(anyhow!("Security max_requests_per_minute must be greater than 0"));
        }
        
        if self.security.max_request_size == 0 {
            return Err(anyhow!("Security max_request_size must be greater than 0"));
        }
        
        Ok(())
    }
    
    /// Generate default configuration file
    pub fn generate_default_config<P: AsRef<std::path::Path>>(path: P) -> Result<()> {
        let config = DinariConfig::default();
        config.to_file(path)?;
        println!("Generated default configuration file");
        Ok(())
    }
    
    /// Get data directory path
    pub fn data_dir(&self) -> &PathBuf {
        &self.database.path
    }
    
    /// Get log level as filter
    pub fn log_level_filter(&self) -> log::LevelFilter {
        match self.logging.level.to_lowercase().as_str() {
            "error" => log::LevelFilter::Error,
            "warn" => log::LevelFilter::Warn,
            "info" => log::LevelFilter::Info,
            "debug" => log::LevelFilter::Debug,
            "trace" => log::LevelFilter::Trace,
            _ => log::LevelFilter::Info,
        }
    }
    
    /// Check if running in development mode
    pub fn is_development(&self) -> bool {
        self.logging.level == "debug" || self.logging.level == "trace"
    }
    
    /// Check if running in production mode
    pub fn is_production(&self) -> bool {
        !self.is_development() && self.security.enable_rate_limiting
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_default_config() {
        let config = DinariConfig::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_config_serialization() {
        let config = DinariConfig::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: DinariConfig = toml::from_str(&serialized).unwrap();
        assert!(deserialized.validate().is_ok());
    }
    
    #[test]
    fn test_config_file_operations() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");
        
        let original_config = DinariConfig::default();
        original_config.to_file(&config_path).unwrap();
        
        let loaded_config = DinariConfig::from_file(&config_path).unwrap();
        assert_eq!(original_config.rpc.port, loaded_config.rpc.port);
        assert_eq!(original_config.network.max_peers, loaded_config.network.max_peers);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = DinariConfig::default();
        
        // Valid config should pass
        assert!(config.validate().is_ok());
        
        // Invalid port should fail
        config.rpc.port = 0;
        assert!(config.validate().is_err());
        
        // Invalid log level should fail
        config.rpc.port = 3030;
        config.logging.level = "invalid".to_string();
        assert!(config.validate().is_err());
    }
}