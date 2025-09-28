// src/config/network.rs
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use serde::{Deserialize, Serialize};

/// Network and P2P configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable P2P networking
    pub enabled: bool,
    
    /// Local node listening address
    pub listen_address: IpAddr,
    
    /// Local node listening port
    pub listen_port: u16,
    
    /// External address for NAT traversal (if different from listen_address)
    pub external_address: Option<IpAddr>,
    
    /// External port for NAT traversal (if different from listen_port)
    pub external_port: Option<u16>,
    
    /// Maximum number of peer connections
    pub max_peers: usize,
    
    /// Maximum number of inbound connections
    pub max_inbound_peers: usize,
    
    /// Maximum number of outbound connections
    pub max_outbound_peers: usize,
    
    /// List of bootstrap nodes to connect to initially
    pub bootstrap_nodes: Vec<String>,
    
    /// List of DNS seeds for peer discovery
    pub dns_seeds: Vec<String>,
    
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    
    /// Handshake timeout in seconds
    pub handshake_timeout_secs: u64,
    
    /// Ping interval in seconds
    pub ping_interval_secs: u64,
    
    /// Peer discovery interval in seconds
    pub discovery_interval_secs: u64,
    
    /// Block sync interval in seconds
    pub sync_interval_secs: u64,
    
    /// Transaction broadcast interval in seconds
    pub broadcast_interval_secs: u64,
    
    /// Maximum message size in bytes
    pub max_message_size: usize,
    
    /// Network protocol version
    pub protocol_version: u32,
    
    /// Chain ID for network isolation
    pub chain_id: String,
    
    /// Network magic bytes (4 bytes for message framing)
    pub network_magic: [u8; 4],
    
    /// Enable message compression
    pub enable_compression: bool,
    
    /// Compression threshold in bytes
    pub compression_threshold: usize,
    
    /// Peer reputation system
    pub reputation: ReputationConfig,
    
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
    
    /// Node discovery configuration
    pub discovery: DiscoveryConfig,
}

/// Peer reputation system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    /// Enable reputation tracking
    pub enabled: bool,
    
    /// Initial reputation score for new peers
    pub initial_score: i32,
    
    /// Minimum reputation score before disconnection
    pub min_score: i32,
    
    /// Maximum reputation score
    pub max_score: i32,
    
    /// Reputation decay interval in seconds
    pub decay_interval_secs: u64,
    
    /// Reputation decay amount per interval
    pub decay_amount: i32,
    
    /// Reputation bonus for valid blocks
    pub valid_block_bonus: i32,
    
    /// Reputation bonus for valid transactions
    pub valid_transaction_bonus: i32,
    
    /// Reputation penalty for invalid data
    pub invalid_data_penalty: i32,
    
    /// Reputation penalty for connection drops
    pub connection_drop_penalty: i32,
}

/// Rate limiting configuration for network messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    
    /// Maximum messages per peer per second
    pub max_messages_per_sec: u32,
    
    /// Maximum blocks per peer per second
    pub max_blocks_per_sec: u32,
    
    /// Maximum transactions per peer per second
    pub max_transactions_per_sec: u32,
    
    /// Rate limit window in seconds
    pub window_secs: u64,
    
    /// Action when rate limit exceeded: "warn", "disconnect", "ban"
    pub action: String,
    
    /// Ban duration in seconds (if action is "ban")
    pub ban_duration_secs: u64,
}

/// Node discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable peer discovery
    pub enabled: bool,
    
    /// Enable DNS discovery
    pub enable_dns: bool,
    
    /// Enable DHT-based discovery
    pub enable_dht: bool,
    
    /// Enable local network discovery (LAN)
    pub enable_lan: bool,
    
    /// Minimum peers to maintain
    pub min_peers: usize,
    
    /// Target number of peers
    pub target_peers: usize,
    
    /// Discovery query interval in seconds
    pub query_interval_secs: u64,
    
    /// Maximum hops for peer gossip
    pub max_gossip_hops: u32,
    
    /// Peer advertisement interval in seconds
    pub advertise_interval_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), // Listen on all interfaces
            listen_port: 30303,
            external_address: None,
            external_port: None,
            max_peers: 50,
            max_inbound_peers: 25,
            max_outbound_peers: 25,
            bootstrap_nodes: vec![
                // Add default bootstrap nodes for mainnet
                "DT1111111111111111111111111111111111111111@seed1.dinarichain.org:30303".to_string(),
                "DT2222222222222222222222222222222222222222@seed2.dinarichain.org:30303".to_string(),
            ],
            dns_seeds: vec![
                "dnsseed.dinarichain.org".to_string(),
                "seed.dinarichain.org".to_string(),
            ],
            connection_timeout_secs: 30,
            handshake_timeout_secs: 10,
            ping_interval_secs: 30,
            discovery_interval_secs: 60,
            sync_interval_secs: 10,
            broadcast_interval_secs: 5,
            max_message_size: 10 * 1024 * 1024, // 10MB
            protocol_version: 1,
            chain_id: "dinari-mainnet".to_string(),
            network_magic: [0xD1, 0xNA, 0xR1, 0x01], // "DNAR" + version
            enable_compression: true,
            compression_threshold: 1024, // 1KB
            reputation: ReputationConfig::default(),
            rate_limiting: RateLimitConfig::default(),
            discovery: DiscoveryConfig::default(),
        }
    }
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_score: 50,
            min_score: -100,
            max_score: 100,
            decay_interval_secs: 3600, // 1 hour
            decay_amount: 1,
            valid_block_bonus: 10,
            valid_transaction_bonus: 1,
            invalid_data_penalty: -20,
            connection_drop_penalty: -5,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_messages_per_sec: 100,
            max_blocks_per_sec: 5,
            max_transactions_per_sec: 50,
            window_secs: 60,
            action: "warn".to_string(),
            ban_duration_secs: 3600, // 1 hour
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_dns: true,
            enable_dht: false, // DHT can be enabled later for full decentralization
            enable_lan: true,
            min_peers: 3,
            target_peers: 10,
            query_interval_secs: 300, // 5 minutes
            max_gossip_hops: 3,
            advertise_interval_secs: 600, // 10 minutes
        }
    }
}

impl NetworkConfig {
    /// Get the socket address to bind to
    pub fn bind_address(&self) -> SocketAddr {
        SocketAddr::new(self.listen_address, self.listen_port)
    }
    
    /// Get the external address for advertising to peers
    pub fn external_address(&self) -> SocketAddr {
        let addr = self.external_address.unwrap_or(self.listen_address);
        let port = self.external_port.unwrap_or(self.listen_port);
        SocketAddr::new(addr, port)
    }
    
    /// Get connection timeout as Duration
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.connection_timeout_secs)
    }
    
    /// Get handshake timeout as Duration
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_secs)
    }
    
    /// Get ping interval as Duration
    pub fn ping_interval(&self) -> Duration {
        Duration::from_secs(self.ping_interval_secs)
    }
    
    /// Get discovery interval as Duration
    pub fn discovery_interval(&self) -> Duration {
        Duration::from_secs(self.discovery_interval_secs)
    }
    
    /// Get sync interval as Duration
    pub fn sync_interval(&self) -> Duration {
        Duration::from_secs(self.sync_interval_secs)
    }
    
    /// Get broadcast interval as Duration
    pub fn broadcast_interval(&self) -> Duration {
        Duration::from_secs(self.broadcast_interval_secs)
    }
    
    /// Parse bootstrap node string into (node_id, address)
    pub fn parse_bootstrap_nodes(&self) -> Vec<(String, SocketAddr)> {
        let mut nodes = Vec::new();
        
        for node_str in &self.bootstrap_nodes {
            if let Some((node_id, addr_str)) = node_str.split_once('@') {
                if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                    nodes.push((node_id.to_string(), addr));
                } else {
                    log::warn!("Invalid bootstrap node address: {}", addr_str);
                }
            } else {
                log::warn!("Invalid bootstrap node format: {}", node_str);
            }
        }
        
        nodes
    }
    
    /// Check if this is a mainnet configuration
    pub fn is_mainnet(&self) -> bool {
        self.chain_id == "dinari-mainnet"
    }
    
    /// Check if this is a testnet configuration
    pub fn is_testnet(&self) -> bool {
        self.chain_id.contains("testnet")
    }
    
    /// Get configuration for testnet
    pub fn testnet() -> Self {
        let mut config = Self::default();
        config.chain_id = "dinari-testnet".to_string();
        config.listen_port = 30304; // Different port for testnet
        config.network_magic = [0xD1, 0xNA, 0xR1, 0xT1]; // "DNAR" + testnet
        config.bootstrap_nodes = vec![
            "DT1111111111111111111111111111111111111111@testnet-seed1.dinarichain.org:30304".to_string(),
            "DT2222222222222222222222222222222222222222@testnet-seed2.dinarichain.org:30304".to_string(),
        ];
        config.dns_seeds = vec![
            "testnet-dnsseed.dinarichain.org".to_string(),
        ];
        config
    }
    
    /// Get configuration for local development
    pub fn local() -> Self {
        let mut config = Self::default();
        config.chain_id = "dinari-local".to_string();
        config.listen_port = 30305;
        config.network_magic = [0xD1, 0xNA, 0xR1, 0x99]; // "DNAR" + local
        config.bootstrap_nodes = vec![];
        config.dns_seeds = vec![];
        config.discovery.enabled = false; // No discovery for local
        config.max_peers = 5; // Fewer peers for local testing
        config
    }
    
    /// Validate network configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_peers == 0 {
            return Err(anyhow::anyhow!("max_peers must be greater than 0"));
        }
        
        if self.max_inbound_peers + self.max_outbound_peers > self.max_peers {
            return Err(anyhow::anyhow!("sum of max_inbound_peers and max_outbound_peers cannot exceed max_peers"));
        }
        
        if self.connection_timeout_secs == 0 {
            return Err(anyhow::anyhow!("connection_timeout_secs must be greater than 0"));
        }
        
        if self.max_message_size == 0 {
            return Err(anyhow::anyhow!("max_message_size must be greater than 0"));
        }
        
        if self.max_message_size > 100 * 1024 * 1024 { // 100MB limit
            return Err(anyhow::anyhow!("max_message_size cannot exceed 100MB"));
        }
        
        // Validate rate limiting
        if self.rate_limiting.enabled {
            if self.rate_limiting.max_messages_per_sec == 0 {
                return Err(anyhow::anyhow!("rate_limiting.max_messages_per_sec must be greater than 0"));
            }
            
            if !["warn", "disconnect", "ban"].contains(&self.rate_limiting.action.as_str()) {
                return Err(anyhow::anyhow!("rate_limiting.action must be one of: warn, disconnect, ban"));
            }
        }
        
        // Validate reputation system
        if self.reputation.enabled {
            if self.reputation.min_score >= self.reputation.max_score {
                return Err(anyhow::anyhow!("reputation.min_score must be less than reputation.max_score"));
            }
        }
        
        // Validate discovery settings
        if self.discovery.enabled {
            if self.discovery.min_peers > self.discovery.target_peers {
                return Err(anyhow::anyhow!("discovery.min_peers cannot exceed discovery.target_peers"));
            }
            
            if self.discovery.target_peers > self.max_peers {
                return Err(anyhow::anyhow!("discovery.target_peers cannot exceed max_peers"));
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_network_config() {
        let config = NetworkConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.is_mainnet());
        assert!(!config.is_testnet());
    }
    
    #[test]
    fn test_testnet_config() {
        let config = NetworkConfig::testnet();
        assert!(config.validate().is_ok());
        assert!(!config.is_mainnet());
        assert!(config.is_testnet());
        assert_eq!(config.listen_port, 30304);
    }
    
    #[test]
    fn test_local_config() {
        let config = NetworkConfig::local();
        assert!(config.validate().is_ok());
        assert!(!config.discovery.enabled);
        assert_eq!(config.max_peers, 5);
    }
    
    #[test]
    fn test_bootstrap_node_parsing() {
        let config = NetworkConfig::default();
        let nodes = config.parse_bootstrap_nodes();
        assert!(nodes.len() >= 1);
        
        // Test valid parsing
        let (node_id, addr) = &nodes[0];
        assert!(node_id.starts_with("DT"));
        assert!(addr.port() > 0);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = NetworkConfig::default();
        
        // Valid config should pass
        assert!(config.validate().is_ok());
        
        // Invalid max_peers
        config.max_peers = 0;
        assert!(config.validate().is_err());
        
        // Invalid peer distribution
        config.max_peers = 10;
        config.max_inbound_peers = 8;
        config.max_outbound_peers = 8; // 8 + 8 > 10
        assert!(config.validate().is_err());
    }
}