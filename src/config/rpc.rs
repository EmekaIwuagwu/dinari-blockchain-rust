// src/config/rpc.rs
use std::net::IpAddr;
use std::path::PathBuf;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// RPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Enable RPC server
    pub enabled: bool,
    
    /// RPC server bind address
    pub host: IpAddr,
    
    /// RPC server port
    pub port: u16,
    
    /// Maximum concurrent connections
    pub max_connections: usize,
    
    /// Maximum request size in bytes
    pub max_request_size: usize,
    
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    
    /// Enable request logging
    pub log_requests: bool,
    
    /// Enable response compression
    pub enable_compression: bool,
    
    /// CORS configuration
    pub cors: CorsConfig,
    
    /// Authentication and authorization
    pub auth: AuthConfig,
    
    /// Rate limiting configuration
    pub rate_limiting: RpcRateLimitConfig,
    
    /// API endpoint configuration
    pub endpoints: EndpointConfig,
    
    /// WebSocket configuration
    pub websocket: WebSocketConfig,
    
    /// TLS/SSL configuration
    pub tls: TlsConfig,
    
    /// Performance and caching
    pub performance: RpcPerformanceConfig,
    
    /// Subscription configuration
    pub subscriptions: SubscriptionConfig,
}

/// CORS (Cross-Origin Resource Sharing) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Enable CORS
    pub enabled: bool,
    
    /// Allowed origins (* for all)
    pub allowed_origins: Vec<String>,
    
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    
    /// Exposed headers
    pub exposed_headers: Vec<String>,
    
    /// Allow credentials
    pub allow_credentials: bool,
    
    /// Max age for preflight requests (seconds)
    pub max_age_secs: u64,
}

/// Authentication and authorization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Enable authentication
    pub enabled: bool,
    
    /// Authentication method: "api_key", "bearer", "basic", "none"
    pub method: String,
    
    /// API keys for access (key -> permissions)
    pub api_keys: HashMap<String, Vec<String>>,
    
    /// JWT configuration (for bearer tokens)
    pub jwt: JwtConfig,
    
    /// Basic auth credentials (username -> password_hash)
    pub basic_auth: HashMap<String, String>,
    
    /// Admin authentication (full access)
    pub admin: AdminAuthConfig,
    
    /// IP whitelist/blacklist
    pub ip_filtering: IpFilterConfig,
    
    /// Session management
    pub sessions: SessionConfig,
}

/// JWT (JSON Web Token) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT secret key
    pub secret: String,
    
    /// Token expiration time in seconds
    pub expiration_secs: u64,
    
    /// JWT algorithm: "HS256", "HS384", "HS512"
    pub algorithm: String,
    
    /// Token issuer
    pub issuer: String,
    
    /// Token audience
    pub audience: String,
    
    /// Enable token refresh
    pub enable_refresh: bool,
    
    /// Refresh token expiration in seconds
    pub refresh_expiration_secs: u64,
}

/// Admin authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuthConfig {
    /// Enable admin endpoints
    pub enabled: bool,
    
    /// Admin API key
    pub api_key: Option<String>,
    
    /// Admin password hash
    pub password_hash: Option<String>,
    
    /// Admin endpoints prefix
    pub endpoints_prefix: String,
    
    /// Require HTTPS for admin access
    pub require_https: bool,
    
    /// Admin session timeout in seconds
    pub session_timeout_secs: u64,
}

/// IP filtering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFilterConfig {
    /// Enable IP filtering
    pub enabled: bool,
    
    /// Whitelist mode (true = allow only whitelisted, false = deny blacklisted)
    pub whitelist_mode: bool,
    
    /// Allowed IP addresses/ranges
    pub allowed_ips: Vec<String>,
    
    /// Blocked IP addresses/ranges
    pub blocked_ips: Vec<String>,
    
    /// Block private IP ranges
    pub block_private_ips: bool,
    
    /// Block tor exit nodes
    pub block_tor_nodes: bool,
}

/// Session management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Enable sessions
    pub enabled: bool,
    
    /// Session storage: "memory", "redis", "database"
    pub storage: String,
    
    /// Session timeout in seconds
    pub timeout_secs: u64,
    
    /// Session cleanup interval in seconds
    pub cleanup_interval_secs: u64,
    
    /// Maximum sessions per IP
    pub max_sessions_per_ip: usize,
    
    /// Session cookie configuration
    pub cookie: CookieConfig,
}

/// Session cookie configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieConfig {
    /// Cookie name
    pub name: String,
    
    /// Cookie domain
    pub domain: Option<String>,
    
    /// Cookie path
    pub path: String,
    
    /// Cookie secure flag
    pub secure: bool,
    
    /// Cookie HttpOnly flag
    pub http_only: bool,
    
    /// Cookie SameSite policy: "strict", "lax", "none"
    pub same_site: String,
}

/// RPC rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    
    /// Global rate limit (requests per minute)
    pub global_limit: u32,
    
    /// Per-IP rate limit (requests per minute)
    pub per_ip_limit: u32,
    
    /// Per-API-key rate limit (requests per minute)
    pub per_key_limit: u32,
    
    /// Rate limit window in seconds
    pub window_secs: u64,
    
    /// Burst allowance
    pub burst_size: u32,
    
    /// Rate limit storage: "memory", "redis"
    pub storage: String,
    
    /// Method-specific limits
    pub method_limits: HashMap<String, u32>,
    
    /// Whitelist for rate limiting
    pub whitelist: Vec<String>,
}

/// API endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// Enable JSON-RPC 2.0
    pub jsonrpc: bool,
    
    /// Enable REST API
    pub rest: bool,
    
    /// Enable GraphQL API
    pub graphql: bool,
    
    /// Enable WebSocket API
    pub websocket: bool,
    
    /// API version
    pub version: String,
    
    /// Base path for all APIs
    pub base_path: String,
    
    /// Enabled methods (empty = all enabled)
    pub enabled_methods: Vec<String>,
    
    /// Disabled methods
    pub disabled_methods: Vec<String>,
    
    /// Method aliases
    pub method_aliases: HashMap<String, String>,
    
    /// Custom endpoints
    pub custom_endpoints: CustomEndpointConfig,
}

/// Custom endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomEndpointConfig {
    /// Enable health check endpoint
    pub health: bool,
    
    /// Enable metrics endpoint
    pub metrics: bool,
    
    /// Enable version endpoint
    pub version: bool,
    
    /// Enable status endpoint
    pub status: bool,
    
    /// Enable debug endpoints
    pub debug: bool,
    
    /// Health check path
    pub health_path: String,
    
    /// Metrics path
    pub metrics_path: String,
    
    /// Version path
    pub version_path: String,
    
    /// Status path
    pub status_path: String,
    
    /// Debug path prefix
    pub debug_path_prefix: String,
}

/// WebSocket configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    /// Enable WebSocket support
    pub enabled: bool,
    
    /// WebSocket path
    pub path: String,
    
    /// Maximum WebSocket connections
    pub max_connections: usize,
    
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    
    /// Ping interval in seconds
    pub ping_interval_secs: u64,
    
    /// Pong timeout in seconds
    pub pong_timeout_secs: u64,
    
    /// Maximum message size in bytes
    pub max_message_size: usize,
    
    /// Enable compression
    pub enable_compression: bool,
    
    /// Subscription configuration
    pub subscriptions: WsSubscriptionConfig,
}

/// WebSocket subscription configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsSubscriptionConfig {
    /// Enable subscriptions
    pub enabled: bool,
    
    /// Maximum subscriptions per connection
    pub max_per_connection: usize,
    
    /// Subscription timeout in seconds
    pub timeout_secs: u64,
    
    /// Buffer size for subscription events
    pub buffer_size: usize,
    
    /// Enable subscription filtering
    pub enable_filtering: bool,
}

/// TLS/SSL configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS
    pub enabled: bool,
    
    /// Certificate file path
    pub cert_file: Option<PathBuf>,
    
    /// Private key file path
    pub key_file: Option<PathBuf>,
    
    /// Certificate chain file path
    pub chain_file: Option<PathBuf>,
    
    /// TLS version: "1.2", "1.3", "auto"
    pub version: String,
    
    /// Cipher suites
    pub cipher_suites: Vec<String>,
    
    /// Enable OCSP stapling
    pub enable_ocsp_stapling: bool,
    
    /// Client certificate verification
    pub client_verification: ClientVerificationConfig,
}

/// Client certificate verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientVerificationConfig {
    /// Enable client certificate verification
    pub enabled: bool,
    
    /// Client CA certificate file
    pub ca_file: Option<PathBuf>,
    
    /// Verification mode: "none", "optional", "required"
    pub mode: String,
    
    /// Certificate revocation list file
    pub crl_file: Option<PathBuf>,
}

/// RPC performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcPerformanceConfig {
    /// Enable request caching
    pub enable_caching: bool,
    
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
    
    /// Maximum cache size in MB
    pub cache_size_mb: u64,
    
    /// Enable request batching
    pub enable_batching: bool,
    
    /// Maximum batch size
    pub max_batch_size: usize,
    
    /// Batch timeout in milliseconds
    pub batch_timeout_ms: u64,
    
    /// Enable connection pooling
    pub enable_connection_pooling: bool,
    
    /// Connection pool size
    pub connection_pool_size: usize,
    
    /// Connection keep-alive timeout in seconds
    pub keep_alive_timeout_secs: u64,
    
    /// Enable response streaming
    pub enable_streaming: bool,
    
    /// Stream buffer size
    pub stream_buffer_size: usize,
}

/// Subscription configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    /// Enable event subscriptions
    pub enabled: bool,
    
    /// Maximum subscriptions per client
    pub max_per_client: usize,
    
    /// Subscription timeout in seconds
    pub timeout_secs: u64,
    
    /// Event buffer size
    pub event_buffer_size: usize,
    
    /// Enable subscription persistence
    pub enable_persistence: bool,
    
    /// Persistence storage: "memory", "redis", "database"
    pub persistence_storage: String,
    
    /// Supported subscription types
    pub supported_types: Vec<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: "127.0.0.1".parse().unwrap(),
            port: 3030,
            max_connections: 1000,
            max_request_size: 1024 * 1024, // 1MB
            request_timeout_secs: 30,
            log_requests: true,
            enable_compression: true,
            cors: CorsConfig::default(),
            auth: AuthConfig::default(),
            rate_limiting: RpcRateLimitConfig::default(),
            endpoints: EndpointConfig::default(),
            websocket: WebSocketConfig::default(),
            tls: TlsConfig::default(),
            performance: RpcPerformanceConfig::default(),
            subscriptions: SubscriptionConfig::default(),
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
            ],
            exposed_headers: vec![],
            allow_credentials: false,
            max_age_secs: 3600,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            method: "none".to_string(),
            api_keys: HashMap::new(),
            jwt: JwtConfig::default(),
            basic_auth: HashMap::new(),
            admin: AdminAuthConfig::default(),
            ip_filtering: IpFilterConfig::default(),
            sessions: SessionConfig::default(),
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "change-this-secret-key".to_string(),
            expiration_secs: 3600, // 1 hour
            algorithm: "HS256".to_string(),
            issuer: "dinari-blockchain".to_string(),
            audience: "dinari-api".to_string(),
            enable_refresh: true,
            refresh_expiration_secs: 86400, // 24 hours
        }
    }
}

impl Default for AdminAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: None,
            password_hash: None,
            endpoints_prefix: "/admin".to_string(),
            require_https: true,
            session_timeout_secs: 1800, // 30 minutes
        }
    }
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            whitelist_mode: false,
            allowed_ips: vec![],
            blocked_ips: vec![],
            block_private_ips: false,
            block_tor_nodes: false,
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage: "memory".to_string(),
            timeout_secs: 3600, // 1 hour
            cleanup_interval_secs: 300, // 5 minutes
            max_sessions_per_ip: 10,
            cookie: CookieConfig::default(),
        }
    }
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "dinari_session".to_string(),
            domain: None,
            path: "/".to_string(),
            secure: true,
            http_only: true,
            same_site: "strict".to_string(),
        }
    }
}

impl Default for RpcRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global_limit: 1000, // 1000 requests per minute globally
            per_ip_limit: 100,  // 100 requests per minute per IP
            per_key_limit: 1000, // 1000 requests per minute per API key
            window_secs: 60,
            burst_size: 10,
            storage: "memory".to_string(),
            method_limits: HashMap::new(),
            whitelist: vec![],
        }
    }
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            jsonrpc: true,
            rest: false,
            graphql: false,
            websocket: false,
            version: "1.0".to_string(),
            base_path: "/".to_string(),
            enabled_methods: vec![], // Empty = all enabled
            disabled_methods: vec![],
            method_aliases: HashMap::new(),
            custom_endpoints: CustomEndpointConfig::default(),
        }
    }
}

impl Default for CustomEndpointConfig {
    fn default() -> Self {
        Self {
            health: true,
            metrics: false,
            version: true,
            status: true,
            debug: false,
            health_path: "/health".to_string(),
            metrics_path: "/metrics".to_string(),
            version_path: "/version".to_string(),
            status_path: "/status".to_string(),
            debug_path_prefix: "/debug".to_string(),
        }
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "/ws".to_string(),
            max_connections: 100,
            connection_timeout_secs: 60,
            ping_interval_secs: 30,
            pong_timeout_secs: 10,
            max_message_size: 1024 * 1024, // 1MB
            enable_compression: true,
            subscriptions: WsSubscriptionConfig::default(),
        }
    }
}

impl Default for WsSubscriptionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_per_connection: 100,
            timeout_secs: 300, // 5 minutes
            buffer_size: 1000,
            enable_filtering: true,
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: None,
            key_file: None,
            chain_file: None,
            version: "auto".to_string(),
            cipher_suites: vec![],
            enable_ocsp_stapling: false,
            client_verification: ClientVerificationConfig::default(),
        }
    }
}

impl Default for ClientVerificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ca_file: None,
            mode: "none".to_string(),
            crl_file: None,
        }
    }
}

impl Default for RpcPerformanceConfig {
    fn default() -> Self {
        Self {
            enable_caching: false,
            cache_ttl_secs: 300, // 5 minutes
            cache_size_mb: 100,
            enable_batching: true,
            max_batch_size: 100,
            batch_timeout_ms: 10,
            enable_connection_pooling: true,
            connection_pool_size: 100,
            keep_alive_timeout_secs: 60,
            enable_streaming: false,
            stream_buffer_size: 8192,
        }
    }
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_per_client: 50,
            timeout_secs: 300, // 5 minutes
            event_buffer_size: 1000,
            enable_persistence: false,
            persistence_storage: "memory".to_string(),
            supported_types: vec![
                "newHeads".to_string(),
                "newTransactions".to_string(),
                "logs".to_string(),
            ],
        }
    }
}

impl RpcConfig {
    /// Get bind address
    pub fn bind_address(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.host, self.port)
    }
    
    /// Check if method is enabled
    pub fn is_method_enabled(&self, method: &str) -> bool {
        // If disabled methods contains this method, it's disabled
        if self.endpoints.disabled_methods.contains(&method.to_string()) {
            return false;
        }
        
        // If enabled methods is empty, all methods are enabled by default
        if self.endpoints.enabled_methods.is_empty() {
            return true;
        }
        
        // Otherwise, check if method is in enabled list
        self.endpoints.enabled_methods.contains(&method.to_string())
    }
    
    /// Get method alias
    pub fn get_method_alias(&self, method: &str) -> String {
        self.endpoints.method_aliases
            .get(method)
            .cloned()
            .unwrap_or_else(|| method.to_string())
    }
    
    /// Check if authentication is required
    pub fn requires_auth(&self) -> bool {
        self.auth.enabled && self.auth.method != "none"
    }
    
    /// Get rate limit for method
    pub fn get_method_rate_limit(&self, method: &str) -> Option<u32> {
        self.rate_limiting.method_limits.get(method).copied()
    }
    
    /// Create production configuration
    pub fn production() -> Self {
        let mut config = Self::default();
        config.host = "0.0.0.0".parse().unwrap(); // Listen on all interfaces
        config.cors.allowed_origins = vec!["https://app.dinarichain.org".to_string()];
        config.auth.enabled = true;
        config.auth.method = "api_key".to_string();
        config.tls.enabled = true;
        config.endpoints.custom_endpoints.debug = false;
        config.log_requests = false; // Reduce logging in production
        config.rate_limiting.per_ip_limit = 60; // More restrictive
        config
    }
    
    /// Create development configuration
    pub fn development() -> Self {
        let mut config = Self::default();
        config.endpoints.custom_endpoints.debug = true;
        config.endpoints.custom_endpoints.metrics = true;
        config.websocket.enabled = true;
        config.subscriptions.enabled = true;
        config.auth.enabled = false; // No auth for development
        config.tls.enabled = false;
        config.rate_limiting.enabled = false; // No rate limiting for dev
        config
    }
    
    /// Validate RPC configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate port
        if self.port == 0 {
            return Err(anyhow::anyhow!("RPC port cannot be 0"));
        }
        
        // Validate request size
        if self.max_request_size == 0 {
            return Err(anyhow::anyhow!("max_request_size must be greater than 0"));
        }
        
        if self.max_request_size > 100 * 1024 * 1024 { // 100MB limit
            return Err(anyhow::anyhow!("max_request_size cannot exceed 100MB"));
        }
        
        // Validate timeouts
        if self.request_timeout_secs == 0 {
            return Err(anyhow::anyhow!("request_timeout_secs must be greater than 0"));
        }
        
        // Validate TLS configuration
        if self.tls.enabled {
            if self.tls.cert_file.is_none() {
                return Err(anyhow::anyhow!("TLS cert_file is required when TLS is enabled"));
            }
            
            if self.tls.key_file.is_none() {
                return Err(anyhow::anyhow!("TLS key_file is required when TLS is enabled"));
            }
            
            if !["1.2", "1.3", "auto"].contains(&self.tls.version.as_str()) {
                return Err(anyhow::anyhow!("TLS version must be one of: 1.2, 1.3, auto"));
            }
        }
        
        // Validate authentication
        if self.auth.enabled {
            if !["api_key", "bearer", "basic", "none"].contains(&self.auth.method.as_str()) {
                return Err(anyhow::anyhow!("auth.method must be one of: api_key, bearer, basic, none"));
            }
            
            if self.auth.method == "api_key" && self.auth.api_keys.is_empty() {
                return Err(anyhow::anyhow!("API keys must be configured when using api_key authentication"));
            }
            
            if self.auth.method == "bearer" && self.auth.jwt.secret == "change-this-secret-key" {
                return Err(anyhow::anyhow!("JWT secret must be changed from default value"));
            }
        }
        
        // Validate WebSocket configuration
        if self.websocket.enabled {
            if self.websocket.max_connections == 0 {
                return Err(anyhow::anyhow!("websocket.max_connections must be greater than 0"));
            }
            
            if self.websocket.max_message_size == 0 {
                return Err(anyhow::anyhow!("websocket.max_message_size must be greater than 0"));
            }
        }
        
        // Validate rate limiting
        if self.rate_limiting.enabled {
            if self.rate_limiting.window_secs == 0 {
                return Err(anyhow::anyhow!("rate_limiting.window_secs must be greater than 0"));
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_rpc_config() {
        let config = RpcConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.enabled);
        assert_eq!(config.port, 3030);
        assert!(!config.requires_auth());
    }
    
    #[test]
    fn test_production_config() {
        let config = RpcConfig::production();
        assert!(config.validate().is_err()); // Should fail without proper TLS setup
        assert!(config.requires_auth());
        assert!(config.tls.enabled);
    }
    
    #[test]
    fn test_development_config() {
        let config = RpcConfig::development();
        assert!(config.validate().is_ok());
        assert!(!config.requires_auth());
        assert!(config.endpoints.custom_endpoints.debug);
        assert!(config.websocket.enabled);
    }
    
    #[test]
    fn test_method_filtering() {
        let mut config = RpcConfig::default();
        
        // All methods enabled by default
        assert!(config.is_method_enabled("getBalance"));
        
        // Disable specific method
        config.endpoints.disabled_methods.push("sendTransaction".to_string());
        assert!(!config.is_method_enabled("sendTransaction"));
        assert!(config.is_method_enabled("getBalance"));
        
        // Enable only specific methods
        config.endpoints.enabled_methods = vec!["getBalance".to_string()];
        assert!(config.is_method_enabled("getBalance"));
        assert!(!config.is_method_enabled("getBlock"));
    }
    
    #[test]
    fn test_method_aliases() {
        let mut config = RpcConfig::default();
        config.endpoints.method_aliases.insert(
            "balance".to_string(),
            "getBalance".to_string(),
        );
        
        assert_eq!(config.get_method_alias("balance"), "getBalance");
        assert_eq!(config.get_method_alias("getBlock"), "getBlock");
    }
}