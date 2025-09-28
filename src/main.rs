// src/main.rs - WITH PEG SYSTEM INTEGRATION
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::signal;
use anyhow::{Result, anyhow};
use log::{info, error};

use dinari_blockchain::{
    database::BlockchainDB,
    consensus::PoAConsensus,
    rpc::{RpcServer, RpcConfig},
    crypto::Wallet,
    utils,
};

/// Node configuration
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub db_path: String,
    pub rpc_host: String,
    pub rpc_port: u16,
    pub validator_private_key: Option<String>,
    pub block_time_seconds: u64,
    pub enable_rpc: bool,
    pub log_level: String,
    pub is_validator: bool,
    pub enable_peg: bool, // NEW: Peg configuration
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            db_path: "./data/dinari_chain.db".to_string(),
            rpc_host: "127.0.0.1".to_string(),
            rpc_port: 3030,
            validator_private_key: None,
            block_time_seconds: 15,
            enable_rpc: true,
            log_level: "info".to_string(),
            is_validator: false,
            enable_peg: true, // NEW: Enable peg by default
        }
    }
}

impl NodeConfig {
    /// Load configuration from environment variables and command line args
    pub fn from_env_and_args() -> Self {
        let mut config = NodeConfig::default();
        
        // Load from environment variables
        if let Ok(db_path) = env::var("DINARI_DB_PATH") {
            config.db_path = db_path;
        }
        if let Ok(rpc_host) = env::var("DINARI_RPC_HOST") {
            config.rpc_host = rpc_host;
        }
        if let Ok(rpc_port) = env::var("DINARI_RPC_PORT") {
            if let Ok(port) = rpc_port.parse() {
                config.rpc_port = port;
            }
        }
        if let Ok(validator_key) = env::var("DINARI_VALIDATOR_KEY") {
            config.validator_private_key = Some(validator_key);
            config.is_validator = true;
        }
        if let Ok(block_time) = env::var("DINARI_BLOCK_TIME") {
            if let Ok(time) = block_time.parse() {
                config.block_time_seconds = time;
            }
        }
        if let Ok(enable_rpc) = env::var("DINARI_ENABLE_RPC") {
            config.enable_rpc = enable_rpc.to_lowercase() == "true";
        }
        if let Ok(log_level) = env::var("DINARI_LOG_LEVEL") {
            config.log_level = log_level;
        }
        // NEW: Peg configuration from environment
        if let Ok(enable_peg) = env::var("DINARI_ENABLE_PEG") {
            config.enable_peg = enable_peg.to_lowercase() == "true";
        }
        
        // Parse command line arguments
        let args: Vec<String> = env::args().collect();
        for (i, arg) in args.iter().enumerate() {
            match arg.as_str() {
                "--validator" => {
                    config.is_validator = true;
                }
                "--validator-key" => {
                    if let Some(key) = args.get(i + 1) {
                        config.validator_private_key = Some(key.clone());
                        config.is_validator = true;
                    }
                }
                "--db-path" => {
                    if let Some(path) = args.get(i + 1) {
                        config.db_path = path.clone();
                    }
                }
                "--rpc-port" => {
                    if let Some(port_str) = args.get(i + 1) {
                        if let Ok(port) = port_str.parse() {
                            config.rpc_port = port;
                        }
                    }
                }
                "--block-time" => {
                    if let Some(time_str) = args.get(i + 1) {
                        if let Ok(time) = time_str.parse() {
                            config.block_time_seconds = time;
                        }
                    }
                }
                "--log-level" => {
                    if let Some(level) = args.get(i + 1) {
                        config.log_level = level.clone();
                    }
                }
                "--no-rpc" => {
                    config.enable_rpc = false;
                }
                // NEW: Peg command line options
                "--no-peg" => {
                    config.enable_peg = false;
                }
                "--enable-peg" => {
                    config.enable_peg = true;
                }
                "--help" => {
                    Self::print_help();
                    std::process::exit(0);
                }
                _ => {}
            }
        }
        
        config
    }

    /// Print help message
    fn print_help() {
        println!("DinariBlockchain Node v0.1.0 - Algorithmic USD Peg");
        println!();
        println!("USAGE:");
        println!("    dinari_blockchain [OPTIONS]");
        println!();
        println!("OPTIONS:");
        println!("    --validator              Enable validator mode (generates new key)");
        println!("    --validator-key <KEY>    Use specific private key as validator");
        println!("    --db-path <PATH>         Database path (default: ./data/dinari_chain.db)");
        println!("    --rpc-port <PORT>        RPC server port (default: 3030)");
        println!("    --block-time <SECONDS>   Block time in seconds (default: 15)");
        println!("    --log-level <LEVEL>      Log level: error, warn, info, debug (default: info)");
        println!("    --no-rpc                 Disable RPC server");
        println!("    --no-peg                 Disable algorithmic USD peg");
        println!("    --enable-peg             Enable algorithmic USD peg (default)");
        println!("    --help                   Show this help message");
        println!();
        println!("FEATURES:");
        println!("    - Dual-token economy (DINARI & AFRICOIN)");
        println!("    - Algorithmic USD peg (1 USD = 1 token)");
        println!("    - Activity-based supply adjustment");
        println!("    - Treasury system for token distribution");
        println!("    - Proof of Authority consensus");
        println!();
        println!("ENVIRONMENT VARIABLES:");
        println!("    DINARI_DB_PATH           Database path");
        println!("    DINARI_RPC_HOST          RPC server host");
        println!("    DINARI_RPC_PORT          RPC server port");
        println!("    DINARI_VALIDATOR_KEY     Validator private key");
        println!("    DINARI_BLOCK_TIME        Block time in seconds");
        println!("    DINARI_ENABLE_RPC        Enable RPC server (true/false)");
        println!("    DINARI_ENABLE_PEG        Enable algorithmic peg (true/false)");
        println!("    DINARI_LOG_LEVEL         Log level");
    }

    /// Display configuration
    pub fn display(&self) {
        info!("📋 DinariBlockchain Node Configuration:");
        info!("   Database Path: {}", self.db_path);
        info!("   RPC Server: {}:{}", self.rpc_host, self.rpc_port);
        info!("   Block Time: {}s", self.block_time_seconds);
        info!("   RPC Enabled: {}", self.enable_rpc);
        info!("   Validator: {}", if self.is_validator { "Yes" } else { "No" });
        info!("   Log Level: {}", self.log_level);
        
        // NEW: Show peg system status
        info!("   USD Peg: {}", if self.enable_peg { "Enabled (Algorithmic)" } else { "Disabled" });
        if self.enable_peg {
            info!("   Peg Target: 1 USD = 1 DINARI/AFRICOIN");
            info!("   Peg Mechanism: Activity-based supply adjustment");
        }
    }
}

/// DinariBlockchain Node
pub struct DinariNode {
    config: NodeConfig,
    consensus: Arc<RwLock<PoAConsensus>>,
    rpc_server: Option<RpcServer>,
}

impl DinariNode {
    /// Create new DinariBlockchain node
    pub async fn new(config: NodeConfig) -> Result<Self> {
        info!("🔧 Initializing DinariBlockchain Node with USD Peg System...");
        
        // Initialize database ONCE
        info!("💾 Opening database: {}", config.db_path);
        let db = Arc::new(BlockchainDB::new(&config.db_path)?);
        
        // Initialize consensus engine with shared database
        let mut consensus = PoAConsensus::new(Arc::clone(&db));
        
        // Set as validator if enabled
        if config.is_validator {
            info!("🔒 Configuring node as validator...");
            
            let validator_wallet = if let Some(ref private_key_hex) = config.validator_private_key {
                Self::load_validator_wallet(private_key_hex)?
            } else {
                info!("🎲 Generating new validator wallet...");
                Wallet::new()
            };
            
            let validator_address = format!("{}", validator_wallet.address());
            
            consensus.set_validator(validator_wallet)?;
            info!("✅ Validator configured: {}", validator_address);
        }
        
        // NEW: Configure peg system
        if config.enable_peg {
            info!("💰 Initializing algorithmic USD peg system...");
            // Peg is enabled by default in consensus, but we could disable it here if needed
            consensus.set_peg_enabled(true).await?;
            info!("✅ USD peg system enabled (1 USD = 1 DINARI/AFRICOIN)");
        } else {
            info!("⚠️  Algorithmic USD peg disabled");
            consensus.set_peg_enabled(false).await?;
        }
        
        let consensus = Arc::new(RwLock::new(consensus));
        
        // Initialize RPC server if enabled - Use the same database
        let rpc_server = if config.enable_rpc {
            info!("🌐 Initializing RPC server...");
            let rpc_config = RpcConfig {
                host: config.rpc_host.clone(),
                port: config.rpc_port,
                ..Default::default()
            };
            // Use the same database instance
            Some(RpcServer::new(rpc_config, Arc::clone(&consensus), Arc::clone(&db)))
        } else {
            info!("🌐 RPC server disabled");
            None
        };
        
        Ok(Self {
            config,
            consensus,
            rpc_server,
        })
    }

    /// Load validator wallet from private key hex
    fn load_validator_wallet(private_key_hex: &str) -> Result<Wallet> {
        let private_key_bytes = utils::hex_to_bytes(private_key_hex)?;
        if private_key_bytes.len() != 32 {
            return Err(anyhow!("Invalid private key length: expected 32 bytes"));
        }
        
        let secret_key = secp256k1::SecretKey::from_slice(&private_key_bytes)
            .map_err(|e| anyhow!("Invalid private key: {}", e))?;
        
        Ok(Wallet::from_secret_key(secret_key))
    }

    /// Start the node
    pub async fn start(mut self) -> Result<()> {
        info!("🚀 Starting DinariBlockchain Node with USD Peg System...");
        self.config.display();
        
        // NEW: Display peg status on startup
        if self.config.enable_peg {
            info!("💰 USD Peg System Status:");
            info!("   Target: $1.00 = 1 DINARI = 1 AFRICOIN");
            info!("   Method: Algorithmic supply adjustment");
            info!("   Trigger: Activity-based demand detection");
        }
        
        // Take ownership of RPC server
        let rpc_server = self.rpc_server.take();
        
        // Start RPC server in background task
        let _rpc_task = if let Some(server) = rpc_server {
            Some(tokio::spawn(async move {
                if let Err(e) = server.start().await {
                    error!("❌ RPC server failed: {}", e);
                }
            }))
        } else {
            None
        };
        
        // Start consensus engine
        let consensus_clone = Arc::clone(&self.consensus);
        
        let consensus_task = tokio::spawn(async move {
            info!("🔗 Consensus engine starting...");
            
            // Start the consensus engine directly (it initializes itself)
            let mut consensus = consensus_clone.write().await;
            match consensus.start().await {
                Ok(_) => {
                    info!("✅ Consensus engine completed normally");
                }
                Err(e) => {
                    error!("❌ Consensus engine error: {}", e);
                }
            }
        });
        
        info!("✅ DinariBlockchain Node started successfully!");
        info!("🌟 Node is running. Press Ctrl+C to stop.");
        
        // NEW: Log peg endpoints available
        if self.config.enable_rpc && self.config.enable_peg {
            info!("💰 USD Peg RPC endpoints available:");
            info!("   - getPegStats: Get current peg statistics");
            info!("   - getCurrentPrice: Get current token prices");
            info!("   - getPegDemandScore: Get demand score and status");
            info!("   - getPegSupplyHistory: Get supply adjustment history");
        }
        
        // Wait for shutdown signal
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("📡 Received shutdown signal...");
            }
            result = consensus_task => {
                match result {
                    Ok(_) => info!("🔗 Consensus engine finished"),
                    Err(e) => error!("❌ Consensus engine task error: {}", e),
                }
            }
        }
        
        self.shutdown().await?;
        Ok(())
    }

    /// Graceful shutdown
    async fn shutdown(&self) -> Result<()> {
        info!("🛑 Shutting down DinariBlockchain Node...");
        
        // NEW: Log final peg status if enabled
        if self.config.enable_peg {
            info!("💰 Final USD peg status:");
            let consensus = self.consensus.read().await;
            let peg_stats = consensus.get_peg_stats().await;
            info!("   DINARI supply: {}", peg_stats.current_dinari_supply);
            info!("   AFRICOIN supply: {}", peg_stats.current_africoin_supply);
            info!("   Demand score: {:.2}", peg_stats.current_demand_score);
            info!("   Blocks processed: {}", peg_stats.blocks_processed);
        }
        
        // Give components time to finish current operations
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        info!("✅ DinariBlockchain Node shut down successfully");
        Ok(())
    }
}

/// Initialize logging
fn init_logging(log_level: &str) {
    let level = match log_level.to_lowercase().as_str() {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        _ => log::LevelFilter::Info,
    };
    
    env_logger::Builder::from_default_env()
        .filter_level(level)
        .init();
}

/// Print banner
fn print_banner() {
    println!("████████████████████████████████████████");
    println!("██          DINARI BLOCKCHAIN          ██");
    println!("██         v0.1.0 - Rust PoA           ██");
    println!("██        💰 USD Algorithmic Peg        ██");
    println!("██       1 USD = 1 DINARI/AFRICOIN     ██");
    println!("████████████████████████████████████████");
    println!();
    println!("🎯 Target: Maintain $1.00 USD peg through algorithmic supply adjustment");
    println!("📊 Method: Activity-based demand detection and token supply management");
    println!("🏦 Features: Treasury system, dual-token economy, PoA consensus");
    println!();
}

/// Main entry point
#[tokio::main]
async fn main() -> Result<()> {
    let config = NodeConfig::from_env_and_args();
    
    init_logging(&config.log_level);
    
    print_banner();
    
    let node = DinariNode::new(config).await?;
    node.start().await?;
    
    Ok(())
}