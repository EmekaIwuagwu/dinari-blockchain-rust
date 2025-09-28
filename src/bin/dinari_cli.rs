// src/bin/dinari_cli.rs - CLI client for Dinari Blockchain
use std::fs;
use std::path::PathBuf;
use anyhow::{Result, anyhow};
use serde_json::{json, Value};
use clap::{Parser, Subcommand};
use secp256k1::SecretKey;
use dinari_blockchain::{
    crypto::{Wallet, CryptoEngine},
    account::TokenType,
    transaction::Transaction,
    utils,
};

/// Dinari Blockchain CLI Client
#[derive(Parser)]
#[command(name = "dinari-cli")]
#[command(about = "Command-line client for Dinari Blockchain")]
#[command(version = "0.1.0")]
struct Cli {
    /// RPC server URL
    #[arg(long, default_value = "http://127.0.0.1:3030")]
    rpc_url: String,
    
    /// Wallet file path
    #[arg(long, default_value = "~/.dinari/wallet.json")]
    wallet_path: String,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Wallet management commands
    Wallet {
        #[command(subcommand)]
        action: WalletCommands,
    },
    /// Balance and account commands
    Balance {
        /// Address to check balance for
        address: Option<String>,
        /// Token type (DINARI or AFRICOIN)
        #[arg(long, default_value = "both")]
        token: String,
    },
    /// Send transactions
    Send {
        /// Recipient address
        to: String,
        /// Amount to send
        amount: u64,
        /// Token type (DINARI or AFRICOIN)
        #[arg(long, default_value = "DINARI")]
        token: String,
        /// Gas fee
        #[arg(long, default_value = "10")]
        gas_fee: u64,
    },
    /// Block information
    Block {
        /// Block number (defaults to latest)
        number: Option<u64>,
    },
    /// Chain information
    Info,
    /// Node information
    Node,
    /// List pending transactions
    Pending,
    /// Transaction details
    Transaction {
        /// Transaction ID
        tx_id: String,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Create a new wallet
    Create,
    /// Show wallet info
    Info,
    /// Import wallet from private key
    Import {
        /// Private key in hex format
        private_key: String,
    },
    /// Export private key
    Export,
    /// Show wallet address
    Address,
}

/// Wallet storage format
#[derive(serde::Serialize, serde::Deserialize)]
struct WalletFile {
    address: String,
    private_key: String,
    created_at: String,
}

/// RPC client
struct RpcClient {
    client: reqwest::Client,
    url: String,
    request_id: u64,
}

impl RpcClient {
    fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
            request_id: 1,
        }
    }

    async fn call(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id
        });

        self.request_id += 1;

        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error: {}", response.status()));
        }

        let json: Value = response.json().await?;

        if let Some(error) = json.get("error") {
            return Err(anyhow!("RPC error: {}", error));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("No result in RPC response"))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let mut rpc = RpcClient::new(cli.rpc_url);

    match cli.command {
        Commands::Wallet { action } => handle_wallet_command(action, &cli.wallet_path).await,
        Commands::Balance { address, token } => handle_balance_command(&mut rpc, address, &token, &cli.wallet_path).await,
        Commands::Send { to, amount, token, gas_fee } => handle_send_command(&mut rpc, &to, amount, &token, gas_fee, &cli.wallet_path).await,
        Commands::Block { number } => handle_block_command(&mut rpc, number).await,
        Commands::Info => handle_info_command(&mut rpc).await,
        Commands::Node => handle_node_command(&mut rpc).await,
        Commands::Pending => handle_pending_command(&mut rpc).await,
        Commands::Transaction { tx_id } => handle_transaction_command(&mut rpc, &tx_id).await,
    }
}

async fn handle_wallet_command(action: WalletCommands, wallet_path: &str) -> Result<()> {
    let wallet_path = expand_path(wallet_path);

    match action {
        WalletCommands::Create => {
            if wallet_path.exists() {
                println!("Wallet already exists at: {}", wallet_path.display());
                println!("Use 'wallet info' to view or delete the existing wallet first.");
                return Ok(());
            }

            let wallet = Wallet::new();
            let wallet_file = WalletFile {
                address: wallet.address().to_string(),
                private_key: utils::bytes_to_hex(&wallet.secret_key().secret_bytes()),
                created_at: chrono::Utc::now().to_rfc3339(),
            };

            // Create directory if it doesn't exist
            if let Some(parent) = wallet_path.parent() {
                fs::create_dir_all(parent)?;
            }

            fs::write(&wallet_path, serde_json::to_string_pretty(&wallet_file)?)?;

            println!("✅ New wallet created!");
            println!("📍 Address: {}", wallet_file.address);
            println!("💾 Saved to: {}", wallet_path.display());
            println!("⚠️  Keep your private key safe - it cannot be recovered!");
        }

        WalletCommands::Info => {
            let wallet_file = load_wallet(&wallet_path)?;
            println!("📍 Address: {}", wallet_file.address);
            println!("📅 Created: {}", wallet_file.created_at);
            println!("💾 File: {}", wallet_path.display());
        }

        WalletCommands::Import { private_key } => {
            if wallet_path.exists() {
                println!("Wallet already exists. Delete it first to import a new one.");
                return Ok(());
            }

            let private_key_bytes = utils::hex_to_bytes(&private_key)?;
            if private_key_bytes.len() != 32 {
                return Err(anyhow!("Private key must be 32 bytes (64 hex characters)"));
            }

            let secret_key = SecretKey::from_slice(&private_key_bytes)?;
            let _wallet = Wallet::from_secret_key(secret_key);

            let wallet_file = WalletFile {
                address: _wallet.address().to_string(),
                private_key,
                created_at: chrono::Utc::now().to_rfc3339(),
            };

            if let Some(parent) = wallet_path.parent() {
                fs::create_dir_all(parent)?;
            }

            fs::write(&wallet_path, serde_json::to_string_pretty(&wallet_file)?)?;

            println!("✅ Wallet imported!");
            println!("📍 Address: {}", wallet_file.address);
        }

        WalletCommands::Export => {
            let wallet_file = load_wallet(&wallet_path)?;
            println!("⚠️  WARNING: Never share your private key!");
            println!("🔑 Private Key: {}", wallet_file.private_key);
        }

        WalletCommands::Address => {
            let wallet_file = load_wallet(&wallet_path)?;
            println!("{}", wallet_file.address);
        }
    }

    Ok(())
}

async fn handle_balance_command(
    rpc: &mut RpcClient,
    address: Option<String>,
    _token: &str,
    wallet_path: &str,
) -> Result<()> {
    let addr = match address {
        Some(addr) => addr,
        None => {
            let wallet_file = load_wallet(&expand_path(wallet_path))?;
            wallet_file.address
        }
    };

    let params = json!({
        "address": addr
    });

    let result = rpc.call("getBalance", Some(params)).await?;

    let dinari_balance: u64 = result["dinari_balance"].as_str().unwrap_or("0").parse()?;
    let africoin_balance: u64 = result["africoin_balance"].as_str().unwrap_or("0").parse()?;
    let nonce: u64 = result["nonce"].as_u64().unwrap_or(0);

    println!("📍 Address: {}", addr);
    println!("💰 DINARI Balance: {}", format_tokens(dinari_balance));
    println!("💰 AFRICOIN Balance: {}", format_tokens(africoin_balance));
    println!("🔢 Nonce: {}", nonce);

    Ok(())
}

async fn handle_send_command(
    rpc: &mut RpcClient,
    to: &str,
    amount: u64,
    token: &str,
    gas_fee: u64,
    wallet_path: &str,
) -> Result<()> {
    // Load wallet
    let wallet_file = load_wallet(&expand_path(wallet_path))?;
    let private_key_bytes = utils::hex_to_bytes(&wallet_file.private_key)?;
    let secret_key = SecretKey::from_slice(&private_key_bytes)?;
    let _wallet = Wallet::from_secret_key(secret_key);

    // Validate addresses
    if !to.starts_with("DT") || to.len() < 10 {
        return Err(anyhow!("Invalid recipient address format"));
    }

    // Parse token type
    let token_type = match token.to_uppercase().as_str() {
        "DINARI" => TokenType::DINARI,
        "AFRICOIN" => TokenType::AFRICOIN,
        _ => return Err(anyhow!("Invalid token type. Use DINARI or AFRICOIN")),
    };

    // Create transaction
    let mut transaction = Transaction::new(
        wallet_file.address.clone(),
        to.to_string(),
        amount,
        token_type,
        1, // nonce - in production, get from balance query
        gas_fee,
    )?;

    // Sign transaction
    let crypto = CryptoEngine::new();
    transaction.sign(&crypto, &secret_key)?;

    // Send via RPC
    let params = json!({
        "from": wallet_file.address,
        "to": to,
        "amount": amount.to_string(),
        "token_type": token.to_uppercase(),
        "gas_fee": gas_fee.to_string(),
        "signature": utils::bytes_to_hex(&transaction.signature)
    });

    let result = rpc.call("sendTransaction", Some(params)).await?;

    println!("📤 Transaction submitted!");
    println!("🆔 TX ID: {}", result["tx_id"].as_str().unwrap_or("unknown"));
    println!("📊 Status: {}", result["status"].as_str().unwrap_or("unknown"));
    println!("💬 Message: {}", result["message"].as_str().unwrap_or(""));

    Ok(())
}

async fn handle_block_command(rpc: &mut RpcClient, number: Option<u64>) -> Result<()> {
    let block_number = number.unwrap_or(0);
    
    let params = json!({
        "block_number": block_number
    });

    let result = rpc.call("getBlock", Some(params)).await?;

    println!("🧱 Block #{}", result["block_number"]);
    println!("🔗 Hash: {}", result["block_hash"].as_str().unwrap_or("unknown"));
    println!("🔗 Parent: {}", result["parent_hash"].as_str().unwrap_or("unknown"));
    println!("⏰ Time: {}", result["timestamp"].as_str().unwrap_or("unknown"));
    println!("👤 Validator: {}", result["validator"].as_str().unwrap_or("unknown"));
    println!("📊 Transactions: {}", result["transaction_count"].as_u64().unwrap_or(0));

    if let Some(txs) = result["transactions"].as_array() {
        if !txs.is_empty() {
            println!("📝 Transaction IDs:");
            for tx in txs {
                println!("  - {}", tx.as_str().unwrap_or("unknown"));
            }
        }
    }

    Ok(())
}

async fn handle_info_command(rpc: &mut RpcClient) -> Result<()> {
    let result = rpc.call("getChainInfo", None).await?;

    println!("⛓️  Chain Information");
    println!("📊 Latest Block: #{}", result["latest_block_number"]);
    println!("🔗 Latest Hash: {}", result["latest_block_hash"].as_str().unwrap_or("unknown"));
    println!("📈 Total Transactions: {}", result["total_transactions"]);
    println!("⏳ Pending Transactions: {}", result["pending_transactions"]);
    println!("👥 Active Validators: {}", result["active_validators"]);
    println!("🆔 Chain ID: {}", result["chain_id"].as_str().unwrap_or("unknown"));
    println!("🌱 Genesis Hash: {}", result["genesis_hash"].as_str().unwrap_or("unknown"));

    Ok(())
}

async fn handle_node_command(rpc: &mut RpcClient) -> Result<()> {
    let result = rpc.call("getNodeInfo", None).await?;

    println!("🖥️  Node Information");
    println!("📦 Type: {}", result["node_type"].as_str().unwrap_or("unknown"));
    println!("🏷️  Version: {}", result["version"].as_str().unwrap_or("unknown"));
    println!("🔄 Consensus: {}", result["consensus"].as_str().unwrap_or("unknown"));
    println!("📊 Latest Block: #{}", result["latest_block"]);
    println!("📈 Total Transactions: {}", result["total_transactions"]);
    println!("📡 RPC Requests: {}", result["rpc_requests_served"]);
    println!("✅ Status: {}", result["status"].as_str().unwrap_or("unknown"));

    Ok(())
}

async fn handle_pending_command(rpc: &mut RpcClient) -> Result<()> {
    let result = rpc.call("getPendingTransactions", None).await?;

    println!("⏳ Pending Transactions");
    println!("📊 Count: {}", result["count"].as_str().unwrap_or("unknown"));
    println!("💬 {}", result["message"].as_str().unwrap_or(""));

    Ok(())
}

async fn handle_transaction_command(_rpc: &mut RpcClient, tx_id: &str) -> Result<()> {
    println!("🔍 Transaction lookup not yet implemented in RPC server");
    println!("🆔 Requested TX ID: {}", tx_id);
    println!("💡 Use 'block <number>' to see transactions in a specific block");

    Ok(())
}

fn load_wallet(wallet_path: &PathBuf) -> Result<WalletFile> {
    if !wallet_path.exists() {
        return Err(anyhow!(
            "Wallet not found at {}. Create one with 'wallet create'",
            wallet_path.display()
        ));
    }

    let content = fs::read_to_string(wallet_path)?;
    let wallet: WalletFile = serde_json::from_str(&content)?;
    Ok(wallet)
}

fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

fn format_tokens(amount: u64) -> String {
    // Simple formatting - in production you'd want decimal support
    format!("{}", amount)
}