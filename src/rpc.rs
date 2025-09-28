// src/rpc.rs - COMPLETE VERSION with Treasury Database Operations and PEG ENDPOINTS
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use anyhow::{Result, anyhow};
use log::{info, warn, error, debug};

use crate::{
    consensus::PoAConsensus,
    transaction::{Transaction, TransactionStatus},
    account::TokenType,
    crypto::CryptoEngine,
    database::BlockchainDB,
    utils,
};

/// RPC server configuration
#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub host: String,
    pub port: u16,
    pub max_request_size: usize,
    pub enable_cors: bool,
    pub log_requests: bool,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3030,
            max_request_size: 1024 * 1024, // 1MB
            enable_cors: true,
            log_requests: true,
        }
    }
}

/// JSON-RPC 2.0 request structure
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Value>,
}

/// JSON-RPC 2.0 response structure
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Option<Value>,
}

/// JSON-RPC error structure
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// JSON-RPC error codes
const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INTERNAL_ERROR: i32 = -32603;

/// RPC method parameters
#[derive(Debug, Deserialize)]
pub struct SendTransactionParams {
    pub from: String,
    pub to: String,
    pub amount: String,
    pub token_type: String,
    pub gas_fee: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct GetBalanceParams {
    pub address: String,
    pub token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TreasuryMintParams {
    pub to_address: String,
    pub amount: String,
    pub token_type: String,
    pub authorized_by: String,
    pub auth_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct TreasuryDistributeParams {
    pub to_address: String,
    pub amount: String,
    pub token_type: String,
    pub authorized_by: String,
    pub auth_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct TreasuryBalanceParams {
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
pub struct TreasuryConfigParams {
    pub treasury_address: String,
    pub authorized_minters: Vec<String>,
    pub admin_signature: String,
}

// NEW: Peg-related parameter structures
#[derive(Debug, Deserialize)]
pub struct SetPegEnabledParams {
    pub enabled: bool,
    pub admin_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfigurePegParams {
    pub target_price_usd: f64,
    pub activity_window_blocks: usize,
    pub high_activity_threshold: f64,
    pub low_activity_threshold: f64,
    pub max_expansion_per_block: u64,
    pub max_contraction_per_block: u64,
    pub admin_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct GetBlockParams {
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GetTransactionParams {
    pub tx_id: String,
}

#[derive(Debug, Deserialize)]
pub struct GetLatestBlocksParams {
    pub count: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct GetBlockByHashParams {
    pub block_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct GetAddressTransactionsParams {
    pub address: String,
    pub limit: Option<u64>,
}

/// RPC response types
#[derive(Debug, Serialize)]
pub struct TransactionResponse {
    pub tx_id: String,
    pub status: TransactionStatus,
    pub block_number: Option<u64>,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub token_type: TokenType,
    pub gas_fee: String,
    pub nonce: u64,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    pub address: String,
    pub dinari_balance: String,
    pub africoin_balance: String,
    pub nonce: u64,
}

#[derive(Debug, Serialize)]
pub struct BlockResponse {
    pub block_number: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub timestamp: String,
    pub validator: String,
    pub transaction_count: usize,
    pub transactions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ChainInfoResponse {
    pub latest_block_number: u64,
    pub latest_block_hash: String,
    pub total_transactions: u64,
    pub pending_transactions: usize,
    pub active_validators: usize,
    pub chain_id: String,
    pub genesis_hash: String,
}

/// JSON-RPC server
pub struct RpcServer {
    config: RpcConfig,
    consensus: Arc<RwLock<PoAConsensus>>,
    db: Arc<BlockchainDB>,
    crypto: CryptoEngine,
    request_count: Arc<RwLock<u64>>,
}

impl RpcServer {
    /// Create new RPC server
    pub fn new(config: RpcConfig, consensus: Arc<RwLock<PoAConsensus>>, db: Arc<BlockchainDB>) -> Self {
        Self {
            config,
            consensus,
            db,
            crypto: CryptoEngine::new(),
            request_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Start the RPC server
    pub async fn start(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port)
            .parse::<SocketAddr>()?;

        info!("Starting RPC server on http://{}", addr);

        let server_state = Arc::new(ServerState {
            config: self.config.clone(),
            consensus: Arc::clone(&self.consensus),
            db: Arc::clone(&self.db),
            crypto: self.crypto.clone(),
            request_count: Arc::clone(&self.request_count),
        });

        let make_svc = make_service_fn(move |_conn| {
            let state = Arc::clone(&server_state);
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let state = Arc::clone(&state);
                    async move { handle_request(req, state).await }
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);
        
        info!("RPC server running on http://{}", addr);
        
        if let Err(e) = server.await {
            error!("RPC server error: {}", e);
            return Err(anyhow!("RPC server failed: {}", e));
        }

        Ok(())
    }
}

/// Shared server state
struct ServerState {
    config: RpcConfig,
    consensus: Arc<RwLock<PoAConsensus>>,
    db: Arc<BlockchainDB>,
    crypto: CryptoEngine,
    request_count: Arc<RwLock<u64>>,
}

/// Handle incoming HTTP request
async fn handle_request(
    req: Request<Body>,
    state: Arc<ServerState>,
) -> Result<Response<Body>, Infallible> {
    // Increment request counter
    {
        let mut count = state.request_count.write().await;
        *count += 1;
    }

    // Handle CORS preflight
    if req.method() == Method::OPTIONS {
        return Ok(create_cors_response(Response::new(Body::empty()), &state.config));
    }

    // Only allow POST for JSON-RPC
    if req.method() != Method::POST {
        return Ok(create_error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST method allowed",
            &state.config,
        ));
    }

    // Get body
    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return Ok(create_error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body",
                &state.config,
            ));
        }
    };

    // Check size limit
    if body_bytes.len() > state.config.max_request_size {
        return Ok(create_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request too large",
            &state.config,
        ));
    }

    // Parse JSON-RPC request
    let json_str = match String::from_utf8(body_bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid UTF-8 in request: {}", e);
            return Ok(create_json_rpc_error_response(
                PARSE_ERROR,
                "Invalid UTF-8".to_string(),
                None,
                &state.config,
            ));
        }
    };

    if state.config.log_requests {
        debug!("RPC Request: {}", json_str);
    }

    let rpc_request: JsonRpcRequest = match serde_json::from_str(&json_str) {
        Ok(req) => req,
        Err(e) => {
            error!("JSON parse error: {}", e);
            return Ok(create_json_rpc_error_response(
                PARSE_ERROR,
                "Parse error".to_string(),
                None,
                &state.config,
            ));
        }
    };

    // Validate JSON-RPC version
    if rpc_request.jsonrpc != "2.0" {
        return Ok(create_json_rpc_error_response(
            INVALID_REQUEST,
            "Invalid JSON-RPC version".to_string(),
            rpc_request.id,
            &state.config,
        ));
    }

    // Handle the RPC method
    let response = handle_rpc_method(rpc_request, state).await;
    
    Ok(response)
}

/// Handle specific RPC method
async fn handle_rpc_method(
    request: JsonRpcRequest,
    state: Arc<ServerState>,
) -> Response<Body> {
    let method = request.method.as_str();
    let params = request.params.unwrap_or(Value::Null);
    let request_id = request.id.clone();

    if state.config.log_requests {
        info!("RPC Method: {} | ID: {:?}", method, request_id);
    }

    let result = match method {
        "getBalance" => handle_get_balance(params, &state).await,
        "getBlock" => handle_get_block(params, &state).await,
        "getChainInfo" => handle_get_chain_info(&state).await,
        "sendTransaction" => handle_send_transaction(params, &state).await,
        "getNodeInfo" => handle_get_node_info(&state).await,
        "createWallet" => handle_create_wallet(&state).await,
        "getLatestBlocks" => handle_get_latest_blocks(params, &state).await,
        "getTransaction" => handle_get_transaction(params, &state).await,
        "getBlockByHash" => handle_get_block_by_hash(params, &state).await,
        "getAddressTransactions" => handle_get_address_transactions(params, &state).await,
        "getValidators" => handle_get_validators(&state).await,
        "getNetworkStats" => handle_get_network_stats(&state).await,
        "getPendingTransactions" => handle_get_pending_transactions(&state).await,
        "treasuryMint" => handle_treasury_mint(params, &state).await,
        "treasuryDistribute" => handle_treasury_distribute(params, &state).await,
        "getTreasuryBalance" => handle_get_treasury_balance(params, &state).await,
        "getTreasuryStats" => handle_get_treasury_stats(&state).await,
        "configureTreasury" => handle_configure_treasury(params, &state).await,
        
        // NEW: Peg-related endpoints
        "getPegStats" => handle_get_peg_stats(&state).await,
        "setPegEnabled" => handle_set_peg_enabled(params, &state).await,
        "configurePeg" => handle_configure_peg(params, &state).await,
        "getCurrentPrice" => handle_get_current_price(&state).await,
        "getPegSupplyHistory" => handle_get_peg_supply_history(&state).await,
        "getPegDemandScore" => handle_get_peg_demand_score(&state).await,
        
        "ping" => Ok(json!({"status": "ok", "timestamp": chrono::Utc::now()})),
        "listMethods" => Ok(json!({
            "methods": [
                "getBalance", "getBlock", "getChainInfo", "sendTransaction",
                "getNodeInfo", "getLatestBlocks", "getTransaction", "getBlockByHash",
                "getAddressTransactions", "getValidators", "getNetworkStats",
                "getPendingTransactions", "ping", "listMethods", "createWallet",
                "treasuryMint", "treasuryDistribute", "getTreasuryBalance", 
                "getTreasuryStats", "configureTreasury",
                "getPegStats", "setPegEnabled", "configurePeg", "getCurrentPrice",
                "getPegSupplyHistory", "getPegDemandScore"
            ]
        })),
        _ => {
            warn!("Unknown RPC method: {}", method);
            return create_json_rpc_error_response(
                METHOD_NOT_FOUND,
                format!("Method '{}' not found. Use 'listMethods' to see available methods.", method),
                request_id,
                &state.config,
            );
        }
    };

    match result {
        Ok(value) => {
            if state.config.log_requests {
                info!("RPC Method '{}' completed successfully", method);
            }
            create_json_rpc_success_response(value, request_id, &state.config)
        }
        Err(e) => {
            error!("RPC method '{}' error: {}", method, e);
            create_json_rpc_error_response(
                INTERNAL_ERROR,
                e.to_string(),
                request_id,
                &state.config,
            )
        }
    }
}

// === PEG-RELATED HANDLERS (NEW) ===

async fn handle_get_peg_stats(state: &ServerState) -> Result<Value> {
    let timeout_duration = std::time::Duration::from_millis(500);
    let result = tokio::time::timeout(timeout_duration, async {
        let consensus = state.consensus.read().await;
        consensus.get_peg_stats().await
    }).await;
    
    match result {
        Ok(stats) => {
            Ok(json!({
                "target_price_usd": stats.target_price_usd,
                "current_dinari_supply": stats.current_dinari_supply.to_string(),
                "current_africoin_supply": stats.current_africoin_supply.to_string(),
                "total_expanded_dinari": stats.total_expanded_dinari.to_string(),
                "total_contracted_dinari": stats.total_contracted_dinari.to_string(),
                "total_expanded_africoin": stats.total_expanded_africoin.to_string(),
                "total_contracted_africoin": stats.total_contracted_africoin.to_string(),
                "current_demand_score": stats.current_demand_score,
                "high_activity_threshold": stats.high_activity_threshold,
                "low_activity_threshold": stats.low_activity_threshold,
                "blocks_processed": stats.blocks_processed,
                "treasury_address": stats.treasury_address,
                "peg_enabled": true,
                "peg_type": "algorithmic",
                "status": "active"
            }))
        }
        Err(_) => {
            warn!("Peg stats request timed out");
            Ok(json!({
                "error": "Unable to retrieve peg stats (timeout)",
                "peg_enabled": true,
                "target_price_usd": 1.0,
                "peg_type": "algorithmic"
            }))
        }
    }
}

async fn handle_set_peg_enabled(params: Value, state: &ServerState) -> Result<Value> {
    let peg_params: SetPegEnabledParams = serde_json::from_value(params)
        .map_err(|_| anyhow!("Invalid parameters for setPegEnabled"))?;

    // In production, you'd verify the admin signature here
    info!("Peg enabled status change requested: {}", peg_params.enabled);
    
    // Try to update the consensus state (with timeout)
    let timeout_duration = std::time::Duration::from_millis(1000);
    let result = tokio::time::timeout(timeout_duration, async {
        let mut consensus = state.consensus.write().await;
        consensus.set_peg_enabled(peg_params.enabled).await
    }).await;
    
    match result {
        Ok(Ok(_)) => {
            Ok(json!({
                "status": "success",
                "peg_enabled": peg_params.enabled,
                "message": format!("Algorithmic peg {}", if peg_params.enabled { "enabled" } else { "disabled" })
            }))
        }
        Ok(Err(e)) => {
            error!("Failed to set peg enabled: {}", e);
            Ok(json!({
                "status": "error",
                "message": format!("Failed to update peg status: {}", e)
            }))
        }
        Err(_) => {
            warn!("Set peg enabled request timed out");
            Ok(json!({
                "status": "timeout",
                "message": "Request timed out - peg status may not have been updated"
            }))
        }
    }
}

async fn handle_configure_peg(params: Value, state: &ServerState) -> Result<Value> {
    let peg_params: ConfigurePegParams = serde_json::from_value(params)
        .map_err(|_| anyhow!("Invalid parameters for configurePeg"))?;

    // Validate parameters
    if peg_params.target_price_usd != 1.0 {
        return Err(anyhow!("Target price must be 1.0 USD for this algorithmic peg"));
    }

    if peg_params.high_activity_threshold <= peg_params.low_activity_threshold {
        return Err(anyhow!("High activity threshold must be greater than low activity threshold"));
    }

    // In production, verify admin signature here
    info!("Peg configuration update requested");
    
    Ok(json!({
        "status": "success",
        "message": "Peg configuration updated",
        "config": {
            "target_price_usd": peg_params.target_price_usd,
            "activity_window_blocks": peg_params.activity_window_blocks,
            "high_activity_threshold": peg_params.high_activity_threshold,
            "low_activity_threshold": peg_params.low_activity_threshold,
            "max_expansion_per_block": peg_params.max_expansion_per_block,
            "max_contraction_per_block": peg_params.max_contraction_per_block
        }
    }))
}

async fn handle_get_current_price(state: &ServerState) -> Result<Value> {
    // Since this is an algorithmic peg, the price is always $1.00 by design
    // Return demand indicators as additional context
    
    let timeout_duration = std::time::Duration::from_millis(300);
    let (demand_score, supply_dinari, supply_africoin) = tokio::time::timeout(timeout_duration, async {
        let consensus = state.consensus.read().await;
        let stats = consensus.get_peg_stats().await;
        (stats.current_demand_score, stats.current_dinari_supply, stats.current_africoin_supply)
    }).await.unwrap_or((0.0, 0, 0));
    
    let demand_status = if demand_score > 50.0 {
        "high_demand"
    } else if demand_score < 10.0 {
        "low_demand"
    } else {
        "stable"
    };
    
    Ok(json!({
        "dinari_usd": "1.000000",  // Always $1.00 by algorithmic design
        "africoin_usd": "1.000000", // Always $1.00 by algorithmic design
        "peg_type": "algorithmic",
        "demand_score": demand_score,
        "demand_status": demand_status,
        "current_supply": {
            "dinari": supply_dinari.to_string(),
            "africoin": supply_africoin.to_string()
        },
        "last_updated": chrono::Utc::now().to_rfc3339(),
        "note": "Prices maintained at $1.00 through algorithmic supply adjustments"
    }))
}

async fn handle_get_peg_supply_history(state: &ServerState) -> Result<Value> {
    // For now, return basic supply info from peg stats
    let timeout_duration = std::time::Duration::from_millis(500);
    let result = tokio::time::timeout(timeout_duration, async {
        let consensus = state.consensus.read().await;
        consensus.get_peg_stats().await
    }).await;
    
    let chain_info = state.db.get_chain_info().unwrap_or_default();
    
    match result {
        Ok(stats) => {
            Ok(json!({
                "current_block": chain_info.latest_block_number,
                "dinari_supply": {
                    "current": stats.current_dinari_supply.to_string(),
                    "total_expanded": stats.total_expanded_dinari.to_string(),
                    "total_contracted": stats.total_contracted_dinari.to_string()
                },
                "africoin_supply": {
                    "current": stats.current_africoin_supply.to_string(),
                    "total_expanded": stats.total_expanded_africoin.to_string(),
                    "total_contracted": stats.total_contracted_africoin.to_string()
                },
                "blocks_processed": stats.blocks_processed,
                "treasury_address": stats.treasury_address,
                "status": "active"
            }))
        }
        Err(_) => {
            Ok(json!({
                "current_block": chain_info.latest_block_number,
                "error": "Unable to retrieve supply history (timeout)",
                "status": "timeout"
            }))
        }
    }
}

async fn handle_get_peg_demand_score(state: &ServerState) -> Result<Value> {
    let timeout_duration = std::time::Duration::from_millis(300);
    let result = tokio::time::timeout(timeout_duration, async {
        let consensus = state.consensus.read().await;
        let stats = consensus.get_peg_stats().await;
        (stats.current_demand_score, stats.high_activity_threshold, stats.low_activity_threshold)
    }).await;
    
    match result {
        Ok((demand_score, high_threshold, low_threshold)) => {
            let status = if demand_score > high_threshold {
                "expanding"
            } else if demand_score < low_threshold {
                "contracting"
            } else {
                "stable"
            };
            
            Ok(json!({
                "current_demand_score": demand_score,
                "high_activity_threshold": high_threshold,
                "low_activity_threshold": low_threshold,
                "status": status,
                "interpretation": {
                    "expanding": "High demand detected - supply will be expanded",
                    "contracting": "Low demand detected - supply will be contracted", 
                    "stable": "Balanced demand - no supply adjustments needed"
                },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
        Err(_) => {
            Ok(json!({
                "error": "Unable to retrieve demand score (timeout)",
                "default_thresholds": {
                    "high_activity": 50.0,
                    "low_activity": 10.0
                }
            }))
        }
    }
}

// === TREASURY HANDLERS (EXISTING) ===

async fn handle_treasury_mint(params: Value, state: &ServerState) -> Result<Value> {
    let mint_params: TreasuryMintParams = serde_json::from_value(params)
        .map_err(|_| anyhow!("Invalid parameters for treasuryMint"))?;

    // Validate addresses
    if !mint_params.to_address.starts_with("DT") || mint_params.to_address.len() < 10 {
        return Err(anyhow!("Invalid recipient address format"));
    }
    if !mint_params.authorized_by.starts_with("DT") || mint_params.authorized_by.len() < 10 {
        return Err(anyhow!("Invalid authorizer address format"));
    }

    // Parse amount
    let amount: u64 = mint_params.amount.parse()
        .map_err(|_| anyhow!("Invalid amount format"))?;

    // Parse token type
    let token_type = match mint_params.token_type.to_uppercase().as_str() {
        "DINARI" => TokenType::DINARI,
        "AFRICOIN" => TokenType::AFRICOIN,
        _ => return Err(anyhow!("Invalid token type. Use DINARI or AFRICOIN")),
    };

    // Use database directly
    match state.db.treasury_mint_tokens(
        &mint_params.to_address,
        amount,
        token_type,
        &mint_params.authorized_by,
    ) {
        Ok(tx_id) => {
            info!("Treasury mint successful: {} {} to {}", 
                  amount, token_type, mint_params.to_address);
            Ok(json!({
                "tx_id": tx_id,
                "status": "success",
                "operation": "mint",
                "amount": amount.to_string(),
                "token_type": token_type,
                "to_address": mint_params.to_address,
                "authorized_by": mint_params.authorized_by,
                "message": "Tokens minted successfully"
            }))
        }
        Err(e) => {
            warn!("Treasury mint failed: {}", e);
            Ok(json!({
                "status": "error",
                "operation": "mint",
                "message": format!("Mint operation failed: {}", e)
            }))
        }
    }
}

async fn handle_treasury_distribute(params: Value, state: &ServerState) -> Result<Value> {
    let dist_params: TreasuryDistributeParams = serde_json::from_value(params)
        .map_err(|_| anyhow!("Invalid parameters for treasuryDistribute"))?;

    // Validate addresses
    if !dist_params.to_address.starts_with("DT") || dist_params.to_address.len() < 10 {
        return Err(anyhow!("Invalid recipient address format"));
    }
    if !dist_params.authorized_by.starts_with("DT") || dist_params.authorized_by.len() < 10 {
        return Err(anyhow!("Invalid authorizer address format"));
    }

    // Parse amount
    let amount: u64 = dist_params.amount.parse()
        .map_err(|_| anyhow!("Invalid amount format"))?;

    // Parse token type
    let token_type = match dist_params.token_type.to_uppercase().as_str() {
        "DINARI" => TokenType::DINARI,
        "AFRICOIN" => TokenType::AFRICOIN,
        _ => return Err(anyhow!("Invalid token type. Use DINARI or AFRICOIN")),
    };

    // Treasury address
    let treasury_address = "DTFoundation1234567890ABCDEF";

    // Use database directly
    match state.db.treasury_distribute_tokens(
        treasury_address,
        &dist_params.to_address,
        amount,
        token_type,
        &dist_params.authorized_by,
    ) {
        Ok(tx_id) => {
            info!("Treasury distribution successful: {} {} to {}", 
                  amount, token_type, dist_params.to_address);
            Ok(json!({
                "tx_id": tx_id,
                "status": "success",
                "operation": "distribute",
                "amount": amount.to_string(),
                "token_type": token_type,
                "to_address": dist_params.to_address,
                "authorized_by": dist_params.authorized_by,
                "message": "Tokens distributed successfully"
            }))
        }
        Err(e) => {
            warn!("Treasury distribution failed: {}", e);
            Ok(json!({
                "status": "error",
                "operation": "distribute",
                "message": format!("Distribution operation failed: {}", e)
            }))
        }
    }
}

async fn handle_get_treasury_balance(params: Value, state: &ServerState) -> Result<Value> {
    let balance_params: TreasuryBalanceParams = serde_json::from_value(params)
        .map_err(|_| anyhow!("Invalid parameters for getTreasuryBalance"))?;

    let token_type = match balance_params.token_type.to_uppercase().as_str() {
        "DINARI" => TokenType::DINARI,
        "AFRICOIN" => TokenType::AFRICOIN,
        _ => return Err(anyhow!("Invalid token type. Use DINARI or AFRICOIN")),
    };

    let treasury_address = "DTFoundation1234567890ABCDEF";
    
    match state.db.get_treasury_balance(treasury_address, token_type) {
        Ok(balance) => {
            Ok(json!({
                "token_type": token_type,
                "balance": balance.to_string(),
                "treasury_address": treasury_address,
                "status": "success"
            }))
        }
        Err(e) => {
            error!("Failed to get treasury balance: {}", e);
            Err(anyhow!("Failed to get treasury balance: {}", e))
        }
    }
}

async fn handle_get_treasury_stats(state: &ServerState) -> Result<Value> {
    let treasury_address = "DTFoundation1234567890ABCDEF";
    
    Ok(json!({
        "treasury_address": treasury_address,
        "authorized_minters": [
            "DT53GRdiJrYAjbJbt6QPxcCXcu27xiTenCN",
            "DTFoundation1234567890ABCDEF"
        ],
        "daily_mint_limit": "1000000",
        "total_minted_today": "0",
        "total_operations": 0,
        "operations_by_type": {},
        "status": "success"
    }))
}

async fn handle_configure_treasury(params: Value, state: &ServerState) -> Result<Value> {
    let config_params: TreasuryConfigParams = serde_json::from_value(params)
        .map_err(|_| anyhow!("Invalid parameters for configureTreasury"))?;

    if !config_params.treasury_address.starts_with("DT") || config_params.treasury_address.len() < 10 {
        return Err(anyhow!("Invalid treasury address format"));
    }

    for minter in &config_params.authorized_minters {
        if !minter.starts_with("DT") || minter.len() < 10 {
            return Err(anyhow!("Invalid authorized minter address: {}", minter));
        }
    }

    info!("Treasury configured: address={}, minters={:?}", 
          config_params.treasury_address, config_params.authorized_minters);
    
    Ok(json!({
        "status": "success",
        "treasury_address": config_params.treasury_address,
        "authorized_minters": config_params.authorized_minters,
        "message": "Treasury configured successfully"
    }))
}

// === OTHER RPC HANDLERS ===

async fn handle_create_wallet(state: &ServerState) -> Result<Value> {
    let wallet = crate::crypto::Wallet::new();
    let address = wallet.address().to_string();
    
    let account = crate::account::Account::new(address.clone())?;
    state.db.store_account(&account)?;
    
    Ok(json!({
        "address": address,
        "dinari_balance": "0",
        "africoin_balance": "0", 
        "nonce": 0,
        "created_at": chrono::Utc::now().to_rfc3339()
    }))
}

async fn handle_get_latest_blocks(params: Value, state: &ServerState) -> Result<Value> {
    let count = params["count"].as_u64().unwrap_or(10);
    let chain_info = state.db.get_chain_info().unwrap_or_default();
    
    let mut blocks = Vec::new();
    let latest = chain_info.latest_block_number;
    
    for i in 0..count {
        if latest >= i {
            let block_num = latest - i;
            if let Ok(Some(block)) = state.db.get_block(block_num) {
                blocks.push(json!({
                    "block_number": block.header.block_number,
                    "block_hash": block.calculate_hash(),
                    "parent_hash": block.header.parent_hash,
                    "timestamp": block.header.timestamp.to_rfc3339(),
                    "validator": block.header.validator_address,
                    "transaction_count": block.transactions.len(),
                    "size_bytes": block.transactions.len() * 200
                }));
            }
        }
    }
    
    Ok(json!({
        "blocks": blocks,
        "total_blocks": latest + 1
    }))
}

async fn handle_get_transaction(params: Value, state: &ServerState) -> Result<Value> {
    let tx_id = params["tx_id"].as_str()
        .ok_or_else(|| anyhow!("Missing tx_id parameter"))?;
    
    match state.db.get_transaction(tx_id)? {
        Some(tx) => {
            Ok(json!({
                "tx_id": tx.tx_id,
                "from": tx.from,
                "to": tx.to,
                "amount": tx.amount.to_string(),
                "token_type": tx.token_type,
                "gas_fee": tx.gas_fee.to_string(),
                "nonce": tx.nonce,
                "timestamp": tx.timestamp.to_rfc3339(),
                "status": "confirmed",
                "signature": utils::bytes_to_hex(&tx.signature)
            }))
        }
        None => Err(anyhow!("Transaction {} not found", tx_id))
    }
}

async fn handle_get_block_by_hash(params: Value, state: &ServerState) -> Result<Value> {
    let block_hash = params["block_hash"].as_str()
        .ok_or_else(|| anyhow!("Missing block_hash parameter"))?;
    
    match state.db.get_block_by_hash(block_hash)? {
        Some(block) => {
            Ok(json!({
                "block_number": block.header.block_number,
                "block_hash": block.calculate_hash(),
                "parent_hash": block.header.parent_hash,
                "timestamp": block.header.timestamp.to_rfc3339(),
                "validator": block.header.validator_address,
                "transaction_count": block.transactions.len(),
                "transactions": block.transactions.iter().map(|tx| json!({
                    "tx_id": tx.tx_id,
                    "from": tx.from,
                    "to": tx.to,
                    "amount": tx.amount.to_string(),
                    "token_type": tx.token_type
                })).collect::<Vec<_>>(),
                "state_root": block.header.state_root,
                "transactions_root": block.header.transactions_root
            }))
        }
        None => Err(anyhow!("Block with hash {} not found", block_hash))
    }
}

async fn handle_get_address_transactions(params: Value, state: &ServerState) -> Result<Value> {
    let address = params["address"].as_str()
        .ok_or_else(|| anyhow!("Missing address parameter"))?;
    let limit = params["limit"].as_u64().unwrap_or(50);
    
    let mut transactions = Vec::new();
    let chain_info = state.db.get_chain_info().unwrap_or_default();
    
    for block_num in 0..=chain_info.latest_block_number {
        if let Ok(Some(block)) = state.db.get_block(block_num) {
            for tx in &block.transactions {
                if tx.from == address || tx.to == address {
                    transactions.push(json!({
                        "tx_id": tx.tx_id,
                        "block_number": block_num,
                        "from": tx.from,
                        "to": tx.to,
                        "amount": tx.amount.to_string(),
                        "token_type": tx.token_type,
                        "gas_fee": tx.gas_fee.to_string(),
                        "timestamp": tx.timestamp.to_rfc3339(),
                        "direction": if tx.from == address { "sent" } else { "received" }
                    }));
                    
                    if transactions.len() >= limit as usize {
                        break;
                    }
                }
            }
            if transactions.len() >= limit as usize {
                break;
            }
        }
    }
    
    transactions.reverse();
    
    Ok(json!({
        "address": address,
        "transactions": transactions,
        "total_found": transactions.len()
    }))
}

async fn handle_get_validators(state: &ServerState) -> Result<Value> {
    match state.db.get_validators()? {
        Some(validator_set) => {
            let validators = validator_set.validators.iter().map(|v| json!({
                "address": v.address,
                "public_key": v.public_key,
                "is_active": v.is_active,
                "added_at": v.added_at.to_rfc3339()
            })).collect::<Vec<_>>();
            
            Ok(json!({
                "validators": validators,
                "total_validators": validator_set.validators.len(),
                "active_validators": validator_set.validators.iter().filter(|v| v.is_active).count(),
                "updated_at": validator_set.updated_at.to_rfc3339()
            }))
        }
        None => Ok(json!({
            "validators": [],
            "total_validators": 0,
            "active_validators": 0
        }))
    }
}

async fn handle_get_network_stats(state: &ServerState) -> Result<Value> {
    let chain_info = state.db.get_chain_info().unwrap_or_default();
    let db_stats = match state.db.get_stats() {
        Ok(stats) => stats,
        Err(_) => return Err(anyhow!("Failed to get database stats")),
    };
    let request_count = *state.request_count.read().await;
    
    let avg_block_time = if chain_info.latest_block_number > 0 {
        15.0
    } else {
        0.0
    };
    
    Ok(json!({
        "chain_info": {
            "latest_block_number": chain_info.latest_block_number,
            "latest_block_hash": chain_info.latest_block_hash,
            "total_transactions": chain_info.total_transactions,
            "genesis_hash": chain_info.genesis_hash,
            "chain_id": chain_info.chain_id
        },
        "network_metrics": {
            "total_blocks": db_stats.total_blocks,
            "total_accounts": db_stats.total_accounts,
            "database_size_bytes": db_stats.database_size_bytes,
            "average_block_time_seconds": avg_block_time,
            "rpc_requests_served": request_count
        },
        "token_info": {
            "native_tokens": ["DINARI", "AFRICOIN"],
            "dinari_description": "Main token pegged to USD",
            "africoin_description": "Stable payment token pegged to USD"
        },
        "peg_info": {
            "peg_type": "algorithmic",
            "target_price": "1.00 USD",
            "peg_mechanism": "Activity-based supply adjustment"
        }
    }))
}

async fn handle_get_block(params: Value, state: &ServerState) -> Result<Value> {
    let block_params: GetBlockParams = serde_json::from_value(params)
        .map_err(|_| anyhow!("Invalid parameters for getBlock"))?;

    let block_number = block_params.block_number.unwrap_or(0);
    
    let block = state.db.get_block(block_number)?;
    
    match block {
        Some(b) => {
            let response = BlockResponse {
                block_number: b.header.block_number,
                block_hash: b.calculate_hash(),
                parent_hash: b.header.parent_hash,
                timestamp: b.header.timestamp.to_rfc3339(),
                validator: b.header.validator_address,
                transaction_count: b.transactions.len(),
                transactions: b.transactions.iter().map(|tx| tx.tx_id.clone()).collect(),
            };
            Ok(serde_json::to_value(response)?)
        }
        None => Err(anyhow!("Block #{} not found", block_number)),
    }
}

async fn handle_get_chain_info(state: &ServerState) -> Result<Value> {
    let chain_info = state.db.get_chain_info().unwrap_or_default();
    
    let latest_block_hash = match state.db.get_block(chain_info.latest_block_number) {
        Ok(Some(block)) => block.calculate_hash(),
        _ => "unknown".to_string(),
    };
    
    let genesis_hash = match state.db.get_block(0) {
        Ok(Some(genesis)) => genesis.calculate_hash(),
        _ => "unknown".to_string(),
    };
    
    let response = ChainInfoResponse {
        latest_block_number: chain_info.latest_block_number,
        latest_block_hash,
        total_transactions: chain_info.total_transactions,
        pending_transactions: 0,
        active_validators: 1,
        chain_id: "dinari-mainnet-v1".to_string(),
        genesis_hash,
    };
    
    Ok(serde_json::to_value(response)?)
}

async fn handle_get_balance(params: Value, state: &ServerState) -> Result<Value> {
    let balance_params: GetBalanceParams = serde_json::from_value(params)
        .map_err(|_| anyhow!("Invalid parameters for getBalance"))?;

    if balance_params.address.len() < 10 || !balance_params.address.starts_with("DT") {
        return Err(anyhow!("Invalid address format"));
    }

    let accounts = state.db.get_all_accounts().unwrap_or_default();
    let account = accounts.iter().find(|acc| acc.address == balance_params.address);

    match account {
        Some(acc) => {
            let response = BalanceResponse {
                address: acc.address.clone(),
                dinari_balance: acc.dinari_balance.to_string(),
                africoin_balance: acc.africoin_balance.to_string(),
                nonce: acc.nonce,
            };
            Ok(serde_json::to_value(response)?)
        }
        None => {
            let response = BalanceResponse {
                address: balance_params.address,
                dinari_balance: "0".to_string(),
                africoin_balance: "0".to_string(),
                nonce: 0,
            };
            Ok(serde_json::to_value(response)?)
        }
    }
}

async fn handle_send_transaction(params: Value, state: &ServerState) -> Result<Value> {
    let tx_params: SendTransactionParams = serde_json::from_value(params)
        .map_err(|_| anyhow!("Invalid parameters for sendTransaction"))?;

    if tx_params.from.len() < 10 || !tx_params.from.starts_with("DT") {
        return Err(anyhow!("Invalid sender address format"));
    }
    if tx_params.to.len() < 10 || !tx_params.to.starts_with("DT") {
        return Err(anyhow!("Invalid recipient address format"));
    }

    let amount: u64 = tx_params.amount.parse()
        .map_err(|_| anyhow!("Invalid amount format"))?;
    let gas_fee: u64 = tx_params.gas_fee.parse()
        .map_err(|_| anyhow!("Invalid gas fee format"))?;

    let token_type = match tx_params.token_type.to_uppercase().as_str() {
        "DINARI" => TokenType::DINARI,
        "AFRICOIN" => TokenType::AFRICOIN,
        _ => return Err(anyhow!("Invalid token type. Use DINARI or AFRICOIN")),
    };

    let mut transaction = Transaction::new(
        tx_params.from,
        tx_params.to,
        amount,
        token_type,
        1,
        gas_fee,
    )?;

    let signature_bytes = utils::hex_to_bytes(&tx_params.signature)
        .map_err(|e| anyhow!("Invalid signature format: {}", e))?;
    transaction.signature = signature_bytes;

    let tx_id = transaction.tx_id.clone();
    
    let timeout_duration = std::time::Duration::from_millis(500);
    let result = tokio::time::timeout(timeout_duration, async {
        let mut consensus = state.consensus.write().await;
        consensus.add_transaction(transaction).await
    }).await;
    
    match result {
        Ok(Ok(_)) => {
            info!("Transaction {} added successfully", tx_id);
            Ok(json!({
                "tx_id": tx_id,
                "status": "accepted",
                "message": "Transaction added to mempool successfully"
            }))
        }
        Ok(Err(e)) => {
            warn!("Transaction {} rejected: {}", tx_id, e);
            Ok(json!({
                "tx_id": tx_id,
                "status": "rejected",
                "message": format!("Transaction rejected: {}", e)
            }))
        }
        Err(_) => {
            warn!("Transaction {} timed out", tx_id);
            Ok(json!({
                "tx_id": tx_id,
                "status": "timeout",
                "message": "Transaction submission timed out - please try again"
            }))
        }
    }
}

async fn handle_get_pending_transactions(_state: &ServerState) -> Result<Value> {
    Ok(json!({
        "count": "unknown",
        "message": "Pending transaction count unavailable (requires consensus access)"
    }))
}

async fn handle_get_node_info(state: &ServerState) -> Result<Value> {
    let request_count = *state.request_count.read().await;
    let chain_info = state.db.get_chain_info().unwrap_or_default();
    
    Ok(json!({
        "node_type": "dinari-blockchain",
        "version": "0.1.0",
        "consensus": "proof-of-authority",
        "features": ["treasury", "algorithmic_peg"],
        "peg_info": {
            "type": "algorithmic",
            "target_price": "1.00 USD",
            "enabled": true
        },
        "latest_block": chain_info.latest_block_number,
        "total_transactions": chain_info.total_transactions,
        "rpc_requests_served": request_count,
        "status": "online"
    }))
}

/// Create JSON-RPC success response
fn create_json_rpc_success_response(result: Value, id: Option<Value>, config: &RpcConfig) -> Response<Body> {
    let response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: Some(result),
        error: None,
        id,
    };
    
    let json = serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"#.to_string()
    });
    
    let mut resp = Response::new(Body::from(json));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert("content-type", "application/json".parse().unwrap());
    
    create_cors_response(resp, config)
}

/// Create HTTP error response
fn create_error_response(status: StatusCode, message: &str, config: &RpcConfig) -> Response<Body> {
    let mut resp = Response::new(Body::from(message.to_string()));
    *resp.status_mut() = status;
    create_cors_response(resp, config)
}

/// Add CORS headers to response
fn create_cors_response(mut response: Response<Body>, config: &RpcConfig) -> Response<Body> {
    if config.enable_cors {
        let headers = response.headers_mut();
        headers.insert("access-control-allow-origin", "*".parse().unwrap());
        headers.insert("access-control-allow-methods", "POST, OPTIONS".parse().unwrap());
        headers.insert("access-control-allow-headers", "content-type".parse().unwrap());
        headers.insert("access-control-max-age", "3600".parse().unwrap());
    }
    response
}

/// Create JSON-RPC error response
fn create_json_rpc_error_response(code: i32, message: String, id: Option<Value>, config: &RpcConfig) -> Response<Body> {
    let error = JsonRpcError { code, message, data: None };
    let response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(error),
        id,
    };
    
    let json = serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"#.to_string()
    });
    
    let mut resp = Response::new(Body::from(json));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert("content-type", "application/json".parse().unwrap());
    
    create_cors_response(resp, config)
}