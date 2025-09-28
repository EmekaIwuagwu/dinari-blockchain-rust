// src/peg.rs - Algorithmic USD Peg (No External Oracles) - FIXED ALL ISSUES
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use anyhow::Result;
use std::collections::VecDeque;
use log::{info, warn, debug};

use crate::{
    account::{AccountManager, TokenType},
    transaction::{Transaction, TransactionBuilder},
    crypto::Wallet,
    block::Block,
};

/// Algorithmic peg configuration
#[derive(Debug, Clone)]
pub struct AlgorithmicPegConfig {
    pub target_price_usd: f64,               // Always $1.00 by definition
    pub activity_window_blocks: usize,       // Look at last N blocks for activity
    pub high_activity_threshold: f64,        // Expansion threshold (txs/block)
    pub low_activity_threshold: f64,         // Contraction threshold (txs/block)
    pub max_expansion_per_block: u64,        // Max tokens to mint per block
    pub max_contraction_per_block: u64,      // Max tokens to burn per block  
    pub base_supply: u64,                    // Initial supply (genesis)
    pub stability_fund_address: String,      // Treasury for operations
}

impl Default for AlgorithmicPegConfig {
    fn default() -> Self {
        Self {
            target_price_usd: 1.0,           // $1.00 by definition
            activity_window_blocks: 100,     // Look at last 100 blocks
            high_activity_threshold: 50.0,   // >50 txs/block = high demand
            low_activity_threshold: 10.0,    // <10 txs/block = low demand  
            max_expansion_per_block: 100_000, // 100k max expansion
            max_contraction_per_block: 50_000, // 50k max contraction
            base_supply: 1_000_000_000,      // 1B initial supply
            stability_fund_address: String::new(),
        }
    }
}

/// Block activity metrics for demand estimation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockActivity {
    pub block_number: u64,
    pub timestamp: DateTime<Utc>,
    pub transaction_count: usize,
    pub total_gas_fees: u64,
    pub dinari_volume: u64,      // Total DINARI transferred
    pub africoin_volume: u64,    // Total AFRICOIN transferred
    pub unique_addresses: usize, // Active addresses in block
}

/// Supply adjustment action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupplyAction {
    /// Expand supply (high demand detected)
    Expand { 
        token: TokenType,
        amount: u64, 
        reason: String,
        demand_score: f64,
    },
    /// Contract supply (low demand detected)  
    Contract { 
        token: TokenType,
        amount: u64, 
        reason: String,
        demand_score: f64,
    },
    /// No action (balanced demand)
    None { demand_score: f64 },
}

/// Algorithmic USD Peg Mechanism (No External Price Feeds)
pub struct AlgorithmicPeg {
    config: AlgorithmicPegConfig,
    
    // Activity tracking
    activity_history: VecDeque<BlockActivity>,
    
    // Supply tracking
    current_dinari_supply: u64,
    current_africoin_supply: u64,
    total_expanded_dinari: u64,
    total_contracted_dinari: u64,
    total_expanded_africoin: u64,
    total_contracted_africoin: u64,
    
    // Algorithm state
    stability_wallet: Option<Wallet>,
    pending_actions: Vec<SupplyAction>,
    
    // Performance metrics
    blocks_processed: u64,
    last_action_block: u64,
}

impl AlgorithmicPeg {
    /// Create new algorithmic peg mechanism
    pub fn new(config: AlgorithmicPegConfig) -> Self {
        Self {
            current_dinari_supply: config.base_supply,
            current_africoin_supply: config.base_supply,
            config,
            activity_history: VecDeque::new(),
            total_expanded_dinari: 0,
            total_contracted_dinari: 0,
            total_expanded_africoin: 0,
            total_contracted_africoin: 0,
            stability_wallet: None,
            pending_actions: Vec::new(),
            blocks_processed: 0,
            last_action_block: 0,
        }
    }

    /// Set treasury wallet for supply operations
    pub fn set_stability_wallet(&mut self, wallet: Wallet) -> Result<()> {
        self.config.stability_fund_address = wallet.address().to_string();
        self.stability_wallet = Some(wallet);
        info!("Algorithmic peg treasury set: {}", self.config.stability_fund_address);
        Ok(())
    }

    /// Process new block and adjust supply if needed
    pub fn process_block(&mut self, block: &Block) -> Result<()> {
        // Calculate block activity metrics
        let activity = self.calculate_block_activity(block);
        
        // Add to history
        self.activity_history.push_back(activity);
        
        // Keep only recent history
        while self.activity_history.len() > self.config.activity_window_blocks {
            self.activity_history.pop_front();
        }
        
        // Calculate demand and determine action
        let demand_score = self.calculate_demand_score();
        let action = self.determine_supply_action(demand_score);
        
        if !matches!(action, SupplyAction::None { .. }) {
            info!("Supply action determined: {:?}", action);
            self.pending_actions.push(action);
            self.last_action_block = block.header.block_number;
        }
        
        self.blocks_processed += 1;
        Ok(())
    }

    /// Calculate activity metrics for a block
    fn calculate_block_activity(&self, block: &Block) -> BlockActivity {
        let mut dinari_volume = 0u64;
        let mut africoin_volume = 0u64; 
        let mut total_gas_fees = 0u64;
        let mut unique_addresses = std::collections::HashSet::new();
        
        for tx in &block.transactions {
            // Track volumes
            match tx.token_type {
                TokenType::DINARI => dinari_volume += tx.amount,
                TokenType::AFRICOIN => africoin_volume += tx.amount,
            }
            
            // Track gas fees
            total_gas_fees += tx.gas_fee;
            
            // Track unique addresses
            unique_addresses.insert(tx.from.clone());
            unique_addresses.insert(tx.to.clone());
        }
        
        BlockActivity {
            block_number: block.header.block_number,
            timestamp: block.header.timestamp,
            transaction_count: block.transactions.len(),
            total_gas_fees,
            dinari_volume,
            africoin_volume,
            unique_addresses: unique_addresses.len(),
        }
    }

    /// Calculate demand score based on recent activity
    fn calculate_demand_score(&self) -> f64 {
        if self.activity_history.is_empty() {
            return 0.0;
        }

        let recent_blocks = self.activity_history.len().min(20); // Last 20 blocks
        let recent_activity: Vec<_> = self.activity_history.iter().rev().take(recent_blocks).collect();
        
        // Calculate various demand indicators
        let avg_txs_per_block: f64 = recent_activity.iter()
            .map(|a| a.transaction_count as f64)
            .sum::<f64>() / recent_activity.len() as f64;
            
        let avg_gas_per_block: f64 = recent_activity.iter()
            .map(|a| a.total_gas_fees as f64)
            .sum::<f64>() / recent_activity.len() as f64;
            
        let avg_volume_per_block: f64 = recent_activity.iter()
            .map(|a| (a.dinari_volume + a.africoin_volume) as f64)
            .sum::<f64>() / recent_activity.len() as f64;
            
        let avg_unique_addresses: f64 = recent_activity.iter()
            .map(|a| a.unique_addresses as f64)
            .sum::<f64>() / recent_activity.len() as f64;

        // Weighted composite demand score
        let demand_score = 
            (avg_txs_per_block * 0.4) +           // 40% weight on transaction count
            (avg_gas_per_block / 100.0 * 0.3) +   // 30% weight on gas fees  
            (avg_volume_per_block / 10000.0 * 0.2) + // 20% weight on volume
            (avg_unique_addresses * 0.1);         // 10% weight on unique users

        debug!("Demand score: {:.2} (txs: {:.1}, gas: {:.0}, vol: {:.0}, users: {:.1})", 
               demand_score, avg_txs_per_block, avg_gas_per_block, avg_volume_per_block, avg_unique_addresses);
        
        demand_score
    }

    /// Determine what supply action to take based on demand
    fn determine_supply_action(&self, demand_score: f64) -> SupplyAction {
        // Prevent too frequent actions (minimum 10 blocks between actions)
        if self.blocks_processed - self.last_action_block < 10 {
            return SupplyAction::None { demand_score };
        }

        if demand_score > self.config.high_activity_threshold {
            // High demand -> Expand supply to prevent price rising above $1
            let expansion_amount = self.calculate_expansion_amount(demand_score);
            
            // Alternate between tokens or expand both
            let token = if self.total_expanded_dinari <= self.total_expanded_africoin {
                TokenType::DINARI
            } else {
                TokenType::AFRICOIN  
            };

            SupplyAction::Expand {
                token,
                amount: expansion_amount,
                reason: format!("High demand detected: score {:.2}", demand_score),
                demand_score,
            }
        } else if demand_score < self.config.low_activity_threshold {
            // Low demand -> Contract supply to prevent price falling below $1
            let contraction_amount = self.calculate_contraction_amount(demand_score);
            
            // Contract token with higher supply first
            let token = if self.current_dinari_supply > self.current_africoin_supply {
                TokenType::DINARI
            } else {
                TokenType::AFRICOIN
            };

            SupplyAction::Contract {
                token,
                amount: contraction_amount,
                reason: format!("Low demand detected: score {:.2}", demand_score),
                demand_score,
            }
        } else {
            // Balanced demand -> No action needed
            SupplyAction::None { demand_score }
        }
    }

    /// Calculate expansion amount based on demand intensity
    fn calculate_expansion_amount(&self, demand_score: f64) -> u64 {
        // More demand = more expansion
        let intensity = (demand_score - self.config.high_activity_threshold) / self.config.high_activity_threshold;
        let base_expansion = (intensity * 50_000.0) as u64; // Base calculation
        
        base_expansion.min(self.config.max_expansion_per_block).max(10_000)
    }

    /// Calculate contraction amount based on low demand
    fn calculate_contraction_amount(&self, demand_score: f64) -> u64 {
        // Less demand = more contraction
        let intensity = (self.config.low_activity_threshold - demand_score) / self.config.low_activity_threshold;
        let base_contraction = (intensity * 25_000.0) as u64; // More conservative
        
        base_contraction.min(self.config.max_contraction_per_block).max(5_000)
    }

    /// Execute pending supply actions - FIXED BORROWING ISSUE COMPLETELY
    pub fn execute_supply_actions(&mut self, account_manager: &mut AccountManager) -> Result<Vec<Transaction>> {
        let mut transactions = Vec::new();

        for action in &self.pending_actions {
            match action {
                SupplyAction::Expand { token, amount, reason, .. } => {
                    info!("Expanding supply: {} {} - {}", amount, token, reason);
                    
                    // FIXED: Separate the account operations completely
                    // Step 1: Create or get the account and modify its balance
                    {
                        let treasury_account = account_manager.get_or_create_account(&self.config.stability_fund_address)?;
                        treasury_account.add_balance(token, *amount)?;
                        // treasury_account goes out of scope here, releasing the borrow
                    }
                    // Step 2: Account is automatically updated when reference drops

                    // Update supply tracking
                    match token {
                        TokenType::DINARI => {
                            self.current_dinari_supply += amount;
                            self.total_expanded_dinari += amount;
                        }
                        TokenType::AFRICOIN => {
                            self.current_africoin_supply += amount;
                            self.total_expanded_africoin += amount;
                        }
                    }

                    // Create expansion transaction record
                    let tx = TransactionBuilder::new()
                        .from("DT0000000000000000000000000000000000".to_string()) // Mint address
                        .to(self.config.stability_fund_address.clone())
                        .amount(*amount)
                        .token_type(token.clone())
                        .nonce(0)
                        .gas_fee(0)
                        .build()?;

                    transactions.push(tx);
                }

                SupplyAction::Contract { token, amount, reason, .. } => {
                    info!("Contracting supply: {} {} - {}", amount, token, reason);
                    
                    // FIXED: Check balance and modify in completely separate operations
                    // Step 1: Check if treasury has sufficient balance
                    let has_sufficient_balance = {
                        let treasury_account = account_manager.get_or_create_account(&self.config.stability_fund_address)?;
                        treasury_account.get_balance(token) >= *amount
                        // treasury_account reference drops here
                    };
                    
                    if has_sufficient_balance {
                        // Step 2: Now modify the account in a separate scope
                        {
                            let treasury_account = account_manager.get_or_create_account(&self.config.stability_fund_address)?;
                            treasury_account.subtract_balance(token, *amount)?;
                            // treasury_account goes out of scope here
                        }
                        // Step 3: Account is automatically updated when reference drops

                        // Update supply tracking
                        match token {
                            TokenType::DINARI => {
                                self.current_dinari_supply = self.current_dinari_supply.saturating_sub(*amount);
                                self.total_contracted_dinari += amount;
                            }
                            TokenType::AFRICOIN => {
                                self.current_africoin_supply = self.current_africoin_supply.saturating_sub(*amount);
                                self.total_contracted_africoin += amount;
                            }
                        }

                        // Create contraction transaction record
                        let tx = TransactionBuilder::new()
                            .from(self.config.stability_fund_address.clone())
                            .to("DT0000000000000000000000000000000000".to_string()) // Burn address
                            .amount(*amount)
                            .token_type(token.clone())
                            .nonce(0)
                            .gas_fee(0)
                            .build()?;

                        transactions.push(tx);
                    } else {
                        warn!("Insufficient treasury balance for contraction: need {} {}", amount, token);
                    }
                }

                SupplyAction::None { .. } => {
                    // No action
                }
            }
        }

        // Clear pending actions
        self.pending_actions.clear();
        
        Ok(transactions)
    }

    /// Get current algorithmic peg statistics
    pub fn get_peg_stats(&self) -> AlgorithmicPegStats {
        let current_demand = if !self.activity_history.is_empty() {
            self.calculate_demand_score()
        } else {
            0.0
        };

        AlgorithmicPegStats {
            target_price_usd: self.config.target_price_usd,
            current_dinari_supply: self.current_dinari_supply,
            current_africoin_supply: self.current_africoin_supply,
            total_expanded_dinari: self.total_expanded_dinari,
            total_contracted_dinari: self.total_contracted_dinari,
            total_expanded_africoin: self.total_expanded_africoin,
            total_contracted_africoin: self.total_contracted_africoin,
            current_demand_score: current_demand,
            high_activity_threshold: self.config.high_activity_threshold,
            low_activity_threshold: self.config.low_activity_threshold,
            blocks_processed: self.blocks_processed,
            treasury_address: self.config.stability_fund_address.clone(),
        }
    }
}

/// Algorithmic peg statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmicPegStats {
    pub target_price_usd: f64,
    pub current_dinari_supply: u64,
    pub current_africoin_supply: u64,
    pub total_expanded_dinari: u64,
    pub total_contracted_dinari: u64,
    pub total_expanded_africoin: u64,
    pub total_contracted_africoin: u64,
    pub current_demand_score: f64,
    pub high_activity_threshold: f64,
    pub low_activity_threshold: f64,
    pub blocks_processed: u64,
    pub treasury_address: String,
}

impl std::fmt::Display for AlgorithmicPegStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Algorithmic USD Peg Statistics:")?;
        writeln!(f, "   Target Price: ${:.2} (by definition)", self.target_price_usd)?;
        writeln!(f, "   DINARI Supply: {}", self.current_dinari_supply)?;
        writeln!(f, "   AFRICOIN Supply: {}", self.current_africoin_supply)?;
        writeln!(f, "   Current Demand Score: {:.2}", self.current_demand_score)?;
        
        let demand_status = if self.current_demand_score > self.high_activity_threshold {
            "HIGH (expanding)"
        } else if self.current_demand_score < self.low_activity_threshold {
            "LOW (contracting)"
        } else {
            "BALANCED"
        };
        writeln!(f, "   Demand Status: {}", demand_status)?;
        
        writeln!(f, "   DINARI Expanded: {} | Contracted: {}", 
                self.total_expanded_dinari, self.total_contracted_dinari)?;
        writeln!(f, "   AFRICOIN Expanded: {} | Contracted: {}", 
                self.total_expanded_africoin, self.total_contracted_africoin)?;
        writeln!(f, "   Blocks Processed: {}", self.blocks_processed)?;
        writeln!(f, "   Treasury: {}", self.treasury_address)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block::BlockBuilder, account::AccountManager};

    #[test]
    fn test_algorithmic_peg_creation() {
        let config = AlgorithmicPegConfig::default();
        let peg = AlgorithmicPeg::new(config);
        
        assert_eq!(peg.current_dinari_supply, 1_000_000_000);
        assert_eq!(peg.current_africoin_supply, 1_000_000_000);
    }

    #[test]
    fn test_demand_calculation() {
        let config = AlgorithmicPegConfig::default();
        let mut peg = AlgorithmicPeg::new(config);
        let account_manager = AccountManager::new();
        
        // Create high-activity block
        let high_activity_block = BlockBuilder::new()
            .block_number(1)
            .validator("DTvalidator".to_string())
            .build(&account_manager)
            .unwrap();
            
        peg.process_block(&high_activity_block).unwrap();
        
        // Should have some activity recorded
        assert_eq!(peg.activity_history.len(), 1);
    }

    #[test]
    fn test_supply_expansion() {
        let config = AlgorithmicPegConfig {
            high_activity_threshold: 1.0, // Very low threshold for testing
            ..Default::default()
        };
        let mut peg = AlgorithmicPeg::new(config);
        
        // Set treasury wallet
        let wallet = crate::crypto::Wallet::new();
        peg.set_stability_wallet(wallet).unwrap();
        
        let mut account_manager = AccountManager::new();
        
        // Create high activity scenario
        let demand_score = 60.0; // Above threshold
        let action = peg.determine_supply_action(demand_score);
        
        if let SupplyAction::Expand { amount, .. } = action {
            assert!(amount > 0);
        } else {
            panic!("Expected expansion action");
        }
    }
}