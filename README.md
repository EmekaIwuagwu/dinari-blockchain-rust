# 🌟 DinariBlockchain

A **Proof of Authority (PoA)** blockchain implementation in Rust, featuring dual-token economics and optimized for resource efficiency.

## 🚀 Features

### Core Blockchain
- **Proof of Authority Consensus** - Round-robin validator selection with 15-second block times
- **Dual Token System** - DINARI (gas & governance) + AFRICOIN (payments), both pegged 1:1 to USD
- **Memory Optimized** - Works within 1GB RAM constraint using RocksDB storage
- **Cryptographic Security** - secp256k1 signatures with recoverable public keys

### Developer APIs
- **JSON-RPC Server** - Complete HTTP API for blockchain interaction
- **Transaction Pool** - Smart mempool with fee-based prioritization
- **Account Management** - Real-time balance tracking with nonce-based replay protection
- **Block Validation** - Comprehensive Merkle tree validation

### Address & Transaction Format
- **Addresses**: `DT` prefix with Base58 encoding (e.g., `DTa1b2c3d4e5f6...`)
- **Transactions**: `DTx` prefix with UUID (e.g., `DTxabcdef123456...`)
- **Gas Fees**: Always paid in DINARI, regardless of transfer token

## 📋 Prerequisites

- **Rust 1.70+** - Install from [rustup.rs](https://rustup.rs/)
- **Git** - For cloning the repository

## 🛠️ Installation & Build

### 1. Create New Project
```bash
cargo new dinari_blockchain --bin
cd dinari_blockchain
```

### 2. Setup Cargo.toml
Replace the contents of `Cargo.toml` with:

```toml
[package]
name = "dinari_blockchain"
version = "0.1.0"
edition = "2021"

[dependencies]
# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
bincode = "1.3"

# Cryptography
secp256k1 = { version = "0.27", features = ["rand", "recovery"] }
sha2 = "0.10"
rand = "0.8"

# Database
rocksdb = "0.21"

# Network & RPC
tokio = { version = "1.0", features = ["full"] }
hyper = { version = "0.14", features = ["server", "http1", "tcp"] }

# Utilities
uuid = { version = "1.0", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
bs58 = "0.4"
hex = "0.4"
log = "0.4"
env_logger = "0.10"

# Error handling
anyhow = "1.0"
thiserror = "1.0"

[dev-dependencies]
tempfile = "3.0"
tokio-test = "0.4"
```

### 3. Create Source Files
```bash
# Create all source files
touch src/lib.rs src/block.rs src/transaction.rs src/account.rs src/consensus.rs src/database.rs src/crypto.rs src/mempool.rs src/rpc.rs src/utils.rs

# Create directories
mkdir -p data config
```

### 4. Copy Module Code
Copy all the provided code for each module:
- `src/utils.rs` - Address & transaction utilities
- `src/crypto.rs` - Cryptographic operations
- `src/account.rs` - Account management
- `src/transaction.rs` - Transaction processing
- `src/database.rs` - RocksDB storage
- `src/block.rs` - Block structure & validation
- `src/mempool.rs` - Transaction pool
- `src/consensus.rs` - PoA consensus engine
- `src/rpc.rs` - JSON-RPC server
- `src/lib.rs` - Library exports
- `src/main.rs` - Main application

### 5. Build & Test
```bash
# Build project
cargo build --release

# Run tests
cargo test

# Check compilation
cargo check
```

## 🚀 Quick Start

### 1. Generate Validator Wallet
```bash
# Generate a new validator wallet
cargo run -- wallet generate

# Output:
# Generated new wallet:
# Address: DTxyz123abc456def789...
# Private Key: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
# ⚠️  Keep your private key secure!
```

### 2. Start Validator Node
```bash
# Start as validator (replace with your private key)
DINARI_VALIDATOR_KEY="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" \
cargo run --release

# Output:
# ████████████████████████████████████████
# ██          DINARI BLOCKCHAIN          ██
# ██         v0.1.0 - Rust PoA           ██
# ████████████████████████████████████████
# 🚀 Starting DinariBlockchain Node...
# 📋 DinariBlockchain Node Configuration:
#    Database Path: ./data/dinari_chain.db
#    RPC Server: 127.0.0.1:3030
#    Validator: Yes
# ✅ DinariBlockchain Node started successfully!
```

### 3. Start Regular Node (Non-Validator)
```bash
# Start without validator key
cargo run --release

# Custom configuration
DINARI_RPC_PORT=8080 \
DINARI_BLOCK_TIME=10 \
DINARI_LOG_LEVEL=debug \
cargo run --release
```

## 🌐 JSON-RPC API

The blockchain exposes a JSON-RPC 2.0 API on `http://localhost:3030` (configurable).

### Send Transaction
```bash
curl -X POST http://localhost:3030 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sendTransaction",
    "params": {
      "from": "DTsender123...",
      "to": "DTrecipient456...",
      "amount": "1000",
      "token_type": "DINARI",
      "gas_fee": "10",
      "signature": "abcd1234567890..."
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "tx_id": "DTxabcdef123456...",
    "status": "pending",
    "message": "Transaction added to mempool"
  },
  "id": 1
}
```

### Get Balance
```bash
curl -X POST http://localhost:3030 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getBalance",
    "params": {
      "address": "DTabc123def456..."
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": "DTabc123def456...",
    "dinari_balance": "1000000",
    "africoin_balance": "500000",
    "nonce": 42
  },
  "id": 1
}
```

### Get Block
```bash
curl -X POST http://localhost:3030 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getBlock", 
    "params": {
      "block_number": 1
    },
    "id": 1
  }'
```

### Get Chain Info
```bash
curl -X POST http://localhost:3030 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getChainInfo",
    "params": {},
    "id": 1
  }'
```

## ⚙️ Configuration

Configure the node using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DINARI_DB_PATH` | Database path | `./data/dinari_chain.db` |
| `DINARI_RPC_HOST` | RPC server host | `127.0.0.1` |
| `DINARI_RPC_PORT` | RPC server port | `3030` |
| `DINARI_VALIDATOR_KEY` | Validator private key (hex) | None |
| `DINARI_BLOCK_TIME` | Block time in seconds | `15` |
| `DINARI_ENABLE_RPC` | Enable RPC server | `true` |
| `DINARI_LOG_LEVEL` | Log level (error/warn/info/debug) | `info` |

### Example Configurations

**Validator Node:**
```bash
DINARI_VALIDATOR_KEY="abcd1234..." \
DINARI_BLOCK_TIME=10 \
cargo run --release
```

**Custom RPC Port:**
```bash
DINARI_RPC_PORT=8080 \
DINARI_RPC_HOST=0.0.0.0 \
cargo run --release
```

**Debug Mode:**
```bash
DINARI_LOG_LEVEL=debug \
cargo run --release
```

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│         JSON-RPC Server             │
│    (sendTransaction, getBalance)    │
├─────────────────────────────────────┤
│           Mempool                   │
│     (Transaction Queue & Pool)      │
├─────────────────────────────────────┤
│         PoA Consensus               │
│   (Round-Robin Block Production)    │
├─────────────────────────────────────┤
│       Account Manager               │
│  (DINARI & AFRICOIN Balances)      │
├─────────────────────────────────────┤
│       RocksDB Database              │
│  (Blocks, Transactions, Accounts)   │
└─────────────────────────────────────┘
```

## 💰 Token Economics

### DINARI Token
- **Purpose**: Gas fees, validator rewards, governance
- **Peg**: 1 DINARI = 1 USD
- **Supply**: Genesis 1B + validator rewards
- **Usage**: Required for all transaction gas fees

### AFRICOIN Token  
- **Purpose**: Stable payments and transfers
- **Peg**: 1 AFRICOIN = 1 USD
- **Supply**: Genesis 1B
- **Gas**: Uses DINARI for transaction fees

### Gas Fee Model
- **DINARI transfers**: Amount + gas both from DINARI balance
- **AFRICOIN transfers**: Amount from AFRICOIN, gas from DINARI
- **Minimum gas**: 1 DINARI unit
- **Fee replacement**: 10% higher fee for transaction replacement

## 🔒 Security Features

- **secp256k1 Signatures** - Same cryptography as Bitcoin
- **Address Validation** - Base58 encoding with checksum
- **Nonce Protection** - Prevents replay attacks
- **Validator Authority** - Only authorized validators can produce blocks
- **Merkle Tree Validation** - Transaction and state integrity
- **Balance Verification** - Real-time balance and fee validation

## 🧪 Development & Testing

### Run Tests
```bash
# Run all tests
cargo test

# Run specific module tests
cargo test crypto
cargo test mempool
cargo test consensus

# Run with output
cargo test -- --nocapture
```

### Example Transaction Flow

1. **Create Transaction**
```rust
use dinari_blockchain::*;

let wallet = Wallet::new();
let tx = TransactionBuilder::new()
    .from(wallet.address().to_string())
    .to("DTrecipient123...".to_string())
    .amount(1000)
    .token_type(TokenType::DINARI)
    .nonce(1)
    .gas_fee(10)
    .build()?;
```

2. **Sign Transaction**
```rust
let crypto = CryptoEngine::new();
tx.sign(&crypto, wallet.secret_key())?;
```

3. **Submit via RPC**
```bash
curl -X POST http://localhost:3030 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "sendTransaction", "params": {...}, "id": 1}'
```

## 📊 Performance

- **Block Time**: 15 seconds (configurable)
- **TPS**: ~66 transactions/second (1000 tx/block ÷ 15s)
- **Memory Usage**: <1GB RAM (RocksDB on disk)
- **Storage**: Efficient with LZ4 compression
- **Consensus**: O(1) validator selection (round-robin)

## 🛠️ Troubleshooting

### Common Issues

**Port already in use:**
```bash
DINARI_RPC_PORT=8080 cargo run --release
```

**Database permission error:**
```bash
mkdir -p data
chmod 755 data
```

**Validator key format error:**
- Ensure 64-character hex string (32 bytes)
- Use lowercase hex characters

### Debug Mode
```bash
DINARI_LOG_LEVEL=debug cargo run --release
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **secp256k1** cryptography library
- **RocksDB** high-performance database
- **Tokio** async runtime
- **Hyper** HTTP server

---

**DinariBlockchain v0.1.0** - Built with 🦀 Rust