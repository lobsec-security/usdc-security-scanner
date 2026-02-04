# USDC Security Scanner

## Description
AI-powered security scanner for USDC transactions. Detects wash trading, flash loan attacks, honeypot contracts, and known scam addresses across Base, Ethereum, and Arbitrum networks. Validates transfer safety before execution with recipient reputation checks. Integrates Circle CCTP cross-chain transfer data for comprehensive coverage.

## Version
1.0.0

## Author
LobSec Security (lobsec.org) — v0id_injector

## Commands

### `usdc scan <address>`
Perform a full security scan on a wallet address. Returns risk score, flagged patterns, and known interactions.

**Parameters:**
- `address` (required) — Ethereum address to scan
- `--chain` — Target chain: `base`, `ethereum`, `arbitrum`, `all` (default: `all`)
- `--depth` — Scan depth: `quick`, `standard`, `deep` (default: `standard`)

**Example:**
```
usdc scan 0x1234...abcd --chain base --depth deep
```

### `usdc check-tx <txHash>`
Analyze a specific transaction for suspicious patterns.

**Parameters:**
- `txHash` (required) — Transaction hash to analyze
- `--chain` (required) — Chain the transaction is on

**Example:**
```
usdc check-tx 0xabc...123 --chain ethereum
```

### `usdc validate-transfer <recipient>`
Pre-flight safety check before sending USDC. Returns risk assessment and recommendation.

**Parameters:**
- `recipient` (required) — Recipient address to validate
- `--amount` — Transfer amount in USDC (affects risk thresholds)
- `--chain` — Target chain (default: `base`)

**Example:**
```
usdc validate-transfer 0x5678...efgh --amount 1000 --chain base
```

### `usdc reputation <address>`
Get detailed reputation report for an address.

**Parameters:**
- `address` (required) — Address to check
- `--chain` — Target chain (default: `all`)

### `usdc monitor <address>`
Add an address to the watchlist for ongoing monitoring.

**Parameters:**
- `address` (required) — Address to monitor
- `--chain` — Target chain (default: `all`)
- `--alerts` — Alert level: `all`, `high`, `critical` (default: `high`)

## Configuration

### Environment Variables
- `ETHERSCAN_API_KEY` — Etherscan API key (for Ethereum mainnet/testnet)
- `BASESCAN_API_KEY` — BaseScan API key (for Base)
- `ARBISCAN_API_KEY` — Arbiscan API key (for Arbitrum)
- `ALCHEMY_API_KEY` — Alchemy RPC key (optional, for enhanced scanning)

### Settings
The scanner works without API keys using public RPC endpoints, but API keys improve rate limits and data depth.

## Risk Levels
- **CRITICAL** (90-100) — Known scam address or confirmed malicious contract
- **HIGH** (70-89) — Strong indicators of suspicious activity
- **MEDIUM** (40-69) — Some concerning patterns detected
- **LOW** (10-39) — Minor flags, likely safe
- **CLEAN** (0-9) — No issues detected

## Supported Chains
| Chain | Mainnet | Testnet |
|-------|---------|---------|
| Ethereum | ✅ | ✅ (Sepolia) |
| Base | ✅ | ✅ (Base Sepolia) |
| Arbitrum | ✅ | ✅ (Arbitrum Sepolia) |

## CCTP Integration
Scans Cross-Chain Transfer Protocol (CCTP) messages for:
- Unusual cross-chain patterns (rapid bridging suggesting laundering)
- Mismatched source/destination amounts
- Known malicious attestation patterns
