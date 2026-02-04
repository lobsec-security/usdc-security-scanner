# USDC Security Scanner

**AI-powered transaction security for USDC operations.** Scans addresses, detects scam patterns, validates transfers before execution.

Built by [LobSec](https://lobsec.org) — AI Security for the Agent Economy.

## Features

- **Address Reputation Check** — 200+ known scam addresses, freshness detection, contract analysis
- **Transaction Pattern Detection** — Wash trading, flash loan attacks, circular flows, approval abuse
- **Honeypot Contract Analysis** — Bytecode scanning, proxy detection, owner privilege checks
- **CCTP Security** — Cross-chain transfer validation via Circle's Cross-Chain Transfer Protocol
- **Multi-Chain Support** — Ethereum, Base, Arbitrum (mainnet + Sepolia testnets)
- **Risk Scoring** — 0-100 risk score with detailed breakdown per address

## Install

```bash
npx clawhub install lobsec-security/usdc-security-scanner
```

## Quick Start

```javascript
const Scanner = require('@lobsec/usdc-security-scanner');

const scanner = new Scanner({ chain: 'base' });

// Check if an address is safe before sending USDC
const result = await scanner.validateTransfer('0x742d...', 500);
console.log(result.safe);       // true/false
console.log(result.riskScore);  // 0-100
console.log(result.flags);     // ['known_scam', 'honeypot', etc.]

// Full address analysis
const report = await scanner.analyzeAddress('0x...');

// Scan transaction patterns
const patterns = await scanner.detectPatterns('0x...', { depth: 50 });
```

## API

### `scanner.validateTransfer(address, amount, options)`
Pre-transfer safety check. Returns risk assessment before USDC moves.

### `scanner.analyzeAddress(address)`
Full address reputation report — scam list check, contract analysis, activity patterns.

### `scanner.detectPatterns(address, options)`
Transaction pattern analysis — wash trading, flash loans, circular flows.

### `scanner.checkContract(address)`
Smart contract security check — proxy detection, owner privileges, pause capabilities.

### `scanner.getThreatFeed(options)`
Real-time threat intelligence feed — newly flagged addresses, cross-chain alerts.

## Architecture

```
Input → Address Blocklist (200+ scams)
      → Bytecode Analysis (honeypot detection)
      → Transaction Pattern Scan
      → Contract Privilege Analysis
      → On-chain Age/Activity Check
      → CCTP Cross-Chain Validation
      → Risk Score Aggregation → SAFE / WARN / BLOCK
```

## Data Sources

- Scam address database (curated from real exploit incidents)
- Known malicious contract patterns
- Flash loan attack signatures
- CCTP message validation

## Testing

```bash
npm test
```

## Stats

- 502 lines core scanner
- 6 specialized analysis modules
- 200+ known scam addresses
- 60+ detection patterns
- Full test suite

## License

MIT

## Links

- 🌐 [lobsec.org](https://lobsec.org)
- 🛡️ [AgentShield API](https://agentshield.lobsec.org)
- 🐦 [@lobsec](https://x.com/lobsec)
- 📊 [ClawHub Scanner Report](https://github.com/lobsec-security/clawhub-scanner)

---

**Built by v0id_injector for the USDC Hackathon 2026**
