'use strict';

const { RpcClient } = require('./lib/rpc');
const { AddressChecker } = require('./lib/address-checker');
const { PatternDetector } = require('./lib/pattern-detector');
const { CCTPAnalyzer } = require('./lib/cctp-analyzer');
const { ReportGenerator } = require('./lib/report');
const { SUPPORTED_CHAINS, THRESHOLDS, RISK_LEVELS } = require('./lib/constants');

/**
 * USDCSecurityScanner — Main entry point for the LobSec USDC Security Scanner.
 * 
 * Provides comprehensive security scanning for USDC transactions across
 * Ethereum, Base, and Arbitrum networks. Detects wash trading, flash loan
 * attacks, honeypot contracts, scam addresses, and suspicious cross-chain
 * patterns via Circle's CCTP.
 * 
 * Zero external dependencies. Production-ready. Built for the agent economy.
 * 
 * @example
 *   const scanner = new USDCSecurityScanner();
 *   const report = await scanner.scanAddress('0x1234...');
 *   console.log(report.formatted);
 * 
 * @author LobSec Security (lobsec.org)
 */
class USDCSecurityScanner {
  /**
   * @param {Object} options
   * @param {boolean} [options.testnet=false] — Use testnet RPCs
   * @param {string} [options.alchemyKey] — Alchemy API key for enhanced RPC
   * @param {number} [options.rateLimitDelay=250] — Delay between RPC calls (ms)
   */
  constructor(options = {}) {
    this.rpc = new RpcClient({
      testnet: options.testnet ?? false,
      alchemyKey: options.alchemyKey,
      rateLimitDelay: options.rateLimitDelay ?? 250,
    });
    
    this.addressChecker = new AddressChecker(this.rpc);
    this.patternDetector = new PatternDetector(this.rpc);
    this.cctpAnalyzer = new CCTPAnalyzer(this.rpc);
    this.options = options;
  }

  /**
   * Full security scan of a wallet address.
   * 
   * @param {string} address — Ethereum address to scan
   * @param {Object} options
   * @param {string|string[]} [options.chains='all'] — Chain(s) to scan
   * @param {string} [options.depth='standard'] — Scan depth: quick|standard|deep
   * @returns {Object} Scan result with risk score, patterns, and formatted report
   */
  async scanAddress(address, options = {}) {
    this._validateAddress(address);
    
    const chains = this._resolveChains(options.chains || 'all');
    const depth = options.depth || 'standard';
    
    const result = {
      address: address.toLowerCase(),
      chains: {},
      patterns: [],
      cctpAnalysis: null,
      reputation: null,
      overallScore: 0,
      level: 'CLEAN',
      scannedAt: new Date().toISOString(),
      scanDepth: depth,
    };

    // 1. Get reputation (includes scam DB check + on-chain profile)
    result.reputation = await this.addressChecker.getReputation(address, chains);
    result.overallScore = result.reputation.overallScore;
    result.chains = result.reputation.chains;

    // 2. Pattern detection (standard + deep)
    if (depth !== 'quick') {
      const patternResults = await Promise.allSettled(
        chains.map(async chain => {
          const transfers = await this.rpc.getUSDCTransfers(chain, address).catch(() => []);
          if (transfers.length === 0) return null;
          return this.patternDetector.analyzePatterns(address, chain, transfers);
        })
      );

      for (const pr of patternResults) {
        if (pr.status === 'fulfilled' && pr.value) {
          result.patterns.push(...pr.value.patterns);
        }
      }

      // Add pattern risk to overall score
      const patternRisk = result.patterns.reduce((sum, p) => sum + p.riskImpact, 0);
      result.overallScore = Math.min(100, result.overallScore + patternRisk);
    }

    // 3. CCTP analysis (deep only)
    if (depth === 'deep') {
      result.cctpAnalysis = await this.cctpAnalyzer.analyzeCrossChainActivity(address, chains);
      
      if (result.cctpAnalysis.riskFactors.length > 0) {
        const cctpRisk = result.cctpAnalysis.riskFactors.reduce((sum, f) => sum + f.impact, 0);
        result.overallScore = Math.min(100, result.overallScore + cctpRisk);
      }
    }

    // 4. Determine final risk level
    result.level = this._scoreToLevel(result.overallScore);

    // 5. Generate formatted report
    result.formatted = ReportGenerator.formatScanReport(result);
    result.json = ReportGenerator.toJSON(result);

    return result;
  }

  /**
   * Analyze a specific transaction for security concerns.
   * 
   * @param {string} txHash — Transaction hash
   * @param {string} chain — Chain name
   * @returns {Object} Transaction analysis
   */
  async checkTransaction(txHash, chain) {
    if (!SUPPORTED_CHAINS.includes(chain)) {
      throw new Error(`Unsupported chain: ${chain}. Supported: ${SUPPORTED_CHAINS.join(', ')}`);
    }

    // Analyze the transaction
    const txAnalysis = await this.patternDetector.analyzeTransaction(chain, txHash);
    
    // Check involved addresses against scam DB
    if (txAnalysis.details.involvedAddresses) {
      txAnalysis.scamMatches = [];
      for (const addr of txAnalysis.details.involvedAddresses) {
        const match = this.addressChecker.checkScamDatabase(addr);
        if (match) {
          txAnalysis.scamMatches.push({ address: addr, ...match });
          txAnalysis.riskScore += match.riskScore;
          txAnalysis.flags.push(`INTERACTS_WITH_${match.category.toUpperCase()}`);
        }
      }
    }

    // Check if CCTP transaction
    const cctpCheck = await this.cctpAnalyzer.analyzeCCTPTransfer(chain, txHash);
    if (cctpCheck.isCCTP) {
      txAnalysis.cctp = cctpCheck;
      txAnalysis.flags.push('CCTP_TRANSACTION');
    }

    txAnalysis.riskScore = Math.min(100, txAnalysis.riskScore);
    txAnalysis.level = this._scoreToLevel(txAnalysis.riskScore);

    return txAnalysis;
  }

  /**
   * Validate whether a USDC transfer to a recipient is safe.
   * Pre-flight check before sending funds.
   * 
   * @param {string} recipient — Recipient address
   * @param {Object} options
   * @param {number} [options.amount] — Transfer amount in USDC
   * @param {string} [options.chain='base'] — Target chain
   * @returns {Object} Validation result with safety recommendation
   */
  async validateTransfer(recipient, options = {}) {
    this._validateAddress(recipient);
    
    const chain = options.chain || 'base';
    const amount = options.amount || 0;

    const validation = {
      recipient: recipient.toLowerCase(),
      chain,
      amount,
      overallScore: 0,
      level: 'CLEAN',
      safe: true,
      flags: [],
      scamMatch: null,
      recommendation: '',
      checks: [],
    };

    // Check 1: Scam database
    const scamMatch = this.addressChecker.checkScamDatabase(recipient);
    if (scamMatch) {
      validation.scamMatch = scamMatch;
      validation.overallScore = scamMatch.riskScore;
      validation.safe = false;
      validation.flags.push(`KNOWN_${scamMatch.category.toUpperCase()}`);
      validation.checks.push({
        check: 'Scam Database',
        result: 'FAIL',
        detail: `Known ${scamMatch.category}: ${scamMatch.label}`,
      });
    } else {
      validation.checks.push({
        check: 'Scam Database',
        result: 'PASS',
        detail: 'Not found in known scam address database',
      });
    }

    // Check 2: Address profile
    try {
      const profile = await this.addressChecker.analyzeAddressProfile(recipient, chain);
      validation.profile = profile;

      for (const rf of profile.riskFactors) {
        validation.overallScore = Math.min(100, validation.overallScore + rf.impact);
      }
      validation.flags.push(...profile.flags);

      validation.checks.push({
        check: 'Address Profile',
        result: profile.flags.length > 0 ? 'WARN' : 'PASS',
        detail: profile.flags.length > 0 
          ? `Flags: ${profile.flags.join(', ')}` 
          : `${profile.txCount} transactions, ${profile.isContract ? 'contract' : 'EOA'}`,
      });

      // Check 3: Zero address / burn address
      if (recipient.toLowerCase() === '0x0000000000000000000000000000000000000000' ||
          recipient.toLowerCase() === '0x000000000000000000000000000000000000dead') {
        validation.overallScore = 100;
        validation.safe = false;
        validation.flags.push('BURN_ADDRESS');
        validation.checks.push({
          check: 'Burn Address',
          result: 'FAIL',
          detail: 'This is a burn address. Funds sent here are permanently lost.',
        });
      }

    } catch (err) {
      validation.checks.push({
        check: 'Address Profile',
        result: 'ERROR',
        detail: `Failed to analyze: ${err.message}`,
      });
    }

    // Check 4: Large transfer enhanced verification
    if (amount >= THRESHOLDS.LARGE_TRANSFER_USDC) {
      validation.flags.push('LARGE_TRANSFER');
      validation.checks.push({
        check: 'Large Transfer',
        result: 'WARN',
        detail: `Transfer amount ($${amount.toLocaleString()}) exceeds $${THRESHOLDS.LARGE_TRANSFER_USDC.toLocaleString()} threshold — enhanced verification recommended`,
      });

      // For large transfers, check scam interactions too
      try {
        const interactions = await this.addressChecker.checkScamInteractions(recipient, chain);
        if (interactions.length > 0) {
          validation.overallScore = Math.min(100, validation.overallScore + 30);
          validation.flags.push('SCAM_INTERACTIONS');
          validation.safe = false;
          validation.checks.push({
            check: 'Scam Interactions',
            result: 'FAIL',
            detail: `Recipient has interacted with ${interactions.length} known scam address(es)`,
          });
        }
      } catch {}
    }

    // Determine final safety
    validation.overallScore = Math.min(100, validation.overallScore);
    validation.level = this._scoreToLevel(validation.overallScore);
    
    if (validation.overallScore >= 70) {
      validation.safe = false;
    }

    // Generate recommendation
    if (!validation.safe) {
      if (validation.scamMatch) {
        validation.recommendation = `⛔ DO NOT SEND. Recipient is identified as: ${validation.scamMatch.label}. ${validation.scamMatch.details}`;
      } else {
        validation.recommendation = `🔴 HIGH RISK transfer. Multiple concerning indicators detected. Verify the recipient address through an independent channel before proceeding.`;
      }
    } else if (validation.overallScore >= 40) {
      validation.recommendation = `🟠 PROCEED WITH CAUTION. Some risk indicators present. Double-check the recipient address.`;
    } else if (validation.overallScore >= 10) {
      validation.recommendation = `🟡 LOW RISK. Minor flags detected but transfer appears generally safe.`;
    } else {
      validation.recommendation = `✅ Transfer appears safe. No concerning patterns detected for the recipient.`;
    }

    validation.formatted = ReportGenerator.formatTransferValidation(validation);

    return validation;
  }

  /**
   * Get detailed reputation report for an address.
   * 
   * @param {string} address — Address to check
   * @param {Object} options
   * @param {string|string[]} [options.chains='all'] — Chain(s) to check
   * @returns {Object} Reputation report
   */
  async getReputation(address, options = {}) {
    this._validateAddress(address);
    const chains = this._resolveChains(options.chains || 'all');
    
    const reputation = await this.addressChecker.getReputation(address, chains);
    reputation.formatted = ReportGenerator.formatReputationReport(reputation);
    
    return reputation;
  }

  /**
   * Check if a contract is a honeypot.
   * 
   * @param {string} address — Contract address
   * @param {string} chain — Chain name
   * @returns {Object} Honeypot analysis
   */
  async checkHoneypot(address, chain = 'base') {
    this._validateAddress(address);
    return this.patternDetector.detectHoneypot(address, chain);
  }

  /**
   * Quick check — just scam database lookup (instant, no RPC).
   * 
   * @param {string} address — Address to check
   * @returns {Object|null} Scam info if found, null if clean
   */
  quickCheck(address) {
    this._validateAddress(address);
    return this.addressChecker.checkScamDatabase(address);
  }

  /**
   * Batch check multiple addresses (efficient for agent workflows).
   * 
   * @param {string[]} addresses — Array of addresses to check
   * @returns {Object[]} Array of quick check results
   */
  batchQuickCheck(addresses) {
    return addresses.map(addr => ({
      address: addr.toLowerCase(),
      result: this.quickCheck(addr),
    }));
  }

  /**
   * Get CCTP domain information for a chain.
   * 
   * @param {string} chain — Chain name
   * @returns {Object} CCTP domain info
   */
  getCCTPInfo(chain) {
    return this.cctpAnalyzer.getDomainInfo(chain);
  }

  /**
   * Reload the scam address database (hot-reload for updates).
   */
  reloadDatabase() {
    this.addressChecker.reload();
  }

  // ─── Internal Helpers ───

  _validateAddress(address) {
    if (!address || typeof address !== 'string') {
      throw new Error('Address is required and must be a string');
    }
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
      throw new Error(`Invalid Ethereum address: ${address}`);
    }
  }

  _resolveChains(chains) {
    if (chains === 'all') return [...SUPPORTED_CHAINS];
    if (typeof chains === 'string') return [chains];
    if (Array.isArray(chains)) return chains.filter(c => SUPPORTED_CHAINS.includes(c));
    return [...SUPPORTED_CHAINS];
  }

  _scoreToLevel(score) {
    if (score >= 90) return 'CRITICAL';
    if (score >= 70) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    if (score >= 10) return 'LOW';
    return 'CLEAN';
  }
}

// ─── CLI Entry Point ───

if (require.main === module) {
  const args = process.argv.slice(2);
  const command = args[0];
  const target = args[1];

  if (!command) {
    console.log(`
LobSec USDC Security Scanner v1.0.0
Usage:
  node index.js scan <address> [--chain <chain>] [--depth <depth>]
  node index.js check-tx <txHash> --chain <chain>
  node index.js validate <recipient> [--amount <usdc>] [--chain <chain>]
  node index.js reputation <address> [--chain <chain>]
  node index.js quick <address>
  node index.js honeypot <address> [--chain <chain>]

Chains: ethereum, base, arbitrum, all (default: all)
Depths: quick, standard, deep (default: standard)
`);
    process.exit(0);
  }

  function getFlag(flag) {
    const idx = args.indexOf(flag);
    return idx !== -1 && args[idx + 1] ? args[idx + 1] : null;
  }

  const scanner = new USDCSecurityScanner({
    testnet: args.includes('--testnet'),
    alchemyKey: process.env.ALCHEMY_API_KEY,
  });

  (async () => {
    try {
      switch (command) {
        case 'scan': {
          if (!target) throw new Error('Address required');
          const result = await scanner.scanAddress(target, {
            chains: getFlag('--chain') || 'all',
            depth: getFlag('--depth') || 'standard',
          });
          console.log(result.formatted);
          break;
        }
        case 'check-tx': {
          if (!target) throw new Error('Transaction hash required');
          const chain = getFlag('--chain');
          if (!chain) throw new Error('--chain is required for check-tx');
          const result = await scanner.checkTransaction(target, chain);
          console.log(JSON.stringify(result, null, 2));
          break;
        }
        case 'validate': {
          if (!target) throw new Error('Recipient address required');
          const result = await scanner.validateTransfer(target, {
            amount: parseFloat(getFlag('--amount') || '0'),
            chain: getFlag('--chain') || 'base',
          });
          console.log(result.formatted);
          break;
        }
        case 'reputation': {
          if (!target) throw new Error('Address required');
          const result = await scanner.getReputation(target, {
            chains: getFlag('--chain') || 'all',
          });
          console.log(result.formatted);
          break;
        }
        case 'quick': {
          if (!target) throw new Error('Address required');
          const result = scanner.quickCheck(target);
          if (result) {
            console.log(`🚨 KNOWN THREAT: ${result.label}`);
            console.log(`   Category: ${result.category}`);
            console.log(`   Severity: ${result.severity}`);
            console.log(`   Details: ${result.details}`);
          } else {
            console.log(`✅ Address not found in scam database`);
          }
          break;
        }
        case 'honeypot': {
          if (!target) throw new Error('Address required');
          const chain = getFlag('--chain') || 'base';
          const result = await scanner.checkHoneypot(target, chain);
          console.log(JSON.stringify(result, null, 2));
          break;
        }
        default:
          console.error(`Unknown command: ${command}`);
          process.exit(1);
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  })();
}

module.exports = { USDCSecurityScanner };
