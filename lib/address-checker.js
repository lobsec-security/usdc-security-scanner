'use strict';

const path = require('path');
const fs = require('fs');
const { SEVERITY_WEIGHTS, THRESHOLDS } = require('./constants');

/**
 * Checks addresses against known scam databases and performs
 * on-chain reputation analysis.
 */
class AddressChecker {
  constructor(rpcClient) {
    this.rpc = rpcClient;
    this.scamDb = this._loadScamDatabase();
    this.cache = new Map();
    this.CACHE_TTL = 300000; // 5 minutes
  }

  _loadScamDatabase() {
    const dbPath = path.join(__dirname, '..', 'data', 'scam-addresses.json');
    const raw = fs.readFileSync(dbPath, 'utf8');
    const data = JSON.parse(raw);
    
    // Normalize all addresses to lowercase for matching
    const normalized = {};
    for (const [addr, info] of Object.entries(data.addresses)) {
      normalized[addr.toLowerCase()] = info;
    }
    return normalized;
  }

  /**
   * Reload scam database (for hot-reloading updated lists)
   */
  reload() {
    this.scamDb = this._loadScamDatabase();
    this.cache.clear();
  }

  /**
   * Check if address is in the known scam database
   */
  checkScamDatabase(address) {
    const normalized = address.toLowerCase();
    const entry = this.scamDb[normalized];
    
    if (!entry) return null;

    return {
      isKnownScam: true,
      label: entry.label,
      category: entry.category,
      severity: entry.severity,
      chains: entry.chain,
      details: entry.details,
      reportedAt: entry.reportedAt,
      riskScore: SEVERITY_WEIGHTS[entry.severity] || 50,
    };
  }

  /**
   * Check if address has interacted with any known scam addresses
   */
  async checkScamInteractions(address, chain) {
    const transfers = await this.rpc.getUSDCTransfers(chain, address).catch(() => []);
    const interactions = [];

    for (const tx of transfers) {
      const counterparty = tx.from.toLowerCase() === address.toLowerCase() ? tx.to : tx.from;
      const scamInfo = this.checkScamDatabase(counterparty);
      
      if (scamInfo) {
        interactions.push({
          counterparty,
          txHash: tx.txHash,
          amount: tx.amountUSDC,
          direction: tx.from.toLowerCase() === address.toLowerCase() ? 'sent' : 'received',
          scamInfo,
        });
      }
    }

    return interactions;
  }

  /**
   * Analyze address age and activity patterns
   */
  async analyzeAddressProfile(address, chain) {
    const cacheKey = `profile:${chain}:${address.toLowerCase()}`;
    const cached = this._getCache(cacheKey);
    if (cached) return cached;

    const profile = {
      address: address.toLowerCase(),
      chain,
      isContract: false,
      txCount: 0,
      usdcBalance: '0',
      ethBalance: '0',
      flags: [],
      riskFactors: [],
    };

    try {
      // Check if contract
      profile.isContract = await this.rpc.isContract(chain, address);
      
      // Get transaction count
      profile.txCount = await this.rpc.getTransactionCount(chain, address);
      
      // Get USDC balance
      const rawBalance = await this.rpc.getUSDCBalance(chain, address);
      profile.usdcBalance = rawBalance;
      profile.usdcBalanceFormatted = Number(BigInt(rawBalance)) / 1e6;
      
      // Get ETH balance
      profile.ethBalance = await this.rpc.getBalance(chain, address);
      profile.ethBalanceFormatted = Number(BigInt(profile.ethBalance)) / 1e18;

      // Flag analysis
      if (profile.txCount === 0) {
        profile.flags.push('NEVER_TRANSACTED');
        profile.riskFactors.push({
          factor: 'No transaction history',
          impact: 15,
          detail: 'Address has never sent a transaction. Could be brand new or a fresh scam wallet.',
        });
      }

      if (profile.txCount < 5 && profile.usdcBalanceFormatted > THRESHOLDS.LARGE_TRANSFER_USDC) {
        profile.flags.push('LOW_TX_HIGH_BALANCE');
        profile.riskFactors.push({
          factor: 'Low transactions but high balance',
          impact: 25,
          detail: `Only ${profile.txCount} transactions but holds $${profile.usdcBalanceFormatted.toLocaleString()} USDC`,
        });
      }

      if (profile.isContract) {
        profile.flags.push('IS_CONTRACT');
        // Contracts aren't inherently risky, but worth noting
        profile.riskFactors.push({
          factor: 'Address is a smart contract',
          impact: 5,
          detail: 'Target is a contract. Verify it is the intended contract before interacting.',
        });
      }

      if (profile.ethBalanceFormatted < 0.001 && profile.txCount > 0) {
        profile.flags.push('DUST_ETH');
        profile.riskFactors.push({
          factor: 'Near-zero ETH balance',
          impact: 10,
          detail: 'Very low ETH suggests the wallet may be abandoned or a one-time-use address.',
        });
      }
    } catch (err) {
      profile.flags.push('RPC_ERROR');
      profile.riskFactors.push({
        factor: 'Failed to query on-chain data',
        impact: 10,
        detail: `RPC error: ${err.message}`,
      });
    }

    this._setCache(cacheKey, profile);
    return profile;
  }

  /**
   * Calculate address reputation score (0-100, higher = riskier)
   */
  async getReputation(address, chains = ['ethereum', 'base', 'arbitrum']) {
    const reputation = {
      address: address.toLowerCase(),
      overallScore: 0,
      level: 'CLEAN',
      chains: {},
      scamMatch: null,
      interactions: [],
      flags: new Set(),
      riskFactors: [],
    };

    // 1. Check scam database first (instant, no RPC needed)
    const scamMatch = this.checkScamDatabase(address);
    if (scamMatch) {
      reputation.scamMatch = scamMatch;
      reputation.overallScore = scamMatch.riskScore;
      reputation.flags.add(`KNOWN_${scamMatch.category.toUpperCase()}`);
      reputation.riskFactors.push({
        factor: `Known ${scamMatch.category}: ${scamMatch.label}`,
        impact: scamMatch.riskScore,
        detail: scamMatch.details,
      });
    }

    // 2. Check each chain
    for (const chain of chains) {
      try {
        const profile = await this.analyzeAddressProfile(address, chain);
        reputation.chains[chain] = profile;
        
        for (const flag of profile.flags) {
          reputation.flags.add(flag);
        }
        reputation.riskFactors.push(...profile.riskFactors);

        // Check for scam interactions
        const interactions = await this.checkScamInteractions(address, chain);
        if (interactions.length > 0) {
          reputation.interactions.push(...interactions);
          reputation.flags.add('SCAM_INTERACTIONS');
          
          const interactionScore = Math.min(50, interactions.length * 15);
          reputation.riskFactors.push({
            factor: `Interacted with ${interactions.length} known scam address(es) on ${chain}`,
            impact: interactionScore,
            detail: interactions.map(i => 
              `${i.direction} ${i.amount} USDC ${i.direction === 'sent' ? 'to' : 'from'} ${i.scamInfo.label}`
            ).join('; '),
          });
        }
      } catch (err) {
        reputation.chains[chain] = { error: err.message };
      }
    }

    // 3. Calculate final score
    if (!scamMatch) {
      const totalImpact = reputation.riskFactors.reduce((sum, f) => sum + f.impact, 0);
      reputation.overallScore = Math.min(100, totalImpact);
    }

    // 4. Determine risk level
    if (reputation.overallScore >= 90) reputation.level = 'CRITICAL';
    else if (reputation.overallScore >= 70) reputation.level = 'HIGH';
    else if (reputation.overallScore >= 40) reputation.level = 'MEDIUM';
    else if (reputation.overallScore >= 10) reputation.level = 'LOW';
    else reputation.level = 'CLEAN';

    // Convert Set to Array for serialization
    reputation.flags = Array.from(reputation.flags);

    return reputation;
  }

  _getCache(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.time > this.CACHE_TTL) {
      this.cache.delete(key);
      return null;
    }
    return entry.value;
  }

  _setCache(key, value) {
    this.cache.set(key, { value, time: Date.now() });
  }
}

module.exports = { AddressChecker };
