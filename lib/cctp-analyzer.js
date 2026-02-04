'use strict';

const contractsData = require('../data/contracts.json');
const { THRESHOLDS } = require('./constants');

/**
 * Analyzes Circle CCTP (Cross-Chain Transfer Protocol) activity
 * for suspicious cross-chain patterns that may indicate laundering,
 * bridge exploits, or unusual bridging behavior.
 */
class CCTPAnalyzer {
  constructor(rpcClient) {
    this.rpc = rpcClient;
    this.domainToChain = {};
    
    // Build reverse mapping from domain ID to chain name
    const domains = contractsData.cctp?.domainIds || {};
    for (const [chain, domainId] of Object.entries(domains)) {
      this.domainToChain[domainId] = chain;
    }
  }

  /**
   * Analyze cross-chain USDC transfer patterns for an address
   */
  async analyzeCrossChainActivity(address, chains = ['ethereum', 'base', 'arbitrum']) {
    const result = {
      address: address.toLowerCase(),
      chains,
      cctpActivity: [],
      patterns: [],
      riskFactors: [],
      summary: {},
    };

    // Gather CCTP deposit events across chains
    const depositPromises = chains.map(async chain => {
      try {
        const deposits = await this.rpc.getCCTPDeposits(chain, address);
        return deposits.map(d => ({ ...d, sourceChain: chain }));
      } catch {
        return [];
      }
    });

    const depositResults = await Promise.allSettled(depositPromises);
    const allDeposits = depositResults
      .filter(r => r.status === 'fulfilled')
      .flatMap(r => r.value);

    result.cctpActivity = allDeposits;
    result.summary.totalCCTPTransactions = allDeposits.length;

    if (allDeposits.length === 0) {
      result.summary.hasCCTPActivity = false;
      return result;
    }

    result.summary.hasCCTPActivity = true;

    // Pattern: Rapid bridging (multiple cross-chain transfers in short time)
    const rapidBridging = this._detectRapidBridging(allDeposits);
    if (rapidBridging) {
      result.patterns.push(rapidBridging);
      result.riskFactors.push({
        factor: 'Rapid cross-chain bridging detected',
        impact: rapidBridging.riskImpact,
        detail: rapidBridging.detail,
      });
    }

    // Pattern: Chain hopping (using multiple chains in sequence)
    const chainHopping = this._detectChainHopping(allDeposits);
    if (chainHopping) {
      result.patterns.push(chainHopping);
      result.riskFactors.push({
        factor: 'Chain hopping pattern detected',
        impact: chainHopping.riskImpact,
        detail: chainHopping.detail,
      });
    }

    // Pattern: Round-trip bridging (bridge out then back to same chain)
    const roundTrip = await this._detectRoundTrip(address, chains);
    if (roundTrip) {
      result.patterns.push(roundTrip);
      result.riskFactors.push({
        factor: 'Round-trip bridging detected',
        impact: roundTrip.riskImpact,
        detail: roundTrip.detail,
      });
    }

    return result;
  }

  /**
   * Detect rapid bridging: many CCTP transfers in a short window
   */
  _detectRapidBridging(deposits) {
    if (deposits.length < 3) return null;

    // Sort by block number (cross-chain so can't directly compare,
    // but within same chain we can)
    const byChain = {};
    for (const d of deposits) {
      if (!byChain[d.sourceChain]) byChain[d.sourceChain] = [];
      byChain[d.sourceChain].push(d);
    }

    let maxBursts = 0;
    for (const [chain, chainDeposits] of Object.entries(byChain)) {
      const sorted = chainDeposits.sort((a, b) => a.blockNumber - b.blockNumber);
      
      // Check for bursts: more than 3 CCTP deposits within 50 blocks
      for (let i = 0; i < sorted.length; i++) {
        let count = 1;
        for (let j = i + 1; j < sorted.length && sorted[j].blockNumber - sorted[i].blockNumber <= 50; j++) {
          count++;
        }
        maxBursts = Math.max(maxBursts, count);
      }
    }

    if (maxBursts < 3) return null;

    return {
      type: 'RAPID_BRIDGING',
      severity: maxBursts >= 5 ? 'high' : 'medium',
      riskImpact: Math.min(35, 15 + maxBursts * 5),
      confidence: Math.min(85, 40 + maxBursts * 10),
      detail: `${maxBursts} CCTP bridge transactions detected within a short block window — may indicate automated laundering`,
      evidence: {
        maxBurstSize: maxBursts,
        totalDeposits: deposits.length,
      },
    };
  }

  /**
   * Detect chain hopping: using all supported chains (A -> B -> C pattern)
   */
  _detectChainHopping(deposits) {
    const chainsUsed = new Set(deposits.map(d => d.sourceChain));
    
    if (chainsUsed.size < 3) return null;

    return {
      type: 'CHAIN_HOPPING',
      severity: 'medium',
      riskImpact: 20,
      confidence: 60,
      detail: `CCTP bridges initiated from ${chainsUsed.size} different chains (${Array.from(chainsUsed).join(', ')}) — multi-chain activity may indicate obfuscation`,
      evidence: {
        chainsUsed: Array.from(chainsUsed),
        totalDeposits: deposits.length,
      },
    };
  }

  /**
   * Detect round-trip bridging: bridge out then back to same chain
   * This requires checking if there are both deposits from and receipts to the same chain
   */
  async _detectRoundTrip(address, chains) {
    // Check USDC balance changes across chains to infer round trips
    const balances = {};
    for (const chain of chains) {
      try {
        const balance = await this.rpc.getUSDCBalance(chain, address);
        balances[chain] = Number(BigInt(balance)) / 1e6;
      } catch {
        balances[chain] = null;
      }
    }

    // If address has CCTP activity but most funds are back on original chain,
    // it suggests round-tripping
    const nonZeroChains = Object.entries(balances)
      .filter(([, bal]) => bal !== null && bal > 0);
    
    // Can't determine round-trip from balance alone without historical data
    // This is a placeholder for more advanced analysis with indexed data
    return null;
  }

  /**
   * Check if a specific CCTP transfer looks suspicious
   */
  async analyzeCCTPTransfer(chain, txHash) {
    const result = {
      txHash,
      chain,
      isCCTP: false,
      flags: [],
      details: {},
    };

    try {
      const receipt = await this.rpc.getTransactionReceipt(chain, txHash);
      if (!receipt) {
        result.flags.push('TX_NOT_FOUND');
        return result;
      }

      const network = this.rpc.useTestnet ? 'sepolia' : 'mainnet';
      const tokenMessenger = contractsData.cctp?.tokenMessenger?.[chain]?.[network]?.toLowerCase();
      
      // Check if transaction interacted with CCTP TokenMessenger
      if (receipt.to?.toLowerCase() === tokenMessenger) {
        result.isCCTP = true;
        result.details.type = 'CCTP_DEPOSIT';
      }

      // Check logs for CCTP events
      const depositTopic = '0x2fa9ca894982930190727e75500a97d8dc500233a5065e0f3126c48fbe0343c0';
      const cctpLogs = (receipt.logs || []).filter(log => 
        log.topics[0] === depositTopic
      );

      if (cctpLogs.length > 0) {
        result.isCCTP = true;
        result.details.cctpEventCount = cctpLogs.length;
      }

      // Multiple CCTP operations in one transaction is unusual
      if (cctpLogs.length > 1) {
        result.flags.push('MULTIPLE_CCTP_OPS');
        result.details.note = 'Multiple CCTP deposit events in single transaction — unusual and potentially suspicious';
      }

    } catch (err) {
      result.flags.push('ANALYSIS_ERROR');
      result.details.error = err.message;
    }

    return result;
  }

  /**
   * Get CCTP domain info for a chain
   */
  getDomainInfo(chain) {
    const domains = contractsData.cctp?.domainIds || {};
    return {
      chain,
      domainId: domains[chain],
      tokenMessenger: contractsData.cctp?.tokenMessenger?.[chain],
      messageTransmitter: contractsData.cctp?.messageTransmitter?.[chain],
    };
  }
}

module.exports = { CCTPAnalyzer };
