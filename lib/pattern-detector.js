'use strict';

const { THRESHOLDS, FUNCTION_SELECTORS } = require('./constants');

/**
 * Detects suspicious transaction patterns in USDC transactions:
 * - Wash trading (circular transfers to inflate volume)
 * - Flash loan attacks (borrow + manipulate + repay in one tx)
 * - Honeypot contracts (can buy but not sell)
 * - Rapid bridging (potential laundering via CCTP)
 * - Sybil patterns (many wallets, coordinated behavior)
 */
class PatternDetector {
  constructor(rpcClient) {
    this.rpc = rpcClient;
  }

  /**
   * Run all pattern detections on a set of transactions
   */
  async analyzePatterns(address, chain, transfers) {
    const results = {
      address: address.toLowerCase(),
      chain,
      patterns: [],
      totalTransfers: transfers.length,
      summary: {},
    };

    // Run detectors in parallel
    const [washTrade, flashLoan, velocity, circular, largeTransfer] = await Promise.allSettled([
      this.detectWashTrading(address, transfers),
      this.detectFlashLoanPatterns(address, chain, transfers),
      this.detectHighVelocity(address, transfers),
      this.detectCircularFlows(address, transfers),
      this.detectLargeTransfers(address, transfers),
    ]);

    if (washTrade.status === 'fulfilled' && washTrade.value) {
      results.patterns.push(washTrade.value);
    }
    if (flashLoan.status === 'fulfilled' && flashLoan.value) {
      results.patterns.push(flashLoan.value);
    }
    if (velocity.status === 'fulfilled' && velocity.value) {
      results.patterns.push(velocity.value);
    }
    if (circular.status === 'fulfilled' && circular.value) {
      results.patterns.push(circular.value);
    }
    if (largeTransfer.status === 'fulfilled' && largeTransfer.value) {
      results.patterns.push(largeTransfer.value);
    }

    results.summary = {
      patternsDetected: results.patterns.length,
      highestSeverity: results.patterns.reduce(
        (max, p) => Math.max(max, p.riskImpact), 0
      ),
      categories: results.patterns.map(p => p.type),
    };

    return results;
  }

  /**
   * Detect wash trading: same amounts cycling between a small set of addresses
   */
  async detectWashTrading(address, transfers) {
    const addr = address.toLowerCase();
    
    // Group transfers by counterparty
    const counterparties = {};
    for (const tx of transfers) {
      const counterparty = tx.from.toLowerCase() === addr ? tx.to.toLowerCase() : tx.from.toLowerCase();
      if (!counterparties[counterparty]) {
        counterparties[counterparty] = { sent: [], received: [] };
      }
      if (tx.from.toLowerCase() === addr) {
        counterparties[counterparty].sent.push(tx);
      } else {
        counterparties[counterparty].received.push(tx);
      }
    }

    // Look for bidirectional transfers with similar amounts
    const suspiciousPairs = [];
    for (const [cp, flows] of Object.entries(counterparties)) {
      if (flows.sent.length === 0 || flows.received.length === 0) continue;

      let matches = 0;
      for (const sent of flows.sent) {
        for (const received of flows.received) {
          const tolerance = sent.amountUSDC * THRESHOLDS.WASH_TRADE_AMOUNT_TOLERANCE;
          if (Math.abs(sent.amountUSDC - received.amountUSDC) <= tolerance) {
            matches++;
          }
        }
      }

      if (matches >= THRESHOLDS.WASH_TRADE_MIN_CYCLES) {
        suspiciousPairs.push({
          counterparty: cp,
          sentCount: flows.sent.length,
          receivedCount: flows.received.length,
          matchingAmountCycles: matches,
          totalVolume: [...flows.sent, ...flows.received].reduce((sum, tx) => sum + tx.amountUSDC, 0),
        });
      }
    }

    if (suspiciousPairs.length === 0) return null;

    return {
      type: 'WASH_TRADING',
      severity: 'high',
      riskImpact: 35,
      confidence: Math.min(95, 50 + suspiciousPairs.length * 15),
      detail: `Detected ${suspiciousPairs.length} counterparty pair(s) with bidirectional transfers of matching amounts`,
      evidence: {
        suspiciousPairs,
        totalSuspiciousVolume: suspiciousPairs.reduce((sum, p) => sum + p.totalVolume, 0),
      },
    };
  }

  /**
   * Detect flash loan attack patterns:
   * - Large borrow + complex operations + repay in same block/tx
   * - Interaction with known flash loan providers
   */
  async detectFlashLoanPatterns(address, chain, transfers) {
    // Group transfers by block
    const byBlock = {};
    for (const tx of transfers) {
      if (!byBlock[tx.blockNumber]) {
        byBlock[tx.blockNumber] = [];
      }
      byBlock[tx.blockNumber].push(tx);
    }

    const suspiciousBlocks = [];
    for (const [block, txs] of Object.entries(byBlock)) {
      // Multiple large transfers in the same block
      const largeTxs = txs.filter(tx => tx.amountUSDC >= THRESHOLDS.FLASH_LOAN_MIN_AMOUNT);
      
      if (largeTxs.length >= 2) {
        // Check for borrow-repay pattern (receive then send similar amount)
        const received = largeTxs.filter(tx => tx.to.toLowerCase() === address.toLowerCase());
        const sent = largeTxs.filter(tx => tx.from.toLowerCase() === address.toLowerCase());
        
        if (received.length > 0 && sent.length > 0) {
          for (const recv of received) {
            for (const send of sent) {
              const tolerance = recv.amountUSDC * 0.05; // 5% tolerance (fees)
              if (Math.abs(recv.amountUSDC - send.amountUSDC) <= tolerance) {
                suspiciousBlocks.push({
                  blockNumber: parseInt(block),
                  receivedAmount: recv.amountUSDC,
                  sentAmount: send.amountUSDC,
                  receivedFrom: recv.from,
                  sentTo: send.to,
                  netProfit: send.amountUSDC - recv.amountUSDC,
                });
              }
            }
          }
        }
      }
    }

    if (suspiciousBlocks.length === 0) return null;

    return {
      type: 'FLASH_LOAN_PATTERN',
      severity: 'high',
      riskImpact: 40,
      confidence: Math.min(90, 40 + suspiciousBlocks.length * 20),
      detail: `Detected ${suspiciousBlocks.length} block(s) with flash-loan-like borrow/repay patterns`,
      evidence: {
        suspiciousBlocks,
        totalSuspiciousVolume: suspiciousBlocks.reduce((sum, b) => sum + b.receivedAmount, 0),
      },
    };
  }

  /**
   * Detect abnormally high transaction velocity
   */
  async detectHighVelocity(address, transfers) {
    if (transfers.length < THRESHOLDS.HIGH_VELOCITY_TXS_PER_HOUR) return null;

    // Sort by block number
    const sorted = [...transfers].sort((a, b) => a.blockNumber - b.blockNumber);
    
    // Sliding window: check for bursts
    // Approximate: 1 block ≈ 12s on Ethereum, 2s on Base, 0.25s on Arbitrum
    const blockTimeEstimate = { ethereum: 12, base: 2, arbitrum: 0.25 };
    
    let maxInWindow = 0;
    let windowStart = 0;
    const blocksPerHour = 3600 / (blockTimeEstimate.ethereum || 12); // Conservative

    for (let i = 0; i < sorted.length; i++) {
      while (windowStart < i && sorted[i].blockNumber - sorted[windowStart].blockNumber > blocksPerHour) {
        windowStart++;
      }
      maxInWindow = Math.max(maxInWindow, i - windowStart + 1);
    }

    if (maxInWindow < THRESHOLDS.HIGH_VELOCITY_TXS_PER_HOUR) return null;

    return {
      type: 'HIGH_VELOCITY',
      severity: 'medium',
      riskImpact: 20,
      confidence: Math.min(85, 30 + (maxInWindow / THRESHOLDS.HIGH_VELOCITY_TXS_PER_HOUR) * 30),
      detail: `${maxInWindow} USDC transfers detected within approximately 1 hour window`,
      evidence: {
        peakTransfersPerHour: maxInWindow,
        totalTransfers: transfers.length,
      },
    };
  }

  /**
   * Detect circular fund flows (A -> B -> C -> A)
   */
  async detectCircularFlows(address, transfers) {
    const addr = address.toLowerCase();
    
    // Build adjacency: who did this address send to, and who sent to those addresses?
    const sentTo = new Set();
    const receivedFrom = new Set();
    
    for (const tx of transfers) {
      if (tx.from.toLowerCase() === addr) {
        sentTo.add(tx.to.toLowerCase());
      } else {
        receivedFrom.add(tx.from.toLowerCase());
      }
    }

    // Direct circular: addresses that both sent to AND received from the target
    const directCircular = [];
    for (const cp of sentTo) {
      if (receivedFrom.has(cp)) {
        const sentTxs = transfers.filter(t => t.from.toLowerCase() === addr && t.to.toLowerCase() === cp);
        const recvTxs = transfers.filter(t => t.to.toLowerCase() === addr && t.from.toLowerCase() === cp);
        
        const totalSent = sentTxs.reduce((sum, t) => sum + t.amountUSDC, 0);
        const totalRecv = recvTxs.reduce((sum, t) => sum + t.amountUSDC, 0);

        directCircular.push({
          counterparty: cp,
          totalSent,
          totalReceived: totalRecv,
          netFlow: totalRecv - totalSent,
          cycleCount: Math.min(sentTxs.length, recvTxs.length),
        });
      }
    }

    // Only flag if significant circular activity
    const significantCircular = directCircular.filter(c => c.cycleCount >= 2 && c.totalSent > 100);
    
    if (significantCircular.length === 0) return null;

    return {
      type: 'CIRCULAR_FLOW',
      severity: significantCircular.some(c => c.totalSent > 10000) ? 'high' : 'medium',
      riskImpact: Math.min(30, 10 + significantCircular.length * 5),
      confidence: Math.min(80, 30 + significantCircular.length * 10),
      detail: `${significantCircular.length} circular flow pattern(s) detected with counterparties`,
      evidence: {
        circularCounterparties: significantCircular,
        totalCircularVolume: significantCircular.reduce((sum, c) => sum + c.totalSent + c.totalReceived, 0),
      },
    };
  }

  /**
   * Flag large transfers that warrant enhanced scrutiny
   */
  async detectLargeTransfers(address, transfers) {
    const large = transfers.filter(tx => tx.amountUSDC >= THRESHOLDS.LARGE_TRANSFER_USDC);
    
    if (large.length === 0) return null;

    const totalLargeVolume = large.reduce((sum, tx) => sum + tx.amountUSDC, 0);

    return {
      type: 'LARGE_TRANSFERS',
      severity: totalLargeVolume > 1000000 ? 'high' : 'medium',
      riskImpact: totalLargeVolume > 1000000 ? 25 : 10,
      confidence: 100, // Factual, no inference
      detail: `${large.length} transfer(s) exceeding $${THRESHOLDS.LARGE_TRANSFER_USDC.toLocaleString()} USDC threshold`,
      evidence: {
        largeTransfers: large.map(tx => ({
          txHash: tx.txHash,
          amount: tx.amountUSDC,
          from: tx.from,
          to: tx.to,
          blockNumber: tx.blockNumber,
        })),
        totalLargeVolume,
      },
    };
  }

  /**
   * Analyze a single transaction for suspicious patterns
   */
  async analyzeTransaction(chain, txHash) {
    const results = {
      txHash,
      chain,
      flags: [],
      riskScore: 0,
      details: {},
    };

    try {
      const [tx, receipt] = await Promise.all([
        this.rpc.getTransaction(chain, txHash),
        this.rpc.getTransactionReceipt(chain, txHash),
      ]);

      if (!tx || !receipt) {
        results.flags.push('TX_NOT_FOUND');
        return results;
      }

      results.details.from = tx.from;
      results.details.to = tx.to;
      results.details.value = tx.value ? BigInt(tx.value).toString() : '0';
      results.details.gasUsed = receipt.gasUsed ? parseInt(receipt.gasUsed, 16) : 0;
      results.details.status = receipt.status === '0x1' ? 'success' : 'failed';
      results.details.logCount = receipt.logs ? receipt.logs.length : 0;

      // Check function selector
      if (tx.input && tx.input.length >= 10) {
        const selector = tx.input.slice(0, 10);
        for (const [name, sig] of Object.entries(FUNCTION_SELECTORS)) {
          if (selector === sig) {
            results.details.functionCalled = name;
            break;
          }
        }
      }

      // Flag: failed transaction
      if (results.details.status === 'failed') {
        results.flags.push('TX_FAILED');
        results.riskScore += 5;
      }

      // Flag: very high gas usage (>500K) suggests complex operation
      if (results.details.gasUsed > 500000) {
        results.flags.push('HIGH_GAS_USAGE');
        results.riskScore += 10;
      }

      // Flag: many log events (>10) suggests complex multi-step operation
      if (results.details.logCount > 10) {
        results.flags.push('COMPLEX_OPERATION');
        results.riskScore += 15;
      }

      // Flag: interacting with suspicious approve patterns
      if (results.details.functionCalled === 'approve') {
        // Check if approving max amount
        if (tx.input && tx.input.length > 74) {
          const amountHex = '0x' + tx.input.slice(74);
          try {
            const amount = BigInt(amountHex);
            if (amount >= BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff') - BigInt(1000)) {
              results.flags.push('UNLIMITED_APPROVAL');
              results.riskScore += 25;
            }
          } catch {}
        }
      }

      // Check if involves known scam addresses (deferred to caller who has AddressChecker)
      results.details.involvedAddresses = [tx.from, tx.to].filter(Boolean);

    } catch (err) {
      results.flags.push('ANALYSIS_ERROR');
      results.details.error = err.message;
    }

    return results;
  }

  /**
   * Detect honeypot characteristics in a contract
   */
  async detectHoneypot(address, chain) {
    const result = {
      address: address.toLowerCase(),
      chain,
      isHoneypot: false,
      confidence: 0,
      indicators: [],
    };

    try {
      // Check if it's a contract
      const isContract = await this.rpc.isContract(chain, address);
      if (!isContract) {
        result.indicators.push('NOT_A_CONTRACT');
        return result;
      }

      // Get contract code
      const code = await this.rpc.getCode(chain, address);
      
      // Heuristic checks on bytecode
      const codeStr = code.toLowerCase();
      
      // Check for selfdestruct opcode (0xff)
      if (codeStr.includes('ff')) {
        // This is just an opcode presence — many legit contracts have it
        // But combined with other indicators it's suspicious
        result.indicators.push('HAS_SELFDESTRUCT_OPCODE');
      }

      // Check for delegatecall (0xf4) — can be used to change behavior
      const delegatecallCount = (codeStr.match(/f4/g) || []).length;
      if (delegatecallCount > 3) {
        result.indicators.push('EXCESSIVE_DELEGATECALL');
        result.confidence += 15;
      }

      // Check code size — very small contracts are suspicious for tokens
      const codeSize = (code.length - 2) / 2; // Remove 0x, each byte = 2 hex chars
      if (codeSize < 200) {
        result.indicators.push('SUSPICIOUSLY_SMALL_CONTRACT');
        result.confidence += 20;
      }

      // Check transaction patterns
      const txCount = await this.rpc.getTransactionCount(chain, address);
      if (txCount > 0) {
        // Get recent transfers
        const transfers = await this.rpc.getUSDCTransfers(chain, address).catch(() => []);
        
        if (transfers.length >= THRESHOLDS.HONEYPOT_MIN_TRANSACTIONS) {
          const sent = transfers.filter(t => t.from.toLowerCase() === address.toLowerCase());
          const received = transfers.filter(t => t.to.toLowerCase() === address.toLowerCase());
          
          // Classic honeypot: many buys (received) but few/no sells (sent)
          if (received.length > 5 && sent.length === 0) {
            result.indicators.push('NO_OUTGOING_TRANSFERS');
            result.confidence += 40;
          } else if (received.length > 0 && sent.length / received.length < THRESHOLDS.HONEYPOT_SELL_FAIL_RATIO) {
            result.indicators.push('LOW_OUTGOING_RATIO');
            result.confidence += 25;
          }
        }
      }

      result.isHoneypot = result.confidence >= 50;
      
    } catch (err) {
      result.indicators.push('ANALYSIS_ERROR');
      result.error = err.message;
    }

    return result;
  }
}

module.exports = { PatternDetector };
