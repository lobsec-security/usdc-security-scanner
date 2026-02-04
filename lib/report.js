'use strict';

const { RISK_LEVELS } = require('./constants');

/**
 * Formats scan results into human-readable reports.
 */
class ReportGenerator {
  /**
   * Generate a full scan report
   */
  static formatScanReport(scanResult) {
    const { address, overallScore, level, chains, patterns, cctpAnalysis, reputation } = scanResult;
    const riskInfo = Object.values(RISK_LEVELS).find(r => overallScore >= r.min && overallScore <= r.max) || RISK_LEVELS.CLEAN;

    const lines = [];
    
    lines.push(`╔══════════════════════════════════════════════════╗`);
    lines.push(`║  USDC SECURITY SCAN REPORT                      ║`);
    lines.push(`║  LobSec Security — lobsec.org                   ║`);
    lines.push(`╚══════════════════════════════════════════════════╝`);
    lines.push('');
    lines.push(`📍 Address: ${address}`);
    lines.push(`📊 Risk Score: ${overallScore}/100 ${riskInfo.emoji} ${riskInfo.label}`);
    lines.push(`🕐 Scanned: ${new Date().toISOString()}`);
    lines.push('');

    // Risk meter
    lines.push(this._renderRiskMeter(overallScore));
    lines.push('');

    // Known scam match
    if (reputation?.scamMatch) {
      const sm = reputation.scamMatch;
      lines.push(`🚨 KNOWN THREAT MATCH`);
      lines.push(`   Label: ${sm.label}`);
      lines.push(`   Category: ${sm.category}`);
      lines.push(`   Severity: ${sm.severity.toUpperCase()}`);
      lines.push(`   Details: ${sm.details}`);
      lines.push(`   Reported: ${sm.reportedAt}`);
      lines.push('');
    }

    // Chain analysis
    if (chains && Object.keys(chains).length > 0) {
      lines.push(`━━━ CHAIN ANALYSIS ━━━`);
      for (const [chain, data] of Object.entries(chains)) {
        if (data.error) {
          lines.push(`  ${chain}: ⚠️ ${data.error}`);
          continue;
        }
        lines.push(`  ${this._chainEmoji(chain)} ${chain.toUpperCase()}`);
        if (data.usdcBalanceFormatted !== undefined) {
          lines.push(`    USDC Balance: $${data.usdcBalanceFormatted.toLocaleString()}`);
        }
        if (data.txCount !== undefined) {
          lines.push(`    Transactions: ${data.txCount}`);
        }
        if (data.isContract) {
          lines.push(`    Type: Smart Contract 📜`);
        }
        if (data.flags && data.flags.length > 0) {
          lines.push(`    Flags: ${data.flags.join(', ')}`);
        }
      }
      lines.push('');
    }

    // Pattern analysis
    if (patterns && patterns.length > 0) {
      lines.push(`━━━ PATTERN ANALYSIS ━━━`);
      for (const pattern of patterns) {
        const severityEmoji = pattern.severity === 'critical' ? '🚨' : 
                              pattern.severity === 'high' ? '🔴' : 
                              pattern.severity === 'medium' ? '🟠' : '🟡';
        lines.push(`  ${severityEmoji} ${pattern.type}`);
        lines.push(`    ${pattern.detail}`);
        lines.push(`    Confidence: ${pattern.confidence}% | Risk Impact: +${pattern.riskImpact}`);
      }
      lines.push('');
    }

    // CCTP analysis
    if (cctpAnalysis?.summary?.hasCCTPActivity) {
      lines.push(`━━━ CCTP CROSS-CHAIN ANALYSIS ━━━`);
      lines.push(`  Total CCTP transactions: ${cctpAnalysis.summary.totalCCTPTransactions}`);
      if (cctpAnalysis.patterns.length > 0) {
        for (const pattern of cctpAnalysis.patterns) {
          lines.push(`  ⚠️ ${pattern.type}: ${pattern.detail}`);
        }
      } else {
        lines.push(`  ✅ No suspicious cross-chain patterns detected`);
      }
      lines.push('');
    }

    // Scam interactions
    if (reputation?.interactions && reputation.interactions.length > 0) {
      lines.push(`━━━ SCAM ADDRESS INTERACTIONS ━━━`);
      for (const interaction of reputation.interactions) {
        const dirEmoji = interaction.direction === 'sent' ? '📤' : '📥';
        lines.push(`  ${dirEmoji} ${interaction.direction.toUpperCase()} $${interaction.amount.toLocaleString()} USDC`);
        lines.push(`    Counterparty: ${interaction.counterparty}`);
        lines.push(`    Identified as: ${interaction.scamInfo.label}`);
        lines.push(`    TX: ${interaction.txHash}`);
      }
      lines.push('');
    }

    // Risk factors
    if (reputation?.riskFactors && reputation.riskFactors.length > 0) {
      lines.push(`━━━ RISK FACTORS ━━━`);
      const sorted = [...reputation.riskFactors].sort((a, b) => b.impact - a.impact);
      for (const factor of sorted) {
        const bar = '█'.repeat(Math.ceil(factor.impact / 5)) + '░'.repeat(20 - Math.ceil(factor.impact / 5));
        lines.push(`  [${bar}] +${factor.impact} ${factor.factor}`);
        if (factor.detail) {
          lines.push(`    ${factor.detail}`);
        }
      }
      lines.push('');
    }

    // Recommendation
    lines.push(`━━━ RECOMMENDATION ━━━`);
    lines.push(`  ${this._getRecommendation(overallScore, level)}`);
    lines.push('');
    lines.push(`─── Powered by LobSec Security · lobsec.org ───`);

    return lines.join('\n');
  }

  /**
   * Format transfer validation report
   */
  static formatTransferValidation(validation) {
    const { recipient, chain, amount, overallScore, level, safe, recommendation } = validation;
    const riskInfo = Object.values(RISK_LEVELS).find(r => overallScore >= r.min && overallScore <= r.max) || RISK_LEVELS.CLEAN;

    const lines = [];
    lines.push(`╔══════════════════════════════════════════════════╗`);
    lines.push(`║  USDC TRANSFER SAFETY CHECK                     ║`);
    lines.push(`╚══════════════════════════════════════════════════╝`);
    lines.push('');
    lines.push(`📍 Recipient: ${recipient}`);
    lines.push(`⛓️  Chain: ${chain}`);
    if (amount) {
      lines.push(`💰 Amount: $${Number(amount).toLocaleString()} USDC`);
    }
    lines.push(`📊 Risk Score: ${overallScore}/100 ${riskInfo.emoji} ${riskInfo.label}`);
    lines.push('');
    lines.push(this._renderRiskMeter(overallScore));
    lines.push('');

    if (safe) {
      lines.push(`✅ TRANSFER APPEARS SAFE`);
    } else {
      lines.push(`⛔ TRANSFER NOT RECOMMENDED`);
    }
    lines.push('');
    lines.push(`Recommendation: ${recommendation}`);
    lines.push('');

    if (validation.flags && validation.flags.length > 0) {
      lines.push(`Flags: ${validation.flags.join(', ')}`);
    }

    if (validation.scamMatch) {
      lines.push('');
      lines.push(`🚨 WARNING: ${validation.scamMatch.label}`);
      lines.push(`   ${validation.scamMatch.details}`);
    }

    lines.push('');
    lines.push(`─── LobSec Security · lobsec.org ───`);

    return lines.join('\n');
  }

  /**
   * Format reputation report
   */
  static formatReputationReport(reputation) {
    const lines = [];
    const riskInfo = Object.values(RISK_LEVELS).find(r => 
      reputation.overallScore >= r.min && reputation.overallScore <= r.max
    ) || RISK_LEVELS.CLEAN;

    lines.push(`╔══════════════════════════════════════════════════╗`);
    lines.push(`║  ADDRESS REPUTATION REPORT                      ║`);
    lines.push(`╚══════════════════════════════════════════════════╝`);
    lines.push('');
    lines.push(`📍 Address: ${reputation.address}`);
    lines.push(`📊 Reputation Score: ${reputation.overallScore}/100 ${riskInfo.emoji} ${riskInfo.label}`);
    lines.push(this._renderRiskMeter(reputation.overallScore));
    lines.push('');

    if (reputation.flags.length > 0) {
      lines.push(`🏷️  Flags: ${reputation.flags.join(' | ')}`);
      lines.push('');
    }

    if (reputation.scamMatch) {
      lines.push(`🚨 DATABASE MATCH: ${reputation.scamMatch.label}`);
      lines.push(`   Category: ${reputation.scamMatch.category}`);
      lines.push(`   ${reputation.scamMatch.details}`);
      lines.push('');
    }

    for (const [chain, profile] of Object.entries(reputation.chains)) {
      if (profile.error) continue;
      lines.push(`${this._chainEmoji(chain)} ${chain.toUpperCase()}: ${profile.txCount} txs | $${(profile.usdcBalanceFormatted || 0).toLocaleString()} USDC | ${profile.isContract ? 'Contract' : 'EOA'}`);
    }

    lines.push('');
    lines.push(`─── LobSec Security · lobsec.org ───`);

    return lines.join('\n');
  }

  /**
   * Render a visual risk meter
   */
  static _renderRiskMeter(score) {
    const width = 30;
    const filled = Math.round((score / 100) * width);
    const empty = width - filled;
    
    let bar;
    if (score >= 90) bar = '🟥'.repeat(Math.min(filled, width));
    else if (score >= 70) bar = '🟧'.repeat(Math.min(filled, width));
    else if (score >= 40) bar = '🟨'.repeat(Math.min(filled, width));
    else bar = '🟩'.repeat(Math.min(filled, width));
    
    // Use simple ASCII bar for wider compatibility
    const asciiBar = '█'.repeat(filled) + '░'.repeat(empty);
    return `  Risk: [${asciiBar}] ${score}/100`;
  }

  static _chainEmoji(chain) {
    const emojis = {
      ethereum: '⟠',
      base: '🔵',
      arbitrum: '🔷',
    };
    return emojis[chain] || '⛓️';
  }

  static _getRecommendation(score, level) {
    if (score >= 90) {
      return '⛔ DO NOT INTERACT. This address is flagged as critical risk. Cease all interactions immediately.';
    }
    if (score >= 70) {
      return '🔴 HIGH RISK. Strongly advise against interacting. If you must proceed, use minimal amounts and verify thoroughly.';
    }
    if (score >= 40) {
      return '🟠 MODERATE RISK. Exercise caution. Verify the address through independent channels before transacting.';
    }
    if (score >= 10) {
      return '🟡 LOW RISK. Minor flags detected. Standard precautions recommended.';
    }
    return '✅ CLEAN. No concerning patterns detected. Standard safety practices apply.';
  }

  /**
   * Generate JSON report (for API/programmatic consumption)
   */
  static toJSON(scanResult) {
    return {
      version: '1.0.0',
      scanner: 'LobSec USDC Security Scanner',
      timestamp: new Date().toISOString(),
      ...scanResult,
    };
  }
}

module.exports = { ReportGenerator };
