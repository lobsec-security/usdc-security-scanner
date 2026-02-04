'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { USDCSecurityScanner } = require('../index');
const { AddressChecker } = require('../lib/address-checker');
const { PatternDetector } = require('../lib/pattern-detector');
const { CCTPAnalyzer } = require('../lib/cctp-analyzer');
const { ReportGenerator } = require('../lib/report');
const { RpcClient } = require('../lib/rpc');
const { RISK_LEVELS, THRESHOLDS, SUPPORTED_CHAINS } = require('../lib/constants');

// ═══════════════════════════════════════════
// Mock RPC Client for testing without network
// ═══════════════════════════════════════════

class MockRpcClient {
  constructor() {
    this.mockResponses = {};
    this.useTestnet = false;
  }

  setMock(method, response) {
    this.mockResponses[method] = response;
  }

  async call(chain, method, params) {
    if (this.mockResponses[method]) {
      return typeof this.mockResponses[method] === 'function'
        ? this.mockResponses[method](chain, params)
        : this.mockResponses[method];
    }
    return null;
  }

  async getBlockNumber(chain) { return 1000000; }
  async getTransaction(chain, hash) { return this.mockResponses['getTransaction'] || null; }
  async getTransactionReceipt(chain, hash) { return this.mockResponses['getTransactionReceipt'] || null; }
  async getCode(chain, addr) { return this.mockResponses['getCode'] || '0x'; }
  async isContract(chain, addr) { return (this.mockResponses['getCode'] || '0x') !== '0x'; }
  async getUSDCBalance(chain, addr) { return this.mockResponses['getUSDCBalance'] || '0'; }
  async getBalance(chain, addr) { return this.mockResponses['getBalance'] || '0'; }
  async getTransactionCount(chain, addr) { return this.mockResponses['getTransactionCount'] || 0; }
  async getUSDCTransfers(chain, addr) { return this.mockResponses['getUSDCTransfers'] || []; }
  async getCCTPDeposits(chain, addr) { return this.mockResponses['getCCTPDeposits'] || []; }
  async getBlock(chain, num) { return this.mockResponses['getBlock'] || { timestamp: '0x60000000' }; }
}

// ═══════════════════════════════════════════
// Scanner Initialization Tests
// ═══════════════════════════════════════════

describe('USDCSecurityScanner', () => {
  it('should instantiate without errors', () => {
    const scanner = new USDCSecurityScanner();
    assert.ok(scanner);
    assert.ok(scanner.rpc);
    assert.ok(scanner.addressChecker);
    assert.ok(scanner.patternDetector);
    assert.ok(scanner.cctpAnalyzer);
  });

  it('should accept testnet option', () => {
    const scanner = new USDCSecurityScanner({ testnet: true });
    assert.ok(scanner.rpc.useTestnet);
  });

  it('should validate address format', () => {
    const scanner = new USDCSecurityScanner();
    
    assert.throws(() => scanner.quickCheck('invalid'), /Invalid Ethereum address/);
    assert.throws(() => scanner.quickCheck('0x123'), /Invalid Ethereum address/);
    assert.throws(() => scanner.quickCheck(''), /Address is required/);
    assert.throws(() => scanner.quickCheck(null), /Address is required/);
  });
});

// ═══════════════════════════════════════════
// Scam Database Tests
// ═══════════════════════════════════════════

describe('Scam Database', () => {
  let scanner;

  beforeEach(() => {
    scanner = new USDCSecurityScanner();
  });

  it('should detect known scam addresses', () => {
    const result = scanner.quickCheck('0x098B716B8Aaf21512996dC57EB0615e2383E2f96');
    assert.ok(result);
    assert.equal(result.isKnownScam, true);
    assert.equal(result.category, 'exploit');
    assert.ok(result.label.includes('Ronin'));
  });

  it('should detect sanctioned addresses', () => {
    const result = scanner.quickCheck('0x8589427373D6D84E98730D7795D8f6f8731FDA16');
    assert.ok(result);
    assert.equal(result.category, 'sanctioned');
    assert.equal(result.severity, 'critical');
  });

  it('should be case-insensitive', () => {
    const lower = scanner.quickCheck('0x098b716b8aaf21512996dc57eb0615e2383e2f96');
    const upper = scanner.quickCheck('0x098B716B8Aaf21512996dC57EB0615e2383E2f96');
    assert.deepEqual(lower, upper);
  });

  it('should return null for clean addresses', () => {
    const result = scanner.quickCheck('0x1111111111111111111111111111111111111111');
    assert.equal(result, null);
  });

  it('should detect zero/dead addresses', () => {
    const zero = scanner.quickCheck('0x0000000000000000000000000000000000000000');
    assert.ok(zero);
    assert.equal(zero.category, 'burn');

    const dead = scanner.quickCheck('0x000000000000000000000000000000000000dEaD');
    assert.ok(dead);
    assert.equal(dead.category, 'burn');
  });

  it('should batch check multiple addresses', () => {
    const results = scanner.batchQuickCheck([
      '0x098B716B8Aaf21512996dC57EB0615e2383E2f96', // Known scam
      '0x1111111111111111111111111111111111111111', // Clean
      '0x0000000000000000000000000000000000000000', // Burn
    ]);

    assert.equal(results.length, 3);
    assert.ok(results[0].result); // Scam found
    assert.equal(results[1].result, null); // Clean
    assert.ok(results[2].result); // Burn found
  });

  it('should have at least 50 scam addresses', () => {
    const fs = require('fs');
    const path = require('path');
    const data = JSON.parse(fs.readFileSync(
      path.join(__dirname, '..', 'data', 'scam-addresses.json'), 'utf8'
    ));
    const count = Object.keys(data.addresses).length;
    assert.ok(count >= 50, `Expected at least 50 addresses, got ${count}`);
  });
});

// ═══════════════════════════════════════════
// Address Checker Tests
// ═══════════════════════════════════════════

describe('AddressChecker', () => {
  let checker;
  let mockRpc;

  beforeEach(() => {
    mockRpc = new MockRpcClient();
    checker = new AddressChecker(mockRpc);
  });

  it('should analyze address profile', async () => {
    mockRpc.setMock('getTransactionCount', 42);
    mockRpc.setMock('getUSDCBalance', '1000000000'); // 1000 USDC
    mockRpc.setMock('getBalance', '1000000000000000000'); // 1 ETH

    const profile = await checker.analyzeAddressProfile(
      '0x1111111111111111111111111111111111111111',
      'ethereum'
    );

    assert.equal(profile.txCount, 42);
    assert.equal(profile.usdcBalanceFormatted, 1000);
    assert.equal(profile.isContract, false);
  });

  it('should flag new addresses with no transactions', async () => {
    mockRpc.setMock('getTransactionCount', 0);
    mockRpc.setMock('getUSDCBalance', '0');
    mockRpc.setMock('getBalance', '0');

    const profile = await checker.analyzeAddressProfile(
      '0x1111111111111111111111111111111111111111',
      'ethereum'
    );

    assert.ok(profile.flags.includes('NEVER_TRANSACTED'));
  });

  it('should flag low-tx high-balance addresses', async () => {
    mockRpc.setMock('getTransactionCount', 2);
    mockRpc.setMock('getUSDCBalance', '100000000000'); // 100K USDC
    mockRpc.setMock('getBalance', '1000000000000000000');

    const profile = await checker.analyzeAddressProfile(
      '0x1111111111111111111111111111111111111111',
      'base'
    );

    assert.ok(profile.flags.includes('LOW_TX_HIGH_BALANCE'));
  });

  it('should detect contracts', async () => {
    mockRpc.setMock('getCode', '0x6080604052');
    mockRpc.setMock('getTransactionCount', 100);
    mockRpc.setMock('getUSDCBalance', '0');
    mockRpc.setMock('getBalance', '0');

    const profile = await checker.analyzeAddressProfile(
      '0x1111111111111111111111111111111111111111',
      'ethereum'
    );

    assert.equal(profile.isContract, true);
    assert.ok(profile.flags.includes('IS_CONTRACT'));
  });

  it('should compute reputation score', async () => {
    mockRpc.setMock('getTransactionCount', 0);
    mockRpc.setMock('getUSDCBalance', '0');
    mockRpc.setMock('getBalance', '0');
    mockRpc.setMock('getUSDCTransfers', []);

    const reputation = await checker.getReputation(
      '0x1111111111111111111111111111111111111111',
      ['ethereum']
    );

    assert.ok(typeof reputation.overallScore === 'number');
    assert.ok(['CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(reputation.level));
    assert.ok(Array.isArray(reputation.flags));
  });

  it('should give critical score to known scam addresses', async () => {
    mockRpc.setMock('getTransactionCount', 100);
    mockRpc.setMock('getUSDCBalance', '0');
    mockRpc.setMock('getBalance', '0');
    mockRpc.setMock('getUSDCTransfers', []);

    const reputation = await checker.getReputation(
      '0x098B716B8Aaf21512996dC57EB0615e2383E2f96', // Ronin exploiter
      ['ethereum']
    );

    assert.ok(reputation.overallScore >= 90);
    assert.equal(reputation.level, 'CRITICAL');
    assert.ok(reputation.scamMatch);
  });

  it('should cache profile results', async () => {
    let callCount = 0;
    const origGetTxCount = mockRpc.getTransactionCount.bind(mockRpc);
    mockRpc.getTransactionCount = async () => { callCount++; return 10; };
    mockRpc.setMock('getUSDCBalance', '0');
    mockRpc.setMock('getBalance', '0');

    const addr = '0x2222222222222222222222222222222222222222';
    await checker.analyzeAddressProfile(addr, 'ethereum');
    await checker.analyzeAddressProfile(addr, 'ethereum');

    assert.equal(callCount, 1, 'Should have cached the second call');
  });
});

// ═══════════════════════════════════════════
// Pattern Detector Tests
// ═══════════════════════════════════════════

describe('PatternDetector', () => {
  let detector;
  let mockRpc;

  beforeEach(() => {
    mockRpc = new MockRpcClient();
    detector = new PatternDetector(mockRpc);
  });

  it('should detect wash trading patterns', async () => {
    const address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const counterparty = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    
    // Create transfers that look like wash trading:
    // same amounts going back and forth
    const transfers = [];
    for (let i = 0; i < 5; i++) {
      transfers.push({
        txHash: `0x${i}a`,
        blockNumber: 1000 + i,
        from: address,
        to: counterparty,
        amount: '1000000000', // 1000 USDC
        amountUSDC: 1000,
        logIndex: 0,
      });
      transfers.push({
        txHash: `0x${i}b`,
        blockNumber: 1001 + i,
        from: counterparty,
        to: address,
        amount: '1000000000',
        amountUSDC: 1000,
        logIndex: 0,
      });
    }

    const result = await detector.detectWashTrading(address, transfers);
    assert.ok(result, 'Should detect wash trading');
    assert.equal(result.type, 'WASH_TRADING');
    assert.ok(result.confidence > 50);
  });

  it('should not flag normal trading as wash trading', async () => {
    const address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    
    const transfers = [
      { txHash: '0x1', blockNumber: 1000, from: address, to: '0xbbbb', amount: '1000000000', amountUSDC: 1000, logIndex: 0 },
      { txHash: '0x2', blockNumber: 2000, from: '0xcccc', to: address, amount: '500000000', amountUSDC: 500, logIndex: 0 },
      { txHash: '0x3', blockNumber: 3000, from: address, to: '0xdddd', amount: '2000000000', amountUSDC: 2000, logIndex: 0 },
    ];

    const result = await detector.detectWashTrading(address, transfers);
    assert.equal(result, null, 'Should not flag normal transactions');
  });

  it('should detect flash loan patterns', async () => {
    const address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    
    // Large borrow and repay in same block
    const transfers = [
      { txHash: '0x1', blockNumber: 5000, from: '0xbbbb', to: address, amount: '50000000000', amountUSDC: 50000, logIndex: 0 },
      { txHash: '0x1', blockNumber: 5000, from: address, to: '0xbbbb', amount: '50100000000', amountUSDC: 50100, logIndex: 1 },
    ];

    const result = await detector.detectFlashLoanPatterns(address, 'ethereum', transfers);
    assert.ok(result, 'Should detect flash loan pattern');
    assert.equal(result.type, 'FLASH_LOAN_PATTERN');
  });

  it('should detect high velocity transfers', async () => {
    const address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    
    // Many transfers in a short block range
    const transfers = [];
    for (let i = 0; i < 25; i++) {
      transfers.push({
        txHash: `0x${i}`,
        blockNumber: 1000 + i, // All within ~5 minutes on Ethereum
        from: address,
        to: `0x${i.toString(16).padStart(40, '0')}`,
        amount: '100000000',
        amountUSDC: 100,
        logIndex: 0,
      });
    }

    const result = await detector.detectHighVelocity(address, transfers);
    assert.ok(result, 'Should detect high velocity');
    assert.equal(result.type, 'HIGH_VELOCITY');
  });

  it('should detect circular flows', async () => {
    const address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const partner = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    
    const transfers = [];
    // Create circular: address sends to partner, partner sends back
    for (let i = 0; i < 3; i++) {
      transfers.push({
        txHash: `0xsend${i}`,
        blockNumber: 1000 + i * 10,
        from: address,
        to: partner,
        amount: '5000000000',
        amountUSDC: 5000,
        logIndex: 0,
      });
      transfers.push({
        txHash: `0xrecv${i}`,
        blockNumber: 1005 + i * 10,
        from: partner,
        to: address,
        amount: '4900000000',
        amountUSDC: 4900,
        logIndex: 0,
      });
    }

    const result = await detector.detectCircularFlows(address, transfers);
    assert.ok(result, 'Should detect circular flows');
    assert.equal(result.type, 'CIRCULAR_FLOW');
  });

  it('should detect large transfers', async () => {
    const address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    
    const transfers = [
      { txHash: '0x1', blockNumber: 1000, from: address, to: '0xbbbb', amount: '100000000000', amountUSDC: 100000, logIndex: 0 },
    ];

    const result = await detector.detectLargeTransfers(address, transfers);
    assert.ok(result, 'Should flag large transfer');
    assert.equal(result.type, 'LARGE_TRANSFERS');
  });

  it('should run all pattern analysis', async () => {
    const address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const transfers = [
      { txHash: '0x1', blockNumber: 1000, from: address, to: '0xbbbb', amount: '1000000', amountUSDC: 1, logIndex: 0 },
    ];

    const results = await detector.analyzePatterns(address, 'ethereum', transfers);
    assert.ok(results);
    assert.equal(results.address, address);
    assert.ok(Array.isArray(results.patterns));
    assert.ok(results.summary);
  });

  it('should analyze a transaction', async () => {
    mockRpc.setMock('getTransaction', {
      from: '0xaaaa',
      to: '0xbbbb',
      value: '0x0',
      input: '0xa9059cbb',
      hash: '0x1234',
    });
    mockRpc.setMock('getTransactionReceipt', {
      status: '0x1',
      gasUsed: '0x5208',
      logs: [],
    });

    const result = await detector.analyzeTransaction('ethereum', '0x1234');
    assert.ok(result);
    assert.equal(result.details.status, 'success');
    assert.equal(result.details.functionCalled, 'transfer');
  });
});

// ═══════════════════════════════════════════
// CCTP Analyzer Tests
// ═══════════════════════════════════════════

describe('CCTPAnalyzer', () => {
  let analyzer;
  let mockRpc;

  beforeEach(() => {
    mockRpc = new MockRpcClient();
    analyzer = new CCTPAnalyzer(mockRpc);
  });

  it('should get CCTP domain info', () => {
    const info = analyzer.getDomainInfo('ethereum');
    assert.equal(info.chain, 'ethereum');
    assert.equal(info.domainId, 0);
    assert.ok(info.tokenMessenger);
  });

  it('should analyze cross-chain activity with no results', async () => {
    const result = await analyzer.analyzeCrossChainActivity(
      '0x1111111111111111111111111111111111111111'
    );
    assert.ok(result);
    assert.equal(result.summary.hasCCTPActivity, false);
    assert.equal(result.patterns.length, 0);
  });

  it('should detect rapid bridging', () => {
    const deposits = [];
    for (let i = 0; i < 5; i++) {
      deposits.push({
        txHash: `0x${i}`,
        blockNumber: 1000 + i * 2,
        sourceChain: 'ethereum',
      });
    }

    const result = analyzer._detectRapidBridging(deposits);
    assert.ok(result, 'Should detect rapid bridging');
    assert.equal(result.type, 'RAPID_BRIDGING');
  });

  it('should detect chain hopping', () => {
    const deposits = [
      { txHash: '0x1', blockNumber: 1000, sourceChain: 'ethereum' },
      { txHash: '0x2', blockNumber: 2000, sourceChain: 'base' },
      { txHash: '0x3', blockNumber: 3000, sourceChain: 'arbitrum' },
    ];

    const result = analyzer._detectChainHopping(deposits);
    assert.ok(result, 'Should detect chain hopping');
    assert.equal(result.type, 'CHAIN_HOPPING');
  });

  it('should not flag single-chain usage as chain hopping', () => {
    const deposits = [
      { txHash: '0x1', blockNumber: 1000, sourceChain: 'ethereum' },
      { txHash: '0x2', blockNumber: 2000, sourceChain: 'ethereum' },
    ];

    const result = analyzer._detectChainHopping(deposits);
    assert.equal(result, null);
  });
});

// ═══════════════════════════════════════════
// Report Generator Tests
// ═══════════════════════════════════════════

describe('ReportGenerator', () => {
  it('should generate scan report', () => {
    const mockResult = {
      address: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      overallScore: 75,
      level: 'HIGH',
      chains: {
        ethereum: { usdcBalanceFormatted: 1000, txCount: 42, isContract: false, flags: [] },
      },
      patterns: [
        { type: 'WASH_TRADING', severity: 'high', detail: 'Test pattern', confidence: 80, riskImpact: 35 },
      ],
      cctpAnalysis: { summary: { hasCCTPActivity: false } },
      reputation: {
        scamMatch: null,
        interactions: [],
        riskFactors: [
          { factor: 'Test factor', impact: 20, detail: 'Test detail' },
        ],
      },
    };

    const report = ReportGenerator.formatScanReport(mockResult);
    assert.ok(report.includes('USDC SECURITY SCAN REPORT'));
    assert.ok(report.includes('LobSec'));
    assert.ok(report.includes('75/100'));
    assert.ok(report.includes('WASH_TRADING'));
  });

  it('should generate transfer validation report', () => {
    const mockValidation = {
      recipient: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      chain: 'base',
      amount: 5000,
      overallScore: 15,
      level: 'LOW',
      safe: true,
      recommendation: 'Transfer appears safe',
      flags: [],
    };

    const report = ReportGenerator.formatTransferValidation(mockValidation);
    assert.ok(report.includes('TRANSFER SAFETY CHECK'));
    assert.ok(report.includes('TRANSFER APPEARS SAFE'));
  });

  it('should generate reputation report', () => {
    const mockReputation = {
      address: '0xcccccccccccccccccccccccccccccccccccccccc',
      overallScore: 45,
      level: 'MEDIUM',
      flags: ['SOME_FLAG'],
      scamMatch: null,
      chains: {
        ethereum: { txCount: 10, usdcBalanceFormatted: 500, isContract: false },
      },
    };

    const report = ReportGenerator.formatReputationReport(mockReputation);
    assert.ok(report.includes('REPUTATION REPORT'));
    assert.ok(report.includes('45/100'));
  });

  it('should output JSON format', () => {
    const result = ReportGenerator.toJSON({ address: '0xtest', score: 50 });
    assert.ok(result.version);
    assert.ok(result.scanner.includes('LobSec'));
    assert.ok(result.timestamp);
  });
});

// ═══════════════════════════════════════════
// Constants Tests
// ═══════════════════════════════════════════

describe('Constants', () => {
  it('should have valid risk levels', () => {
    assert.ok(RISK_LEVELS.CLEAN);
    assert.ok(RISK_LEVELS.LOW);
    assert.ok(RISK_LEVELS.MEDIUM);
    assert.ok(RISK_LEVELS.HIGH);
    assert.ok(RISK_LEVELS.CRITICAL);
    
    // Ensure no gaps
    assert.equal(RISK_LEVELS.CLEAN.max + 1, RISK_LEVELS.LOW.min);
    assert.equal(RISK_LEVELS.LOW.max + 1, RISK_LEVELS.MEDIUM.min);
    assert.equal(RISK_LEVELS.MEDIUM.max + 1, RISK_LEVELS.HIGH.min);
    assert.equal(RISK_LEVELS.HIGH.max + 1, RISK_LEVELS.CRITICAL.min);
  });

  it('should support expected chains', () => {
    assert.ok(SUPPORTED_CHAINS.includes('ethereum'));
    assert.ok(SUPPORTED_CHAINS.includes('base'));
    assert.ok(SUPPORTED_CHAINS.includes('arbitrum'));
  });

  it('should have reasonable thresholds', () => {
    assert.ok(THRESHOLDS.WASH_TRADE_MIN_CYCLES >= 2);
    assert.ok(THRESHOLDS.FLASH_LOAN_MIN_AMOUNT >= 1000);
    assert.ok(THRESHOLDS.HIGH_VELOCITY_TXS_PER_HOUR >= 10);
    assert.ok(THRESHOLDS.LARGE_TRANSFER_USDC >= 10000);
  });
});

// ═══════════════════════════════════════════
// Integration Tests (with mock RPC)
// ═══════════════════════════════════════════

describe('Integration', () => {
  it('should run full scan on known scam address (offline)', async () => {
    // Create scanner with a mock that won't hit network
    const scanner = new USDCSecurityScanner();
    
    // Override the RPC client with mock
    const mockRpc = new MockRpcClient();
    mockRpc.setMock('getTransactionCount', 500);
    mockRpc.setMock('getUSDCBalance', '0');
    mockRpc.setMock('getBalance', '1000000000000000000');
    mockRpc.setMock('getUSDCTransfers', []);
    mockRpc.setMock('getCCTPDeposits', []);
    
    scanner.rpc = mockRpc;
    scanner.addressChecker = new AddressChecker(mockRpc);
    scanner.patternDetector = new PatternDetector(mockRpc);
    scanner.cctpAnalyzer = new CCTPAnalyzer(mockRpc);

    const result = await scanner.scanAddress(
      '0x098B716B8Aaf21512996dC57EB0615e2383E2f96',
      { chains: ['ethereum'], depth: 'deep' }
    );

    assert.ok(result.overallScore >= 90, `Expected critical score, got ${result.overallScore}`);
    assert.equal(result.level, 'CRITICAL');
    assert.ok(result.formatted.includes('Ronin'));
    assert.ok(result.formatted.includes('LobSec'));
  });

  it('should validate transfer to clean address (offline)', async () => {
    const scanner = new USDCSecurityScanner();
    const mockRpc = new MockRpcClient();
    mockRpc.setMock('getTransactionCount', 100);
    mockRpc.setMock('getUSDCBalance', '5000000000');
    mockRpc.setMock('getBalance', '2000000000000000000');
    
    scanner.rpc = mockRpc;
    scanner.addressChecker = new AddressChecker(mockRpc);

    const result = await scanner.validateTransfer(
      '0x1111111111111111111111111111111111111111',
      { amount: 100, chain: 'base' }
    );

    assert.ok(result.safe);
    assert.ok(result.overallScore < 40);
  });

  it('should block transfer to scam address (offline)', async () => {
    const scanner = new USDCSecurityScanner();
    const mockRpc = new MockRpcClient();
    mockRpc.setMock('getTransactionCount', 200);
    mockRpc.setMock('getUSDCBalance', '0');
    mockRpc.setMock('getBalance', '0');
    
    scanner.rpc = mockRpc;
    scanner.addressChecker = new AddressChecker(mockRpc);

    const result = await scanner.validateTransfer(
      '0x098B716B8Aaf21512996dC57EB0615e2383E2f96',
      { amount: 1000, chain: 'ethereum' }
    );

    assert.equal(result.safe, false);
    assert.ok(result.scamMatch);
    assert.ok(result.formatted.includes('DO NOT SEND'));
  });

  it('should block transfer to zero address', async () => {
    const scanner = new USDCSecurityScanner();
    const mockRpc = new MockRpcClient();
    mockRpc.setMock('getTransactionCount', 0);
    mockRpc.setMock('getUSDCBalance', '0');
    mockRpc.setMock('getBalance', '0');
    
    scanner.rpc = mockRpc;
    scanner.addressChecker = new AddressChecker(mockRpc);

    const result = await scanner.validateTransfer(
      '0x0000000000000000000000000000000000000000',
      { chain: 'base' }
    );

    assert.equal(result.safe, false);
    assert.ok(result.flags.includes('BURN_ADDRESS'));
  });
});

// ═══════════════════════════════════════════
// Contracts Data Tests
// ═══════════════════════════════════════════

describe('Contract Data', () => {
  it('should have valid USDC addresses for all chains', () => {
    const data = require('../data/contracts.json');
    
    for (const chain of SUPPORTED_CHAINS) {
      assert.ok(data.usdc[chain], `Missing USDC data for ${chain}`);
      assert.ok(data.usdc[chain].mainnet, `Missing mainnet USDC for ${chain}`);
      assert.ok(data.usdc[chain].sepolia, `Missing sepolia USDC for ${chain}`);
      assert.match(data.usdc[chain].mainnet, /^0x[0-9a-fA-F]{40}$/);
    }
  });

  it('should have CCTP contract addresses', () => {
    const data = require('../data/contracts.json');
    assert.ok(data.cctp);
    assert.ok(data.cctp.tokenMessenger);
    assert.ok(data.cctp.messageTransmitter);
    assert.ok(data.cctp.domainIds);
  });

  it('should have RPC endpoints for all chains', () => {
    const data = require('../data/contracts.json');
    
    for (const chain of SUPPORTED_CHAINS) {
      assert.ok(data.rpcEndpoints[chain], `Missing RPC for ${chain}`);
      assert.ok(data.rpcEndpoints[chain].mainnet);
      assert.ok(data.rpcEndpoints[chain].sepolia);
    }
  });
});
