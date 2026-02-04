'use strict';

// ERC-20 Transfer event signature
const TRANSFER_EVENT_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

// ERC-20 Approval event signature
const APPROVAL_EVENT_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';

// CCTP DepositForBurn event signature
const DEPOSIT_FOR_BURN_TOPIC = '0x2fa9ca894982930190727e75500a97d8dc500233a5065e0f3126c48fbe0343c0';

// CCTP MessageReceived event signature
const MESSAGE_RECEIVED_TOPIC = '0x58200b4c34ae05ee816d710053fff3fb75af4395915d3d2a771b24aa10e3cc5b';

// Risk level thresholds
const RISK_LEVELS = {
  CLEAN:    { min: 0,  max: 9,   label: 'CLEAN',    emoji: '✅' },
  LOW:      { min: 10, max: 39,  label: 'LOW',      emoji: '🟡' },
  MEDIUM:   { min: 40, max: 69,  label: 'MEDIUM',   emoji: '🟠' },
  HIGH:     { min: 70, max: 89,  label: 'HIGH',     emoji: '🔴' },
  CRITICAL: { min: 90, max: 100, label: 'CRITICAL', emoji: '🚨' },
};

// Severity weights for risk score calculation
const SEVERITY_WEIGHTS = {
  critical: 95,
  high: 75,
  medium: 45,
  low: 20,
  info: 5,
};

// Pattern detection thresholds
const THRESHOLDS = {
  // Wash trading
  WASH_TRADE_MIN_CYCLES: 3,
  WASH_TRADE_TIME_WINDOW_MS: 3600000, // 1 hour
  WASH_TRADE_AMOUNT_TOLERANCE: 0.01, // 1% tolerance for "same amount"
  
  // Flash loans
  FLASH_LOAN_BLOCK_WINDOW: 1, // Same block
  FLASH_LOAN_MIN_AMOUNT: 10000, // $10K USDC minimum to flag
  
  // Honeypot
  HONEYPOT_SELL_FAIL_RATIO: 0.5, // >50% failed sells = honeypot
  HONEYPOT_MIN_TRANSACTIONS: 10, // Need at least 10 txs to evaluate
  
  // Address age
  NEW_ADDRESS_THRESHOLD_DAYS: 7,
  
  // Transaction velocity
  HIGH_VELOCITY_TXS_PER_HOUR: 20,
  
  // Large transfer (triggers enhanced checks)
  LARGE_TRANSFER_USDC: 50000,
  
  // Circular flow detection
  CIRCULAR_FLOW_MAX_HOPS: 5,
  CIRCULAR_FLOW_TIME_WINDOW_MS: 86400000, // 24 hours
};

// USDC decimals
const USDC_DECIMALS = 6;

// Supported chains
const SUPPORTED_CHAINS = ['ethereum', 'base', 'arbitrum'];

// ABI fragments for USDC
const USDC_ABI = {
  transfer: 'function transfer(address to, uint256 amount) returns (bool)',
  approve: 'function approve(address spender, uint256 amount) returns (bool)',
  balanceOf: 'function balanceOf(address account) view returns (uint256)',
  allowance: 'function allowance(address owner, address spender) view returns (uint256)',
  totalSupply: 'function totalSupply() view returns (uint256)',
  name: 'function name() view returns (string)',
  symbol: 'function symbol() view returns (string)',
  decimals: 'function decimals() view returns (uint8)',
};

// Function selectors (first 4 bytes of keccak256)
const FUNCTION_SELECTORS = {
  transfer: '0xa9059cbb',
  approve: '0x095ea7b3',
  transferFrom: '0x23b872dd',
  permit: '0xd505accf',
  // CCTP
  depositForBurn: '0x6fd3504e',
  receiveMessage: '0x57ecfd28',
};

module.exports = {
  TRANSFER_EVENT_TOPIC,
  APPROVAL_EVENT_TOPIC,
  DEPOSIT_FOR_BURN_TOPIC,
  MESSAGE_RECEIVED_TOPIC,
  RISK_LEVELS,
  SEVERITY_WEIGHTS,
  THRESHOLDS,
  USDC_DECIMALS,
  SUPPORTED_CHAINS,
  USDC_ABI,
  FUNCTION_SELECTORS,
};
