'use strict';

const https = require('https');
const http = require('http');
const contractsData = require('../data/contracts.json');

/**
 * Minimal JSON-RPC client — zero external dependencies.
 * Supports Ethereum, Base, and Arbitrum via public RPCs or Alchemy.
 */
class RpcClient {
  constructor(options = {}) {
    this.endpoints = {};
    this.useTestnet = options.testnet ?? false;
    this.alchemyKey = options.alchemyKey || process.env.ALCHEMY_API_KEY;
    this.requestId = 0;
    this.rateLimitDelay = options.rateLimitDelay ?? 250; // ms between requests
    this.lastRequestTime = {};
    
    this._initEndpoints();
  }

  _initEndpoints() {
    const network = this.useTestnet ? 'sepolia' : 'mainnet';
    
    for (const chain of ['ethereum', 'base', 'arbitrum']) {
      if (this.alchemyKey) {
        const alchemyChain = chain === 'ethereum' ? 'eth' : chain === 'base' ? 'base' : 'arb';
        const alchemyNet = this.useTestnet ? 'sepolia' : 'mainnet';
        this.endpoints[chain] = `https://${alchemyChain}-${alchemyNet}.g.alchemy.com/v2/${this.alchemyKey}`;
      } else {
        this.endpoints[chain] = contractsData.rpcEndpoints[chain][network];
      }
      this.lastRequestTime[chain] = 0;
    }
  }

  async _rateLimit(chain) {
    const now = Date.now();
    const elapsed = now - this.lastRequestTime[chain];
    if (elapsed < this.rateLimitDelay) {
      await new Promise(r => setTimeout(r, this.rateLimitDelay - elapsed));
    }
    this.lastRequestTime[chain] = Date.now();
  }

  /**
   * Send a raw JSON-RPC request
   */
  async call(chain, method, params = []) {
    if (!this.endpoints[chain]) {
      throw new Error(`Unsupported chain: ${chain}`);
    }

    await this._rateLimit(chain);

    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id: ++this.requestId,
      method,
      params,
    });

    return new Promise((resolve, reject) => {
      const url = new URL(this.endpoints[chain]);
      const transport = url.protocol === 'https:' ? https : http;
      
      const req = transport.request(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
        timeout: 30000,
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            if (json.error) {
              reject(new Error(`RPC error (${chain}): ${json.error.message || JSON.stringify(json.error)}`));
            } else {
              resolve(json.result);
            }
          } catch (e) {
            reject(new Error(`Failed to parse RPC response from ${chain}: ${e.message}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`RPC timeout for ${chain}`));
      });
      req.write(payload);
      req.end();
    });
  }

  /**
   * Get the current block number
   */
  async getBlockNumber(chain) {
    const hex = await this.call(chain, 'eth_blockNumber');
    return parseInt(hex, 16);
  }

  /**
   * Get transaction by hash
   */
  async getTransaction(chain, txHash) {
    return this.call(chain, 'eth_getTransactionByHash', [txHash]);
  }

  /**
   * Get transaction receipt
   */
  async getTransactionReceipt(chain, txHash) {
    return this.call(chain, 'eth_getTransactionReceipt', [txHash]);
  }

  /**
   * Get code at address (to check if contract)
   */
  async getCode(chain, address) {
    return this.call(chain, 'eth_getCode', [address, 'latest']);
  }

  /**
   * Check if address is a contract
   */
  async isContract(chain, address) {
    const code = await this.getCode(chain, address);
    return code && code !== '0x' && code !== '0x0';
  }

  /**
   * Get ERC-20 balance (USDC)
   */
  async getUSDCBalance(chain, address) {
    const network = this.useTestnet ? 'sepolia' : 'mainnet';
    const usdcAddress = contractsData.usdc[chain]?.[network];
    if (!usdcAddress) return '0';

    // balanceOf(address) selector = 0x70a08231
    const paddedAddress = address.toLowerCase().replace('0x', '').padStart(64, '0');
    const data = `0x70a08231${paddedAddress}`;

    const result = await this.call(chain, 'eth_call', [
      { to: usdcAddress, data },
      'latest',
    ]);

    return result ? BigInt(result).toString() : '0';
  }

  /**
   * Get USDC transfer logs for an address
   */
  async getUSDCTransfers(chain, address, fromBlock = 'earliest', toBlock = 'latest', limit = 100) {
    const network = this.useTestnet ? 'sepolia' : 'mainnet';
    const usdcAddress = contractsData.usdc[chain]?.[network];
    if (!usdcAddress) return [];

    const paddedAddress = '0x' + address.toLowerCase().replace('0x', '').padStart(64, '0');
    const transferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

    // Get transfers FROM this address
    const sentLogs = await this.call(chain, 'eth_getLogs', [{
      address: usdcAddress,
      topics: [transferTopic, paddedAddress],
      fromBlock: typeof fromBlock === 'number' ? '0x' + fromBlock.toString(16) : fromBlock,
      toBlock: typeof toBlock === 'number' ? '0x' + toBlock.toString(16) : toBlock,
    }]).catch(() => []);

    // Get transfers TO this address
    const receivedLogs = await this.call(chain, 'eth_getLogs', [{
      address: usdcAddress,
      topics: [transferTopic, null, paddedAddress],
      fromBlock: typeof fromBlock === 'number' ? '0x' + fromBlock.toString(16) : fromBlock,
      toBlock: typeof toBlock === 'number' ? '0x' + toBlock.toString(16) : toBlock,
    }]).catch(() => []);

    const allLogs = [...(sentLogs || []), ...(receivedLogs || [])];
    
    return allLogs.slice(0, limit).map(log => ({
      txHash: log.transactionHash,
      blockNumber: parseInt(log.blockNumber, 16),
      from: '0x' + (log.topics[1] || '').slice(26),
      to: '0x' + (log.topics[2] || '').slice(26),
      amount: log.data ? BigInt(log.data).toString() : '0',
      amountUSDC: log.data ? Number(BigInt(log.data)) / 1e6 : 0,
      logIndex: parseInt(log.logIndex, 16),
    }));
  }

  /**
   * Get CCTP DepositForBurn events (cross-chain transfers)
   */
  async getCCTPDeposits(chain, address, fromBlock = 'earliest', toBlock = 'latest') {
    const network = this.useTestnet ? 'sepolia' : 'mainnet';
    const tokenMessenger = contractsData.cctp?.tokenMessenger?.[chain]?.[network];
    if (!tokenMessenger) return [];

    const depositTopic = '0x2fa9ca894982930190727e75500a97d8dc500233a5065e0f3126c48fbe0343c0';

    const logs = await this.call(chain, 'eth_getLogs', [{
      address: tokenMessenger,
      topics: [depositTopic],
      fromBlock: typeof fromBlock === 'number' ? '0x' + fromBlock.toString(16) : fromBlock,
      toBlock: typeof toBlock === 'number' ? '0x' + toBlock.toString(16) : toBlock,
    }]).catch(() => []);

    return (logs || []).map(log => ({
      txHash: log.transactionHash,
      blockNumber: parseInt(log.blockNumber, 16),
      sourceChain: chain,
      raw: log,
    }));
  }

  /**
   * Get the nonce (transaction count) for an address
   */
  async getTransactionCount(chain, address) {
    const hex = await this.call(chain, 'eth_getTransactionCount', [address, 'latest']);
    return parseInt(hex, 16);
  }

  /**
   * Get ETH balance
   */
  async getBalance(chain, address) {
    const hex = await this.call(chain, 'eth_getBalance', [address, 'latest']);
    return BigInt(hex).toString();
  }

  /**
   * Get block by number
   */
  async getBlock(chain, blockNumber, full = false) {
    const blockHex = typeof blockNumber === 'number' 
      ? '0x' + blockNumber.toString(16) 
      : blockNumber;
    return this.call(chain, 'eth_getBlockByNumber', [blockHex, full]);
  }
}

module.exports = { RpcClient };
