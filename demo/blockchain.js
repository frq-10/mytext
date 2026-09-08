/**
 * 区块链模拟引擎（浏览器端）
 * 用 Web Crypto API 实现 SHA-256，localStorage 持久化账本，
 * 完整模拟：区块结构、哈希链、交易(TxID)、不可篡改校验、审计留痕。
 */

const STORAGE_KEY = 'gov_cert_chain_v1';

// ---------------- 工具函数 ----------------

/** 计算任意字符串的 SHA-256 哈希，返回 64 位十六进制串 */
async function sha256(text) {
  const buf = new TextEncoder().encode(text);
  const hashBuf = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** 生成唯一交易 ID (TxID) */
function makeTxId() {
  return (
    Date.now().toString(16) +
    Math.random().toString(16).slice(2, 10) +
    Math.random().toString(16).slice(2, 6)
  );
}

/** 格式化时间戳 */
function fmtTime(ts) {
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return (
    d.getFullYear() +
    '-' +
    pad(d.getMonth() + 1) +
    '-' +
    pad(d.getDate()) +
    ' ' +
    pad(d.getHours()) +
    ':' +
    pad(d.getMinutes()) +
    ':' +
    pad(d.getSeconds())
  );
}

// ---------------- 区块 ----------------

class Block {
  constructor(index, transactions, previousHash) {
    this.index = index;
    this.timestamp = Date.now();
    this.transactions = transactions;
    this.previousHash = previousHash;
    this.nonce = 0;
    this.hash = '';
  }

  /** 计算本区块哈希：index + timestamp + txs + previousHash + nonce */
  async calculateHash() {
    const payload =
      this.index +
      this.timestamp +
      JSON.stringify(this.transactions) +
      this.previousHash +
      this.nonce;
    return sha256(payload);
  }
}

// ---------------- 区块链 ----------------

class Blockchain {
  constructor() {
    this.chain = [];
    this._load();
    if (this.chain.length === 0) {
      this.chain.push(this._genesisBlock());
      this._save();
    }
  }

  _genesisBlock() {
    const b = new Block(0, [{ type: 'GENESIS', desc: '政务区块链可信数据共享平台 - 创世区块', ts: Date.now() }], '0'.repeat(64));
    // 异步计算创世区块哈希（构造函数无法 await，首次加载后补全）
    b.calculateHash().then((h) => { b.hash = h; this._save(); });
    return b;
  }

  _load() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) this.chain = JSON.parse(raw);
    } catch (e) {
      this.chain = [];
    }
  }

  _save() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(this.chain));
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  /** 把若干交易打包成新区块并上链（模拟出块） */
  async addTransactions(txs) {
    const prev = this.getLatestBlock();
    // 若前驱区块（如创世块）尚未计算哈希，先补算
    if (!prev.hash) {
      prev.hash = await prev.calculateHash();
      this._save();
    }
    const block = new Block(this.chain.length, txs, prev.hash);
    // 模拟挖矿：简单增加 nonce 直到哈希以 '0000' 开头（轻量共识演示）
    let hash = '';
    while (!hash.startsWith('0000')) {
      block.nonce++;
      hash = await block.calculateHash();
    }
    block.hash = hash;
    this.chain.push(block);
    this._save();
    return block;
  }

  /** 校验整条链是否被篡改 */
  async isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const cur = this.chain[i];
      const prev = this.chain[i - 1];
      // 重新计算当前区块哈希
      const recomputed = await new Block(0, [], '').constructor.prototype.calculateHash.call({
        index: cur.index,
        timestamp: cur.timestamp,
        transactions: cur.transactions,
        previousHash: cur.previousHash,
        nonce: cur.nonce,
      });
      if (recomputed !== cur.hash) {
        return { valid: false, reason: `区块 #${cur.index} 哈希不匹配，数据被篡改` };
      }
      if (cur.previousHash !== prev.hash) {
        return { valid: false, reason: `区块 #${cur.index} 前驱哈希断裂` };
      }
    }
    return { valid: true, reason: '链上数据完整，未被篡改' };
  }

  /** 按权证编号查找存证交易 */
  findCertificate(certNo) {
    for (const block of this.chain) {
      for (const tx of block.transactions) {
        if (tx.type === 'CERT_UPLOAD' && tx.payload && tx.payload.certNo === certNo) {
          return { tx, block };
        }
      }
    }
    return null;
  }

  /** 获取所有交易（按时间倒序） */
  getAllTransactions() {
    const list = [];
    for (const block of this.chain) {
      for (const tx of block.transactions) {
        list.push({ ...tx, blockNumber: block.index, blockHash: block.hash, blockTime: block.timestamp });
      }
    }
    return list.sort((a, b) => b.ts - a.ts);
  }

  /** 重置链（清空所有数据） */
  reset() {
    localStorage.removeItem(STORAGE_KEY);
    this.chain = [];
    this.chain.push(this._genesisBlock());
    this._save();
  }
}

// 导出到全局
window.ChainUtil = { sha256, makeTxId, fmtTime, Blockchain, Block };
