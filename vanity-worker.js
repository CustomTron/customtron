/* vanity-worker.js — CustomTron browser vanity generator (optimized) */
/* Uses noble-secp256k1 via dynamic import for ~50x faster key generation */
"use strict";

let secp, keccak_256_fn;

async function init() {
  const noble = await import("https://esm.sh/@noble/secp256k1@1.7.1");
  secp = noble;
  const hashes = await import("https://esm.sh/@noble/hashes@1.3.3/sha3");
  keccak_256_fn = hashes.keccak_256;
  // Also need sha256 for base58check
  const sha2 = await import("https://esm.sh/@noble/hashes@1.3.3/sha256");
  sha256_fn = sha2.sha256;
}

let sha256_fn;

/* ── Base58 ── */
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(payload) {
  let num = 0n;
  for (const b of payload) num = num * 256n + BigInt(b);
  let str = "";
  while (num > 0n) { str = B58[Number(num % 58n)] + str; num /= 58n; }
  for (const b of payload) { if (b !== 0) break; str = "1" + str; }
  return str;
}

function bytesToHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function privToAddress(privBytes) {
  try {
    // Get uncompressed public key (65 bytes: 04 || x || y)
    const pubBytes = secp.getPublicKey(privBytes, false);
    // Skip 04 prefix → 64 bytes
    const pubNoPrefix = pubBytes.slice(1);
    // Keccak256
    const hash = keccak_256_fn(pubNoPrefix);
    // Take last 20 bytes, prepend 0x41 (TRON mainnet)
    const addr21 = new Uint8Array(21);
    addr21[0] = 0x41;
    addr21.set(hash.slice(12), 1);
    // Double SHA-256 checksum
    const h1 = sha256_fn(addr21);
    const h2 = sha256_fn(h1);
    const full = new Uint8Array(25);
    full.set(addr21);
    full.set(h2.slice(0, 4), 21);
    return base58Encode(full);
  } catch(e) {
    return null;
  }
}

/* ── Worker message handler ── */
let running = false;

self.onmessage = async function(e) {
  const msg = e.data;
  if (msg.cmd === 'start') {
    if (!secp) await init();
    running = true;
    generate(msg.prefix || '', msg.suffix || '', !!msg.caseSensitive);
  } else if (msg.cmd === 'stop') {
    running = false;
  }
};

function generate(prefix, suffix, caseSensitive) {
  const matchPrefix = caseSensitive ? prefix : prefix.toLowerCase();
  const matchSuffix = caseSensitive ? suffix : suffix.toLowerCase();
  let count = 0;
  let lastReport = Date.now();
  let lastReportCount = 0;
  const startTime = Date.now();
  const batchSize = 100;

  function batch() {
    if (!running) return;
    for (let i = 0; i < batchSize; i++) {
      count++;
      const privBytes = secp.utils.randomPrivateKey();
      const addr = privToAddress(privBytes);
      if (!addr) continue;

      const addrCheck = caseSensitive ? addr : addr.toLowerCase();
      const prefixOk = matchPrefix ? addrCheck.substring(1, 1 + matchPrefix.length) === matchPrefix : true;
      const suffixOk = matchSuffix ? addrCheck.endsWith(matchSuffix) : true;

      if (prefixOk && suffixOk) {
        running = false;
        self.postMessage({
          type: 'result',
          address: addr,
          privateKey: bytesToHex(privBytes),
          attempts: count
        });
        return;
      }
    }
    // Progress report every 500ms
    const now = Date.now();
    if (now - lastReport >= 500) {
      const intervalMs = now - lastReport;
      const intervalCount = count - lastReportCount;
      self.postMessage({
        type: 'progress',
        attempts: count,
        speed: Math.round(intervalCount / (intervalMs / 1000))
      });
      lastReport = now;
      lastReportCount = count;
    }
    setTimeout(batch, 0);
  }
  batch();
}
