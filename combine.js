#!/usr/bin/env node
/**
 * CustomTron — Offline Split-Key Combiner & Verifier
 *
 * Combines your Generation Private Key with the server's encrypted half,
 * entirely offline, and verifies the result matches your vanity address.
 * No network. No external dependencies. Pure algorithm — audit it yourself.
 *
 * The cryptography here mirrors the published browser module (crypto.js)
 * exactly, so the offline result is byte-identical to the in-browser result.
 *
 * Usage (recommended — decrypts the server half locally):
 *   node combine.js \
 *     --client-privkey <64-hex> \
 *     --encrypted-server-priv <base64-blob> \
 *     --expected-address <TXxx>
 *
 * Usage (if you already have the server half in plaintext hex):
 *   node combine.js \
 *     --client-privkey <64-hex> \
 *     --server-privkey <64-hex> \
 *     --expected-address <TXxx>
 *
 * Exit codes:
 *   0 — address matches, safe to import into your wallet
 *   1 — mismatch or error, do NOT import
 *
 * Where to get the inputs:
 *   --client-privkey         = the Generation Private Key you saved during ordering
 *   --encrypted-server-priv  = the server key share shown on your claim page
 *   --expected-address       = your vanity address (the one with your pattern)
 */

'use strict';

const nodeCrypto = require('crypto');

// ───────────────────────────────────────────────────────────────────
// secp256k1 — identical parameters & point math to crypto.js
// ───────────────────────────────────────────────────────────────────
const P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function mod(a, b = P) { return ((a % b) + b) % b; }
function pow(base, exp, m) {
  let r = 1n; base = mod(base, m);
  while (exp > 0n) { if (exp & 1n) r = mod(r * base, m); exp >>= 1n; base = mod(base * base, m); }
  return r;
}
function inv(n, m = P) { return pow(n, m - 2n, m); }

class Point {
  constructor(x, y) { this.x = x; this.y = y; }
  static ZERO = new Point(0n, 0n);
  isZero() { return this.x === 0n && this.y === 0n; }
  add(other) {
    if (this.isZero()) return other;
    if (other.isZero()) return this;
    if (this.x === other.x) {
      if (this.y !== other.y) return Point.ZERO;
      const lam = mod(3n * this.x * this.x * inv(2n * this.y));
      const x3 = mod(lam * lam - 2n * this.x);
      return new Point(x3, mod(lam * (this.x - x3) - this.y));
    }
    const lam = mod((other.y - this.y) * inv(other.x - this.x));
    const x3 = mod(lam * lam - this.x - other.x);
    return new Point(x3, mod(lam * (this.x - x3) - this.y));
  }
  mul(k) {
    let r = Point.ZERO, p = this;
    while (k > 0n) { if (k & 1n) r = r.add(p); p = p.add(p); k >>= 1n; }
    return r;
  }
}
const G = new Point(Gx, Gy);

// ───────────────────────────────────────────────────────────────────
// Keccak-256 — copied verbatim from crypto.js (must match byte-for-byte)
// ───────────────────────────────────────────────────────────────────
function keccak256(data) {
  const RC = [
    1n,0x8082n,0x800000000000808an,0x8000000080008000n,0x808bn,0x80000001n,
    0x8000000080008081n,0x8000000000008009n,0x8an,0x88n,0x80008009n,0x8000000an,
    0x8000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,
    0x8000000000008002n,0x8000000000000080n,0x800an,0x800000008000000an,
    0x8000000080008081n,0x8000000000008080n,0x80000001n,0x8000000080008008n
  ];
  const ROT = [
    [0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]
  ];
  const msg = (data instanceof Uint8Array) ? data : new TextEncoder().encode(data);
  const rate = 136;
  const padLen = rate - (msg.length % rate);
  const padded = new Uint8Array(msg.length + padLen);
  padded.set(msg);
  padded[msg.length] = 0x01;
  padded[padded.length - 1] |= 0x80;
  const state = Array.from({length:5},()=>Array(5).fill(0n));
  const dv = new DataView(padded.buffer);
  for (let block = 0; block < padded.length; block += rate) {
    for (let i = 0; i < rate/8; i++) {
      const lo = BigInt(dv.getUint32(block+i*8, true));
      const hi = BigInt(dv.getUint32(block+i*8+4, true));
      state[i%5][Math.floor(i/5)] ^= lo | (hi << 32n);
    }
    for (let round = 0; round < 24; round++) {
      const C = state.map(row => row.reduce((a,b)=>a^b,0n));
      const D = C.map((_,x)=>C[(x+4)%5]^rotl64(C[(x+1)%5],1n));
      for(let x=0;x<5;x++)for(let y=0;y<5;y++) state[x][y]^=D[x];
      const B = Array.from({length:5},()=>Array(5).fill(0n));
      for(let x=0;x<5;x++)for(let y=0;y<5;y++) B[y][(2*x+3*y)%5]=rotl64(state[x][y],BigInt(ROT[x][y]));
      for(let x=0;x<5;x++)for(let y=0;y<5;y++) state[x][y]=B[x][y]^(~B[(x+1)%5][y]&B[(x+2)%5][y]);
      state[0][0]^=RC[round];
    }
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for(let i=0;i<4;i++){
    const v=state[i%5][Math.floor(i/5)];
    ov.setUint32(i*8,Number(v&0xFFFFFFFFn),true);
    ov.setUint32(i*8+4,Number((v>>32n)&0xFFFFFFFFn),true);
  }
  return out;
}
function rotl64(x,n){return((x<<n)|(x>>(64n-n)))&0xFFFFFFFFFFFFFFFFn;}

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────
function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) out[i/2] = parseInt(hex.slice(i, i+2), 16);
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
}

// ───────────────────────────────────────────────────────────────────
// Base58Check — TRON address (sha256 via Node, identical output)
// ───────────────────────────────────────────────────────────────────
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) { digits.push(carry % 58); carry = Math.floor(carry / 58); }
  }
  let r = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) r += BASE58[digits[i]];
  return r;
}
function sha256(buf) { return new Uint8Array(nodeCrypto.createHash('sha256').update(buf).digest()); }

function deriveTronAddress(privKeyHex) {
  const priv = BigInt('0x' + privKeyHex);
  const pub  = G.mul(priv);
  const pubBytes = new Uint8Array(64);
  pubBytes.set(hexToBytes(pub.x.toString(16).padStart(64,'0')), 0);
  pubBytes.set(hexToBytes(pub.y.toString(16).padStart(64,'0')), 32);
  const hash   = keccak256(pubBytes);
  const addr20 = hash.slice(12);
  const payload = new Uint8Array(21);
  payload[0] = 0x41;
  payload.set(addr20, 1);
  const chk = sha256(sha256(payload)).slice(0, 4);
  const full = new Uint8Array(25);
  full.set(payload, 0); full.set(chk, 21);
  return base58Encode(full);
}

// ───────────────────────────────────────────────────────────────────
// ECIES decrypt — mirrors crypto.js decryptServerPriv exactly.
// Blob layout: ephPub(65) || iv(16) || tag(16) || ciphertext
// HKDF-SHA256 input = ephPubUncompressed(65) || sharedPointUncompressed(65)
// (salt = empty, info = empty) → AES-256-GCM
// ───────────────────────────────────────────────────────────────────
function decryptServerPriv(clientPrivHex, encryptedBase64) {
  const ct = Uint8Array.from(Buffer.from(encryptedBase64, 'base64'));
  const ephPubUncompressed = ct.slice(0, 65);
  const iv      = ct.slice(65, 81);
  const tag      = ct.slice(81, 97);
  const encBody = ct.slice(97);

  const ephX = BigInt('0x' + bytesToHex(ephPubUncompressed.slice(1, 33)));
  const ephY = BigInt('0x' + bytesToHex(ephPubUncompressed.slice(33, 65)));
  const ephPub = new Point(ephX, ephY);

  const clientPriv = BigInt('0x' + clientPrivHex);
  const shared = ephPub.mul(clientPriv);
  const sharedXBytes = hexToBytes(shared.x.toString(16).padStart(64,'0'));
  const sharedYBytes = hexToBytes(shared.y.toString(16).padStart(64,'0'));
  const sharedPoint = new Uint8Array([0x04, ...sharedXBytes, ...sharedYBytes]);
  const hkdfInput = new Uint8Array([...ephPubUncompressed, ...sharedPoint]);

  // HKDF-SHA256, empty salt, empty info, 32-byte output (Node API → same as WebCrypto)
  const aesKeyBuf = Buffer.from(
    nodeCrypto.hkdfSync('sha256', Buffer.from(hkdfInput), Buffer.alloc(0), Buffer.alloc(0), 32)
  );

  const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', aesKeyBuf, Buffer.from(iv));
  decipher.setAuthTag(Buffer.from(tag));
  const plain = Buffer.concat([decipher.update(Buffer.from(encBody)), decipher.final()]);
  return plain.toString('utf8');
}

// ───────────────────────────────────────────────────────────────────
// Combine: finalPriv = (clientPriv + serverPriv) mod N
// ───────────────────────────────────────────────────────────────────
function combinePrivateKeys(clientPrivHex, serverPrivHex) {
  const a = BigInt('0x' + clientPrivHex);
  const b = BigInt('0x' + serverPrivHex);
  const result = mod(a + b, N);
  if (result === 0n) throw new Error('Invalid key combination (result is zero)');
  return result.toString(16).padStart(64, '0');
}

// ───────────────────────────────────────────────────────────────────
// CLI
// ───────────────────────────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const r = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--client-privkey')          r.clientPrivkey = args[++i];
    else if (a === '--server-privkey')     r.serverPrivkey = args[++i];
    else if (a === '--encrypted-server-priv') r.encryptedServerPriv = args[++i];
    else if (a === '--expected-address')   r.expectedAddress = args[++i];
    else if (a === '--help' || a === '-h') r.help = true;
  }
  return r;
}

function usage() {
  console.log(`
CustomTron — Offline Split-Key Combiner

  node combine.js --client-privkey <hex> --encrypted-server-priv <base64> --expected-address <TXxx>

  or, if you already hold the server half in plaintext:

  node combine.js --client-privkey <hex> --server-privkey <hex> --expected-address <TXxx>

Run this offline. It makes no network calls and has no dependencies.
`);
}

function normalizeHex(h) {
  if (!h) return h;
  h = h.trim().toLowerCase();
  if (h.startsWith('0x')) h = h.slice(2);
  return h;
}

function main() {
  const args = parseArgs();
  if (args.help) { usage(); process.exit(0); }

  const clientPriv = normalizeHex(args.clientPrivkey);
  if (!clientPriv || !/^[0-9a-f]{64}$/.test(clientPriv)) {
    console.error('Error: --client-privkey must be 64 hex characters.');
    usage(); process.exit(1);
  }

  let serverPrivHex;
  if (args.encryptedServerPriv) {
    try {
      serverPrivHex = normalizeHex(decryptServerPriv(clientPriv, args.encryptedServerPriv));
    } catch (e) {
      console.error('Error: failed to decrypt the server half. Check that your client private key and the encrypted value are correct.');
      console.error('Detail:', e.message);
      process.exit(1);
    }
  } else if (args.serverPrivkey) {
    serverPrivHex = normalizeHex(args.serverPrivkey);
  } else {
    console.error('Error: provide either --encrypted-server-priv <base64> or --server-privkey <hex>.');
    usage(); process.exit(1);
  }

  if (!/^[0-9a-f]{64}$/.test(serverPrivHex)) {
    console.error('Error: server private key did not resolve to 64 hex characters.');
    process.exit(1);
  }

  const finalPrivHex = combinePrivateKeys(clientPriv, serverPrivHex);
  const derivedAddress = deriveTronAddress(finalPrivHex);

  console.log('');
  console.log('  Final private key :', finalPrivHex);
  console.log('  Derived address   :', derivedAddress);

  if (args.expectedAddress) {
    const expected = args.expectedAddress.trim();
    console.log('  Expected address  :', expected);
    console.log('');
    if (derivedAddress === expected) {
      console.log('  \u2705  MATCH — this private key controls your vanity address. Safe to import.');
      console.log('');
      process.exit(0);
    } else {
      console.log('  \u274C  MISMATCH — do NOT import. Re-check your inputs or contact support.');
      console.log('');
      process.exit(1);
    }
  } else {
    console.log('');
    console.log('  (No --expected-address given — skipping verification. Strongly recommended to pass it.)');
    console.log('');
  }
}

main();
