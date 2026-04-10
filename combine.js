#!/usr/bin/env node
/**
 * CustomTron — Split-Key Combination & Verification
 *
 * Combines client_privkey + server_privkey on the secp256k1 curve,
 * derives the TRON address, and verifies it matches the expected value.
 *
 * Usage:
 *   node combine.js --client-privkey <hex> --server-privkey <hex> --expected-address <TXxx>
 *
 * Exit codes:
 *   0 — address matches, safe to import
 *   1 — mismatch or error, do not import
 */

'use strict';

const crypto = require('crypto');
const { execSync } = require('child_process');

// ---------------------------------------------------------------------------
// Minimal secp256k1 + TRON address derivation (no external dependencies)
// ---------------------------------------------------------------------------

const P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function modpow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = result * base % mod;
    exp = exp / 2n;
    base = base * base % mod;
  }
  return result;
}

function modinv(a, m) {
  return modpow(((a % m) + m) % m, m - 2n, m);
}

// Elliptic curve point addition over secp256k1
function pointAdd(P1, P2) {
  if (P1 === null) return P2;
  if (P2 === null) return P1;
  const [x1, y1] = P1;
  const [x2, y2] = P2;
  if (x1 === x2) {
    if (y1 !== y2) return null; // point at infinity
    // Point doubling
    const lam = 3n * x1 * x1 % P * modinv(2n * y1, P) % P;
    const x3 = (lam * lam - 2n * x1 + P * 2n) % P;
    const y3 = (lam * (x1 - x3 + P) - y1 + P * 2n) % P;
    return [x3, y3];
  }
  const lam = ((y2 - y1 + P * 2n) % P) * modinv((x2 - x1 + P * 2n) % P, P) % P;
  const x3 = (lam * lam - x1 - x2 + P * 3n) % P;
  const y3 = (lam * (x1 - x3 + P * 2n) - y1 + P * 2n) % P;
  return [x3, y3];
}

// Scalar multiplication
function pointMul(k, point) {
  let result = null;
  let addend = point;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

// Parse uncompressed public key hex (04 xx yy) or compressed (02/03 xx)
function parsePublicKey(hex) {
  const buf = Buffer.from(hex, 'hex');
  if (buf[0] === 0x04 && buf.length === 65) {
    return [
      BigInt('0x' + buf.slice(1, 33).toString('hex')),
      BigInt('0x' + buf.slice(33, 65).toString('hex')),
    ];
  }
  if ((buf[0] === 0x02 || buf[0] === 0x03) && buf.length === 33) {
    const x = BigInt('0x' + buf.slice(1).toString('hex'));
    const ySquared = (modpow(x, 3n, P) + 7n) % P;
    let y = modpow(ySquared, (P + 1n) / 4n, P);
    if ((y % 2n === 0n) !== (buf[0] === 0x02)) y = P - y;
    return [x, y];
  }
  throw new Error('Invalid public key format. Expected 04<x><y> or 02/03<x>.');
}

// Serialize uncompressed public key
function serializePublicKey(point) {
  const [x, y] = point;
  const xHex = x.toString(16).padStart(64, '0');
  const yHex = y.toString(16).padStart(64, '0');
  return '04' + xHex + yHex;
}

// keccak256 (no external deps — uses Node.js built-in if available, else errors)
function keccak256(buf) {
  try {
    return crypto.createHash('sha3-256').update(buf).digest();
  } catch {
    // Node.js does not expose keccak256 directly — use a pure-JS fallback
    // In production the browser version uses crypto.js (SRI-verified)
    throw new Error(
      'keccak256 not available in this Node.js version.\n' +
      'Run: npm install keccak  then re-run this script.'
    );
  }
}

function keccak256WithFallback(buf) {
  // Try native Node.js keccak (available in some builds)
  try {
    const hash = crypto.createHash('keccak256').update(buf).digest();
    return hash;
  } catch {
    // Try installed keccak package
    try {
      const { keccak256: k } = require('ethereum-cryptography/keccak');
      return Buffer.from(k(buf));
    } catch {
      throw new Error(
        'keccak256 not available.\n' +
        'Install: npm install ethereum-cryptography\n' +
        'Then re-run: node combine.js ...'
      );
    }
  }
}

// TRON address derivation: keccak256(pubkey[1:]) → last 20 bytes → prepend 0x41 → Base58Check
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buf) {
  let num = BigInt('0x' + buf.toString('hex'));
  let result = '';
  while (num > 0n) {
    result = BASE58_ALPHABET[Number(num % 58n)] + result;
    num /= 58n;
  }
  for (const byte of buf) {
    if (byte !== 0) break;
    result = '1' + result;
  }
  return result;
}

function base58CheckEncode(payload) {
  const checksum = crypto.createHash('sha256')
    .update(crypto.createHash('sha256').update(payload).digest())
    .digest()
    .slice(0, 4);
  return base58Encode(Buffer.concat([payload, checksum]));
}

function pubkeyToTronAddress(pubkeyHex) {
  const pubkeyBuf = Buffer.from(pubkeyHex.startsWith('04') ? pubkeyHex.slice(2) : pubkeyHex, 'hex');
  const hash = keccak256WithFallback(pubkeyBuf);
  const addressBytes = Buffer.concat([Buffer.from([0x41]), hash.slice(-20)]);
  return base58CheckEncode(addressBytes);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function parseArgs() {
  const args = process.argv.slice(2);
  const result = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--client-privkey') result.clientPrivkey = args[++i];
    else if (args[i] === '--server-privkey') result.serverPrivkey = args[++i];
    else if (args[i] === '--expected-address') result.expectedAddress = args[++i];
    else if (args[i] === '--client-pubkey') result.clientPubkey = args[++i];
  }
  return result;
}

function main() {
  const args = parseArgs();

  if (!args.clientPrivkey || !args.serverPrivkey) {
    console.error('Usage: node combine.js --client-privkey <hex> --server-privkey <hex> [--expected-address <TXxx>]');
    process.exit(1);
  }

  const clientPriv = BigInt('0x' + args.clientPrivkey);
  const serverPriv = BigInt('0x' + args.serverPrivkey);

  // Combine private keys
  const finalPriv = (clientPriv + serverPriv) % N;
  const finalPrivHex = finalPriv.toString(16).padStart(64, '0');

  // Derive public keys
  const G = [Gx, Gy];
  const clientPub = pointMul(clientPriv, G);
  const serverPub = pointMul(serverPriv, G);
  const finalPub  = pointAdd(clientPub, serverPub);

  const clientPubHex = serializePublicKey(clientPub);
  const serverPubHex = serializePublicKey(serverPub);
  const finalPubHex  = serializePublicKey(finalPub);

  // Derive TRON address
  const derivedAddress = pubkeyToTronAddress(finalPubHex);

  // Output
  console.log('');
  console.log('  Client public key :', clientPubHex);
  console.log('  Server public key :', serverPubHex);
  console.log('  Combined pubkey   :', finalPubHex);
  console.log('  Final private key :', finalPrivHex);
  console.log('  Derived address   :', derivedAddress);

  if (args.expectedAddress) {
    console.log('  Expected address  :', args.expectedAddress);
    console.log('');
    if (derivedAddress === args.expectedAddress) {
      console.log('  ✅  MATCH — safe to import into your wallet');
      console.log('');
      process.exit(0);
    } else {
      console.log('  ❌  MISMATCH — do not import, contact support');
      console.log('');
      process.exit(1);
    }
  } else {
    console.log('');
    console.log('  (No --expected-address provided — skipping match check)');
    console.log('');
  }
}

main();
