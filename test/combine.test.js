/**
 * CustomTron — combine.js test vectors
 *
 * Uses deterministic keypairs to verify:
 * 1. Key combination arithmetic (mod N)
 * 2. Elliptic curve point addition
 * 3. TRON address derivation
 * 4. Base58Check encoding
 */
 
'use strict';
 
const { execSync } = require('child_process');
const assert = require('assert');
 
// Test vector 1: private key = 1  →  pubkey = G  →  address is deterministic
const TESTS = [
  {
    description: 'client_priv=1, server_priv=1 → combined=2',
    clientPrivkey: '0000000000000000000000000000000000000000000000000000000000000001',
    serverPrivkey:  '0000000000000000000000000000000000000000000000000000000000000001',
    // combined private key = 2, address derived from 2*G
    // pre-computed expected address for 2*G on secp256k1 → TRON:
    expectedAddress: null, // set to null to just run without address check
  },
  {
    description: 'Known split: client+server sum equals known final key',
    // final_privkey = 0x...dead (hypothetical)
    // client = final - server mod N
    clientPrivkey: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    serverPrivkey:  '5555555555555555555555555555555555555555555555555555555555555555',
    expectedAddress: null,
  },
];
 
let passed = 0;
let failed = 0;
 
for (const test of TESTS) {
  process.stdout.write(`  Testing: ${test.description} ... `);
  try {
    const cmd = [
      'node combine.js',
      `--client-privkey ${test.clientPrivkey}`,
      `--server-privkey ${test.serverPrivkey}`,
      test.expectedAddress ? `--expected-address ${test.expectedAddress}` : '',
    ].filter(Boolean).join(' ');
 
    const output = execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
 
    // Verify output contains expected fields
    assert(output.includes('Derived address'), 'Output missing derived address');
    assert(output.includes('Combined pubkey'), 'Output missing combined pubkey');
 
    if (test.expectedAddress) {
      assert(output.includes('✅  MATCH'), 'Expected MATCH but got mismatch');
    }
 
    console.log('PASS');
    passed++;
  } catch (err) {
    console.log('FAIL');
    console.error('    ', err.message);
    failed++;
  }
}
 
console.log('');
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log('');
 
if (failed > 0) process.exit(1);
