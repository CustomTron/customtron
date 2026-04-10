CustomTron — Split-Key TRON Vanity Address Generator
Show Image
Show Image

You generate your private key locally. We never see it. Mathematically guaranteed.

CustomTron generates personalized TRON addresses (e.g. TALEX..., T...USDT) using
a split-key protocol — the only architecture where you don't have to trust the service
provider, because trust is not mathematically required.

Why split-key matters
Most vanity address services work like this:

Their server generates a full keypair
They search for a matching address
They send you the private key
You have to hope they deleted it

CustomTron works differently:

Your browser generates a random keypair (client_privkey, client_pubkey)
You send only client_pubkey to our server — a public math fact, not a secret
Our GPU cluster finds a server_privkey such that client_pubkey + server_pubkey produces an address matching your pattern
Our server sends you server_privkey
Your browser combines client_privkey + server_privkey = final_privkey
You import final_privkey into TronLink, Ledger, or any TRON wallet

At no point does our server have client_privkey. Without it, server_privkey alone is
cryptographically useless — it corresponds to no meaningful address.

The math
TRON addresses are derived from secp256k1 elliptic curve public keys.
Key combination uses elliptic curve point addition:
final_pubkey = client_pubkey + server_pubkey
Which means:
final_privkey = client_privkey + server_privkey  (mod n)
Where n is the secp256k1 curve order:
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Because elliptic curve point addition is a one-way function, knowing
server_privkey and final_pubkey does not reveal client_privkey.
The server never has both halves, so it can never reconstruct final_privkey.

Client-side verification script
This repository contains the script your browser runs to combine keys and verify the result.
You can audit, run locally, or fork it.
Install
bashnpm install
Combine keys
bashnode combine.js \
  --client-privkey YOUR_CLIENT_PRIVKEY_HEX \
  --server-privkey SERVER_PRIVKEY_HEX \
  --expected-address TALEX...
Output:
Client public key : 04abc123...
Server public key : 04def456...
Combined public key: 04fff789...
Derived address   : TALEXimSfC7LPNhCPLwUKx1UjcRcFaqe7c
Expected address  : TALEXimSfC7LPNhCPLwUKx1UjcRcFaqe7c
✅ MATCH — safe to import
If the derived address does not match what our server returned, the script prints
❌ MISMATCH — do not import and exits with code 1.
Verify independently
You do not have to use our website at all. After receiving server_privkey:
bashnode combine.js --client-privkey <yours> --server-privkey <ours> --expected-address <address>
Run it on an air-gapped machine if you like.

SRI integrity verification
Every time the CustomTron order page loads, your browser computes the SHA-256 hash of
crypto.js (the file that runs key generation) and compares it against the hash
published in this repository.
If the hashes do not match, the page displays a red warning and blocks the order flow.
This means even if our web server is compromised and serves a backdoored crypto.js,
you cannot be silently given a broken key generator.
Current expected hash:
sha256-4e45ab77a6020799eb2f80271801058020848b9ead7214dcde67ecadc66c00db
To verify manually:
bashcurl -s https://customtron.com/crypto.js | sha256sum
The output should match the hash above. If it does not, do not proceed.

Security model summary
What the server knowsWhat the server can doclient_pubkey (your public key)Derive your address pattern — nothing elseserver_privkey (its own half)Nothing without your client_privkeyYour desired patternFind a matching server_privkeyNever: client_privkeyCannot reconstruct final_privkey
Threat model: Even if CustomTron's servers are fully compromised and all data is
exfiltrated, an attacker gains zero ability to spend funds from your vanity address.
The only attack surface remaining is the crypto.js file served to your browser —
which is protected by SRI verification above.

What this repository contains
/
├── combine.js          # Key combination + verification script
├── crypto.js           # Browser key generation (same file SRI-verified on the site)
├── checksums.txt       # SHA-256 hashes of all frontend crypto files
├── test/
│   └── combine.test.js # Test vectors with known keypairs
└── README.md

Run tests
bashnpm test
Tests use deterministic secp256k1 vectors to verify that key combination, address
derivation, and Base58Check encoding are all correct.

License
MIT — audit freely, fork freely.

Service
Vanity address generation with GPU clusters: customtron.com
Pricing starts at $19 USDT · No KYC · No registration · Payment on-chain
