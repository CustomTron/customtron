# CustomTron — Split-Key TRON Vanity Address Generator

**You generate your private key locally. We never see it. This isn't a promise — it's mathematically guaranteed.**

CustomTron generates personalized TRON addresses (e.g. `TALEX…`, `…8888`) using a **split-key protocol** — the only architecture where you don't have to trust the service provider, because trust is not mathematically required.

---

## Why split-key matters

Most vanity-address services work like this:

1. Their server generates a full keypair.
2. It searches for an address matching your pattern.
3. It sends you the private key.
4. You just have to *hope* they deleted their copy.

**CustomTron works differently:**

1. Your browser generates a random keypair (`client_privkey`, `client_pubkey`).
2. You send only `client_pubkey` to our server — a public math fact, not a secret.
3. Our GPU cluster finds a `server_privkey` such that `client_pubkey + server_pubkey` produces an address matching your pattern.
4. Our server sends you `server_privkey`.
5. Your browser combines `client_privkey + server_privkey = final_privkey`.
6. You import `final_privkey` into TronLink or any wallet that supports importing a private key.

At no point does our server have `client_privkey`. Without it, `server_privkey` alone is cryptographically useless — it corresponds to no meaningful address.

---

## The math

TRON addresses are derived from secp256k1 elliptic-curve public keys. Key combination uses elliptic-curve point addition:

```
final_pubkey  = client_pubkey  + server_pubkey
final_privkey = client_privkey + server_privkey   (mod n)
```

where `n` is the secp256k1 curve order:

```
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

Because elliptic-curve point addition is a one-way function, knowing `server_privkey` and `final_pubkey` does not reveal `client_privkey`. The server never has both halves, so it can never reconstruct `final_privkey`.

---

## Free / short patterns (1–3 characters)

For short patterns (1–3 characters) **no GPU server is involved**. Your browser brute-forces a matching address locally in a Web Worker (`vanity-worker.js`); your **private key and address are generated and stay in your browser — they are never sent to us**. The page sends only an anonymous metric (pattern position, case-sensitivity, and time taken) — no key, no address, no pattern. The split-key + GPU flow above is used only for longer (paid) patterns, where brute-forcing in a browser isn't practical.

---

## Client-side verification script

`combine.js` is the script your browser runs to combine the key halves and verify the result. You can read it, run it locally, or fork it.

Install:

```
npm install
```

Combine and verify:

```
node combine.js \
  --client-privkey YOUR_CLIENT_PRIVKEY_HEX \
  --server-privkey SERVER_PRIVKEY_HEX \
  --expected-address TALEX...
```

Output:

```
Client public key:   04abc123...
Server public key:   04def456...
Combined public key: 04fff789...
Derived address:     TALEXimSfC7LPNhCPLwUKx1UjcRcFaqe7c
Expected address:    TALEXimSfC7LPNhCPLwUKx1UjcRcFaqe7c
MATCH — safe to import
```

If the derived address doesn't match what our server returned, the script prints `MISMATCH — do not import` and exits with code 1. You don't have to use our website at all — run it on an air-gapped machine if you like.

---

## SRI integrity verification

Every time the CustomTron order page loads, your browser computes the SHA-256 hash of `crypto.js` and compares it against the hash published in `CHECKSUMS.txt` in this repository (fetched live from GitHub). If they don't match, the page shows a **prominent red security warning telling you not to proceed** — so even if our web server were compromised and served a backdoored `crypto.js`, you'd be warned before entering anything.

Verify manually:

```
curl -s https://customtron.com/crypto.js | sha256sum
```

The output must match the hash on the `crypto.js` line in `CHECKSUMS.txt`. If it doesn't, do not proceed.

---

## Security model

| What the server learns | What it can do with that |
|---|---|
| your `client_pubkey` | derive your address pattern — nothing else |
| your desired pattern | search for a matching `server_privkey` |
| it **never** receives `client_privkey` | so it can **never** reconstruct `final_privkey` or spend your funds |

**Threat model:** even if CustomTron's servers are fully compromised and all data is exfiltrated, an attacker gains **zero** ability to spend funds from your vanity address. The only remaining attack surface is the `crypto.js` served to your browser — which is exactly what the SRI check above protects.

---

## What this repository contains

```
/
├── combine.js          # Key combination + verification script (run it yourself)
├── crypto.js           # Browser key generation (the file SRI-verified on the site)
├── vanity-worker.js    # In-browser generator for free, short (1–3 char) patterns
├── noble-bundle.js     # secp256k1 elliptic-curve library (vendored, unmodified)
├── CHECKSUMS.txt       # SHA-256 hashes of the frontend crypto files (for SRI)
├── test/
│   └── combine.test.js # Test vectors with known keypairs
├── package.json
└── README.md
```

---

## Run tests

```
npm test
```

Tests use deterministic secp256k1 vectors to verify that key combination, address derivation, and Base58Check encoding are all correct.

---

## License

MIT — audit freely, fork freely.

---

## Service

Vanity address generation with GPU clusters: **customtron.com**
Short patterns (1–3 chars) are free; longer patterns from $19 USDT · No KYC · No registration · Payment on-chain.
