# CustomTron — Split-Key TRON Vanity Address Generator

**You generate your private key locally. We never see it.** For the GPU search step this is mathematically guaranteed — our server only ever holds your public key. For the final combine step you run open-source code (and can run it offline), so you never have to take our word for it.

CustomTron generates personalized TRON addresses (e.g. `TALEX…`, `…8888`) using a **split-key protocol**: your wallet key is only ever assembled on your side, never on ours.

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
4. Our server sends you `server_privkey`, encrypted to your public key (ECIES), so only your browser can read it.
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

Because elliptic-curve point addition is a one-way function, knowing `server_privkey` and `final_pubkey` does not reveal `client_privkey`. The server never has both halves, so it can never reconstruct `final_privkey`. This is the part that is guaranteed by mathematics, not by our promise: the search runs on a key share that is useless without yours.

---

## Free / short patterns (1–3 characters)

For short patterns (1–3 characters) **no GPU server is involved**. Your browser brute-forces a matching address locally in a Web Worker (`vanity-worker.js`); your **private key and address are generated and stay in your browser — they are never sent to us**. The page sends only an anonymous metric (pattern position, case-sensitivity, and time taken) — no key, no address, no pattern. The split-key + GPU flow above is used only for longer (paid) patterns, where brute-forcing in a browser isn't practical.

---

## Combine and verify with `combine.js`

`combine.js` reconstructs your wallet key from your Generation Private Key and the server's encrypted key share, derives the address, and checks it against your vanity address. It has **no dependencies** (only Node's built-in `crypto`) and makes **no network calls** — you can read it, run it, or run it on an air-gapped machine.

The two inputs you need are shown on your claim page: your saved **Generation Private Key**, and the **encrypted server key share**.

```
node combine.js \
  --client-privkey <your-Generation-Private-Key> \
  --encrypted-server-priv <encrypted blob from the claim page> \
  --expected-address <your vanity address>
```

Output:

```
  Final private key : 1a2b3c...
  Derived address   : TALEXimSfC7LPNhCPLwUKx1UjcRcFaqe7c
  Expected address  : TALEXimSfC7LPNhCPLwUKx1UjcRcFaqe7c

  ✅  MATCH — this private key controls your vanity address. Safe to import.
```

A `MATCH` and exit code `0` mean the recovered key controls your address. If it doesn't match, the script prints `❌ MISMATCH — do NOT import` and exits with code `1`.

**For maximum assurance, run this on a machine disconnected from the internet** — then the final key never touches our website at all. Never type your private key on an online machine you don't trust.

(If you ever have a plaintext server key instead of the encrypted blob, the script also accepts `--server-privkey <hex>` in place of `--encrypted-server-priv`.)

---

## Code-integrity verification

Every time the CustomTron order page loads, your browser computes the SHA-256 hash of `crypto.js` and compares it against the hash published in `CHECKSUMS.txt` in this repository (fetched live from GitHub). If they don't match, the page shows a **prominent red security warning telling you not to proceed** — so even if our web server were compromised and served a backdoored `crypto.js`, you'd be warned before entering anything.

This is a hash check against the open-source version published here — not browser SRI. If you hold significant funds, verify it yourself rather than relying on the in-page check alone:

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

**Threat model:** even if CustomTron's servers are fully compromised and all data is exfiltrated, an attacker gains **zero** ability to spend funds from your vanity address. The only remaining trust surface is the `crypto.js` served to your browser during the combine step — which is exactly what the code-integrity check above is for, and which you can bypass entirely by combining offline with `combine.js`.

---

## What this repository contains

```
/
├── combine.js          # Key combination + verification (no dependencies; run it yourself, offline if you like)
├── crypto.js           # Browser key generation + combine (the file hash-verified on the site)
├── vanity-worker.js    # In-browser generator for free, short (1–3 char) patterns
├── noble-bundle.js     # secp256k1 elliptic-curve library (vendored, unmodified)
├── CHECKSUMS.txt       # SHA-256 hashes of the frontend crypto files
└── README.md
```

---

## License

MIT — audit freely, fork freely.

---

## Service

Vanity address generation with GPU clusters: **customtron.com**
Short patterns (1–3 chars) are free; longer patterns from $19 USDT · No KYC · No registration · Payment on-chain.
