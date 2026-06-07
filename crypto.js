/**
 * CustomTron — Browser Crypto Library (self-contained)
 * All operations run locally, zero network calls.
 * No external dependencies — secp256k1, keccak256, sha256 all inlined.
 */

const CustomTronCrypto = (() => {
  'use strict'

  // ── secp256k1 curve parameters ──────────────────────────────
  const P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn
  const N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n
  const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n
  const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n

  function mod(a, b = P) { return ((a % b) + b) % b }

  function pow(base, exp, m) {
    let r = 1n; base = mod(base, m)
    while (exp > 0n) {
      if (exp & 1n) r = mod(r * base, m)
      exp >>= 1n; base = mod(base * base, m)
    }
    return r
  }

  function inv(n, m = P) { return pow(n, m - 2n, m) }

  class Point {
    constructor(x, y) { this.x = x; this.y = y }
    static ZERO = new Point(0n, 0n)
    isZero() { return this.x === 0n && this.y === 0n }
    add(other) {
      if (this.isZero()) return other
      if (other.isZero()) return this
      if (this.x === other.x) {
        if (this.y !== other.y) return Point.ZERO
        const lam = mod(3n * this.x * this.x * inv(2n * this.y))
        const x3 = mod(lam * lam - 2n * this.x)
        return new Point(x3, mod(lam * (this.x - x3) - this.y))
      }
      const lam = mod((other.y - this.y) * inv(other.x - this.x))
      const x3 = mod(lam * lam - this.x - other.x)
      return new Point(x3, mod(lam * (this.x - x3) - this.y))
    }
    mul(k) {
      let r = Point.ZERO, p = this
      while (k > 0n) {
        if (k & 1n) r = r.add(p)
        p = p.add(p); k >>= 1n
      }
      return r
    }
  }

  const G = new Point(Gx, Gy)

  // ── SHA-256 (pure JS) ────────────────────────────────────────
  function sha256(data) {
    const K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]
    const H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
    const msg = (data instanceof Uint8Array) ? data : new TextEncoder().encode(data)
    const len = msg.length
    const extra = 64 - ((len + 9) % 64)
    const padded = new Uint8Array(len + 1 + extra + 8)
    padded.set(msg)
    padded[len] = 0x80
    const view = new DataView(padded.buffer)
    view.setUint32(padded.length - 4, len * 8, false)
    const blocks = padded.length / 64
    for (let i = 0; i < blocks; i++) {
      const W = new Array(64)
      for (let t = 0; t < 16; t++) W[t] = view.getUint32((i * 64) + t * 4, false)
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(W[t-15],7)^rotr(W[t-15],18)^(W[t-15]>>>3)
        const s1 = rotr(W[t-2],17)^rotr(W[t-2],19)^(W[t-2]>>>10)
        W[t] = (W[t-16]+s0+W[t-7]+s1)|0
      }
      let [a,b,c,d,e,f,g,h] = H
      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e,6)^rotr(e,11)^rotr(e,25)
        const ch = (e&f)^(~e&g)
        const T1 = (h+S1+ch+K[t]+W[t])|0
        const S0 = rotr(a,2)^rotr(a,13)^rotr(a,22)
        const maj = (a&b)^(a&c)^(b&c)
        const T2 = (S0+maj)|0
        h=g; g=f; f=e; e=(d+T1)|0; d=c; c=b; b=a; a=(T1+T2)|0
      }
      H[0]=(H[0]+a)|0; H[1]=(H[1]+b)|0; H[2]=(H[2]+c)|0; H[3]=(H[3]+d)|0
      H[4]=(H[4]+e)|0; H[5]=(H[5]+f)|0; H[6]=(H[6]+g)|0; H[7]=(H[7]+h)|0
    }
    const out = new Uint8Array(32)
    const ov = new DataView(out.buffer)
    H.forEach((v,i) => ov.setUint32(i*4, v, false))
    return out
  }
  function rotr(x,n) { return (x>>>n)|(x<<(32-n)) }

  // ── Keccak-256 ───────────────────────────────────────────────
  function keccak256(data) {
    const RC = [
      1n,0x8082n,0x800000000000808an,0x8000000080008000n,0x808bn,0x80000001n,
      0x8000000080008081n,0x8000000000008009n,0x8an,0x88n,0x80008009n,0x8000000an,
      0x8000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,
      0x8000000000008002n,0x8000000000000080n,0x800an,0x800000008000000an,
      0x8000000080008081n,0x8000000000008080n,0x80000001n,0x8000000080008008n
    ]
    const ROT = [
      [0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]
    ]
    const msg = (data instanceof Uint8Array) ? data : new TextEncoder().encode(data)
    // Padding
    const rate = 136 // 1088 bits for keccak256
    const padLen = rate - (msg.length % rate)
    const padded = new Uint8Array(msg.length + padLen)
    padded.set(msg)
    padded[msg.length] = 0x01
    padded[padded.length - 1] |= 0x80
    // State
    const state = Array.from({length:5},()=>Array(5).fill(0n))
    const dv = new DataView(padded.buffer)
    for (let block = 0; block < padded.length; block += rate) {
      for (let i = 0; i < rate/8; i++) {
        const lo = BigInt(dv.getUint32(block+i*8, true))
        const hi = BigInt(dv.getUint32(block+i*8+4, true))
        state[i%5][Math.floor(i/5)] ^= lo | (hi << 32n)
      }
      // Keccak-f[1600]
      for (let round = 0; round < 24; round++) {
        // θ
        const C = state.map(row => row.reduce((a,b)=>a^b,0n))
        const D = C.map((_,x)=>C[(x+4)%5]^rotl64(C[(x+1)%5],1n))
        for(let x=0;x<5;x++)for(let y=0;y<5;y++) state[x][y]^=D[x]
        // ρ and π
        const B = Array.from({length:5},()=>Array(5).fill(0n))
        for(let x=0;x<5;x++)for(let y=0;y<5;y++) B[y][(2*x+3*y)%5]=rotl64(state[x][y],BigInt(ROT[x][y]))
        // χ
        for(let x=0;x<5;x++)for(let y=0;y<5;y++) state[x][y]=B[x][y]^(~B[(x+1)%5][y]&B[(x+2)%5][y])
        // ι
        state[0][0]^=RC[round]
      }
    }
    const out = new Uint8Array(32)
    const ov = new DataView(out.buffer)
    for(let i=0;i<4;i++){
      const v=state[i%5][Math.floor(i/5)]
      ov.setUint32(i*8,Number(v&0xFFFFFFFFn),true)
      ov.setUint32(i*8+4,Number((v>>32n)&0xFFFFFFFFn),true)
    }
    return out
  }
  function rotl64(x,n){return((x<<n)|(x>>(64n-n)))&0xFFFFFFFFFFFFFFFFn}

  // ── Helpers ──────────────────────────────────────────────────
  function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error('Invalid hex')
    const out = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2)
      out[i/2] = parseInt(hex.slice(i, i+2), 16)
    return out
  }
  function bytesToHex(bytes) {
    return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('')
  }

  // ── Key generation ───────────────────────────────────────────
  async function generateKeyPair() {
    const privBytes = window.crypto.getRandomValues(new Uint8Array(32))
    // Ensure private key is in valid range [1, N-1]
    let privBig = BigInt('0x' + bytesToHex(privBytes))
    privBig = mod(privBig, N - 1n) + 1n
    const privHex = privBig.toString(16).padStart(64, '0')
    const privB = hexToBytes(privHex)
    const pub = G.mul(privBig)
    const pubHex = pub.x.toString(16).padStart(64,'0') + pub.y.toString(16).padStart(64,'0')
    return { privKey: privHex, pubKey: pubHex }
  }

  // ── ECDH + ECIES decrypt ─────────────────────────────────────
  async function decryptServerPriv(clientPrivHex, encryptedBase64) {
    const ciphertext = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0))
    // eciesjs format: ephPub(65) || nonce(16) || tag(16) || cipherText
    const ephPubUncompressed = ciphertext.slice(0, 65)
    const iv      = ciphertext.slice(65, 81)
    const tag     = ciphertext.slice(81, 97)
    const encBody = ciphertext.slice(97)
    // AES-GCM expects cipherText || tag
    const encData = new Uint8Array([...encBody, ...tag])

    // Parse uncompressed pubkey
    const ephX = BigInt('0x' + bytesToHex(ephPubUncompressed.slice(1, 33)))
    const ephY = BigInt('0x' + bytesToHex(ephPubUncompressed.slice(33, 65)))
    const ephPub = new Point(ephX, ephY)

    // ECDH
    const clientPriv = BigInt('0x' + clientPrivHex)
    const shared = ephPub.mul(clientPriv)
    // eciesjs HKDF input = concat(ephPubUncompressed, sharedPointUncompressed)
    const sharedXBytes = hexToBytes(shared.x.toString(16).padStart(64,'0'))
    const sharedYBytes = hexToBytes(shared.y.toString(16).padStart(64,'0'))
    const sharedPoint = new Uint8Array([0x04, ...sharedXBytes, ...sharedYBytes])
    const sharedX = new Uint8Array([...ephPubUncompressed, ...sharedPoint])

    // HKDF-SHA256 → AES-256-GCM decrypt
    const hkdfKey = await window.crypto.subtle.importKey('raw', sharedX, {name:'HKDF'}, false, ['deriveKey'])
    const aesKey  = await window.crypto.subtle.deriveKey(
      {name:'HKDF', hash:'SHA-256', salt:new Uint8Array(0), info:new Uint8Array(0)},
      hkdfKey, {name:'AES-GCM', length:256}, false, ['decrypt']
    )
    const plain = await window.crypto.subtle.decrypt({name:'AES-GCM', iv}, aesKey, encData)
    return new TextDecoder().decode(plain)
  }

  // ── Combine keys ─────────────────────────────────────────────
  function combinePrivateKeys(clientPrivHex, serverPrivHex) {
    const a = BigInt('0x' + clientPrivHex)
    const b = BigInt('0x' + serverPrivHex)
    const result = mod(a + b, N)
    if (result === 0n) throw new Error('Invalid key combination')
    return result.toString(16).padStart(64, '0')
  }

  // ── Derive TRON address ───────────────────────────────────────
  function deriveTronAddress(privKeyHex) {
    const priv = BigInt('0x' + privKeyHex)
    const pub  = G.mul(priv)
    const pubBytes = new Uint8Array(64)
    const xb = hexToBytes(pub.x.toString(16).padStart(64,'0'))
    const yb = hexToBytes(pub.y.toString(16).padStart(64,'0'))
    pubBytes.set(xb, 0); pubBytes.set(yb, 32)
    const hash   = keccak256(pubBytes)
    const addr20 = hash.slice(12)
    const payload = new Uint8Array(21)
    payload[0] = 0x41
    payload.set(addr20, 1)
    const chk = sha256(sha256(payload)).slice(0, 4)
    const full = new Uint8Array(25)
    full.set(payload, 0); full.set(chk, 21)
    return base58Encode(full)
  }

  // ── Base58 ────────────────────────────────────────────────────
  const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  function base58Encode(bytes) {
    let zeros = 0
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++
    const digits = [0]
    for (let i = zeros; i < bytes.length; i++) {
      let carry = bytes[i]
      for (let j = 0; j < digits.length; j++) {
        carry += digits[j] << 8
        digits[j] = carry % 58
        carry = Math.floor(carry / 58)
      }
      while (carry > 0) { digits.push(carry % 58); carry = Math.floor(carry / 58) }
    }
    let r = '1'.repeat(zeros)
    for (let i = digits.length - 1; i >= 0; i--) r += BASE58[digits[i]]
    return r
  }

  // ── Pattern verify ────────────────────────────────────────────
  function verifyPattern(address, prefix, suffix, caseSensitive) {
    const addr = caseSensitive ? address : address.toLowerCase()
    const pfx  = caseSensitive ? prefix  : (prefix||'').toLowerCase()
    const sfx  = caseSensitive ? suffix  : (suffix||'').toLowerCase()
    if (pfx && !addr.slice(1).startsWith(pfx)) return false
    if (sfx && !addr.endsWith(sfx)) return false
    return true
  }

  // ── Session storage ───────────────────────────────────────────
  const SESSION_KEY = 'ct_client_priv'
  function savePrivKeyToSession(h) { try { sessionStorage.setItem(SESSION_KEY, h) } catch {} }
  function loadPrivKeyFromSession() { try { return sessionStorage.getItem(SESSION_KEY) } catch { return null } }
  function clearPrivKeyFromSession() { try { sessionStorage.removeItem(SESSION_KEY) } catch {} }

  // ── Main flow ─────────────────────────────────────────────────
  async function step2GenerateKeys() {
    const { privKey, pubKey } = await generateKeyPair()
    // savePrivKeyToSession(privKey) — disabled: zero-storage policy
    return { privKey, pubKey }
  }

  async function step5CombineKeys(clientPrivHex, encryptedBase64, patternPrefix, patternSuffix, caseSensitive) {
    const serverPrivHex  = await decryptServerPriv(clientPrivHex, encryptedBase64)
    const finalPriv      = combinePrivateKeys(clientPrivHex, serverPrivHex)
    const finalAddress   = deriveTronAddress(finalPriv)
    const valid = verifyPattern(finalAddress, patternPrefix||'', patternSuffix||'', caseSensitive||false)
    if (!valid) throw new Error(`Address ${finalAddress} does not match pattern. Please contact support.`)
    clearPrivKeyFromSession()
    return { finalPriv, finalAddress }
  }

  async function selfTest() {
    try {
      const { privKey, pubKey } = await generateKeyPair()
      if (privKey.length !== 64) throw new Error('privKey length')
      if (pubKey.length !== 128) throw new Error('pubKey length')
      const addr = deriveTronAddress(privKey)
      if (!addr.startsWith('T')) throw new Error('Address must start with T')
      if (addr.length !== 34) throw new Error('Address length must be 34')
      const combined = combinePrivateKeys(privKey, '0000000000000000000000000000000000000000000000000000000000000001')
      if (combined.length !== 64) throw new Error('Combined key length')
      console.log('[customtron-crypto] Self-test passed ✓')
      return true
    } catch (err) {
      console.error('[customtron-crypto] Self-test FAILED:', err)
      return false
    }
  }

  return {
    generateKeyPair, decryptServerPriv, combinePrivateKeys, deriveTronAddress,
    verifyPattern, step2GenerateKeys, step5CombineKeys,
    savePrivKeyToSession, loadPrivKeyFromSession, clearPrivKeyFromSession,
    selfTest, hexToBytes, bytesToHex, base58Encode,
  }
})()
