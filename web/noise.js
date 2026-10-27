// Noise_KNpsk0_P256_AESGCM_SHA256
//
//   KNpsk0:
//     -> s
//     ...
//     -> psk, e
//     <- e, ee, se
//
// Initiator = browser (static key travels in the QR code), responder = phone.

import {
  concat,
  utf8,
  sha256,
  hmacSha256,
  aesGcmEncrypt,
  aesGcmDecrypt,
  ecdh,
  p256Generate,
} from './crypto.js';

export const PROTOCOL_NAME = 'Noise_KNpsk0_P256_AESGCM_SHA256';
export const PROLOGUE = utf8.encode('BLEDEMO-v1');
const PUBLIC_KEY_LEN = 65;
const TAG_LEN = 16;

// Noise HKDF (spec section 4.3), returns `n` 32-byte outputs.
async function noiseHkdf(chainingKey, ikm, n) {
  const tempKey = await hmacSha256(chainingKey, ikm);
  const out1 = await hmacSha256(tempKey, Uint8Array.of(1));
  const out2 = await hmacSha256(tempKey, concat(out1, Uint8Array.of(2)));
  if (n === 2) return [out1, out2];
  const out3 = await hmacSha256(tempKey, concat(out2, Uint8Array.of(3)));
  return [out1, out2, out3];
}

function gcmNonce(n) {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setBigUint64(4, BigInt(n), false);
  return nonce;
}

export class CipherState {
  constructor(key = null) {
    this.k = key;
    this.n = 0;
  }

  hasKey() {
    return this.k !== null;
  }

  async encryptWithAd(ad, plaintext) {
    if (!this.k) return plaintext;
    const ct = await aesGcmEncrypt(this.k, gcmNonce(this.n), ad, plaintext);
    this.n++;
    return ct;
  }

  async decryptWithAd(ad, ciphertext) {
    if (!this.k) return ciphertext;
    const pt = await aesGcmDecrypt(this.k, gcmNonce(this.n), ad, ciphertext);
    this.n++;
    return pt;
  }
}

class SymmetricState {
  async init() {
    const name = utf8.encode(PROTOCOL_NAME);
    this.h = name.length <= 32 ? concat(name, new Uint8Array(32 - name.length)) : await sha256(name);
    this.ck = this.h;
    this.cipher = new CipherState();
  }

  async mixHash(data) {
    this.h = await sha256(concat(this.h, data));
  }

  async mixKey(ikm) {
    const [ck, k] = await noiseHkdf(this.ck, ikm, 2);
    this.ck = ck;
    this.cipher = new CipherState(k);
  }

  async mixKeyAndHash(ikm) {
    const [ck, tempH, k] = await noiseHkdf(this.ck, ikm, 3);
    this.ck = ck;
    await this.mixHash(tempH);
    this.cipher = new CipherState(k);
  }

  async encryptAndHash(plaintext) {
    const ct = await this.cipher.encryptWithAd(this.h, plaintext);
    await this.mixHash(ct);
    return ct;
  }

  async decryptAndHash(ciphertext) {
    const pt = await this.cipher.decryptWithAd(this.h, ciphertext);
    await this.mixHash(ciphertext);
    return pt;
  }

  async split() {
    const [k1, k2] = await noiseHkdf(this.ck, new Uint8Array(0), 2);
    return [new CipherState(k1), new CipherState(k2)];
  }
}

async function newSymmetricState(initiatorStaticPub) {
  const ss = new SymmetricState();
  await ss.init();
  await ss.mixHash(PROLOGUE);
  await ss.mixHash(initiatorStaticPub); // pre-message "-> s"
  return ss;
}

// Result after a completed handshake: transport ciphers + handshake hash.
function transport(ss, sendCipher, recvCipher, payload) {
  return { send: sendCipher, recv: recvCipher, handshakeHash: ss.h, payload };
}

// ---------- initiator (browser) ----------

export class Initiator {
  // staticKey: { privateKey, publicKey(65B) }; genKeyPair is injectable for test vectors.
  constructor({ staticKey, psk, genKeyPair = p256Generate }) {
    this.s = staticKey;
    this.psk = psk;
    this.genKeyPair = genKeyPair;
  }

  async writeMessage1(payload = new Uint8Array(0)) {
    this.ss = await newSymmetricState(this.s.publicKey);
    await this.ss.mixKeyAndHash(this.psk); // psk
    this.e = await this.genKeyPair(); // e
    await this.ss.mixHash(this.e.publicKey);
    await this.ss.mixKey(this.e.publicKey);
    return concat(this.e.publicKey, await this.ss.encryptAndHash(payload));
  }

  async readMessage2(msg) {
    if (msg.length < PUBLIC_KEY_LEN + TAG_LEN) throw new Error('Handshake message 2 too short');
    const re = msg.slice(0, PUBLIC_KEY_LEN);
    await this.ss.mixHash(re); // e
    await this.ss.mixKey(re);
    await this.ss.mixKey(await ecdh(this.e.privateKey, re)); // ee
    await this.ss.mixKey(await ecdh(this.s.privateKey, re)); // se
    const payload = await this.ss.decryptAndHash(msg.slice(PUBLIC_KEY_LEN));
    const [c1, c2] = await this.ss.split();
    return transport(this.ss, c1, c2, payload);
  }
}

// ---------- responder (phone; used here only for tests) ----------

export class Responder {
  constructor({ initiatorStaticPub, psk, genKeyPair = p256Generate }) {
    this.rs = initiatorStaticPub;
    this.psk = psk;
    this.genKeyPair = genKeyPair;
  }

  async readMessage1(msg) {
    if (msg.length < PUBLIC_KEY_LEN + TAG_LEN) throw new Error('Handshake message 1 too short');
    this.ss = await newSymmetricState(this.rs);
    await this.ss.mixKeyAndHash(this.psk);
    this.re = msg.slice(0, PUBLIC_KEY_LEN);
    await this.ss.mixHash(this.re);
    await this.ss.mixKey(this.re);
    return this.ss.decryptAndHash(msg.slice(PUBLIC_KEY_LEN));
  }

  async writeMessage2(payload) {
    this.e = await this.genKeyPair();
    await this.ss.mixHash(this.e.publicKey);
    await this.ss.mixKey(this.e.publicKey);
    await this.ss.mixKey(await ecdh(this.e.privateKey, this.re)); // ee
    await this.ss.mixKey(await ecdh(this.e.privateKey, this.rs)); // se
    const msg = concat(this.e.publicKey, await this.ss.encryptAndHash(payload));
    const [c1, c2] = await this.ss.split();
    return { msg, ...transport(this.ss, c2, c1, payload) };
  }
}
