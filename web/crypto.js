// Crypto primitives shared by the browser and Node tests (WebCrypto only).

const subtle = globalThis.crypto.subtle;

// ---------- byte helpers ----------

export function concat(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function b64urlEncode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export const utf8 = {
  encode: (s) => new TextEncoder().encode(s),
  decode: (b) => new TextDecoder().decode(b),
};

// ---------- hashing / KDF ----------

export async function sha256(data) {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}

export async function hmacSha256(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}

// RFC 5869 HKDF-SHA256. An empty salt is treated as 32 zero bytes (same as the RFC).
export async function hkdf(ikm, salt, info, length) {
  const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt ?? new Uint8Array(0), info },
    k,
    length * 8,
  );
  return new Uint8Array(bits);
}

// CTAP hybrid style "purpose" info: 4-byte little-endian integer.
export function purposeInfo(purpose) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, purpose, true);
  return out;
}

// ---------- P-256 ----------

export async function p256Generate() {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey)); // 65B uncompressed
  return { privateKey: kp.privateKey, publicKey: pub };
}

export async function p256ImportPrivateJwk(jwk) {
  const privateKey = await subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, [
    'deriveBits',
  ]);
  const publicKey = concat(Uint8Array.of(4), b64urlDecode(jwk.x), b64urlDecode(jwk.y));
  return { privateKey, publicKey };
}

// Returns the 32-byte x-coordinate of the shared point. Import rejects points not on the curve.
export async function ecdh(privateKey, peerPublicRaw) {
  if (peerPublicRaw.length !== 65 || peerPublicRaw[0] !== 4) throw new Error('Invalid P-256 public key');
  const peer = await subtle.importKey('raw', peerPublicRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: peer }, privateKey, 256));
}

// ---------- AES ----------

export async function aesGcmEncrypt(key, nonce, ad, plaintext) {
  const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: ad }, k, plaintext));
}

export async function aesGcmDecrypt(key, nonce, ad, ciphertext) {
  const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: ad }, k, ciphertext));
}

// WebCrypto has no ECB, so single-block ECB is emulated with AES-CBC and a zero IV.
export async function aesEcbEncryptBlock(key, block) {
  const k = await subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
  const out = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, k, block));
  return out.slice(0, 16);
}

export async function aesEcbDecryptBlock(key, block) {
  // Append a block that decrypts to valid PKCS#7 padding (16 x 0x10) so CBC decrypt succeeds:
  // D(pad) XOR block must equal 0x10.., so pad = E(block XOR 0x10..).
  const padBlock = await aesEcbEncryptBlock(key, block.map((b) => b ^ 0x10));
  const k = await subtle.importKey('raw', key, 'AES-CBC', false, ['decrypt']);
  const out = await subtle.decrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, k, concat(block, padBlock));
  return new Uint8Array(out);
}

// ---------- EID (BLE advert) ----------

export const ADVERT_LEN = 20;

export async function deriveEidKeys(qrSecret) {
  const okm = await hkdf(qrSecret, new Uint8Array(0), purposeInfo(1), 64);
  return { aesKey: okm.slice(0, 32), hmacKey: okm.slice(32) };
}

export async function derivePsk(qrSecret, advertPlaintext) {
  return hkdf(qrSecret, advertPlaintext, purposeInfo(3), 32);
}

// plaintext layout: [flags=0 | nonce 10B | reserved 5B (zero)]
export function newAdvertPlaintext() {
  return concat(Uint8Array.of(0), randomBytes(10), new Uint8Array(5));
}

export async function encryptAdvert(eidKeys, plaintext) {
  const ct = await aesEcbEncryptBlock(eidKeys.aesKey, plaintext);
  const tag = (await hmacSha256(eidKeys.hmacKey, ct)).slice(0, 4);
  return concat(ct, tag);
}

// Returns the 16-byte plaintext, or null if the advert was not made from this QR secret.
export async function decryptAdvert(eidKeys, advert) {
  if (advert.length !== ADVERT_LEN) return null;
  const ct = advert.slice(0, 16);
  const tag = (await hmacSha256(eidKeys.hmacKey, ct)).slice(0, 4);
  if (!equalBytes(tag, advert.slice(16))) return null;
  const pt = await aesEcbDecryptBlock(eidKeys.aesKey, ct);
  if (pt[0] !== 0 || pt.slice(11).some((b) => b !== 0)) return null;
  return pt;
}
