import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  p256Generate,
  randomBytes,
  utf8,
  deriveEidKeys,
  derivePsk,
  newAdvertPlaintext,
  encryptAdvert,
  decryptAdvert,
  aesEcbEncryptBlock,
  aesEcbDecryptBlock,
  equalBytes,
} from '../crypto.js';
import { Initiator, Responder } from '../noise.js';
import { buildVectors } from './vectors.mjs';

async function setup() {
  const qrSecret = randomBytes(16);
  const staticKey = await p256Generate();
  const plaintext = newAdvertPlaintext();
  const advert = await encryptAdvert(await deriveEidKeys(qrSecret), plaintext);
  return { qrSecret, staticKey, plaintext, advert };
}

test('single-block ECB round-trips', async () => {
  const key = randomBytes(32);
  const block = randomBytes(16);
  assert.ok(equalBytes(await aesEcbDecryptBlock(key, await aesEcbEncryptBlock(key, block)), block));
});

test('advert decrypts only with the matching QR secret', async () => {
  const { qrSecret, plaintext, advert } = await setup();
  assert.ok(equalBytes(await decryptAdvert(await deriveEidKeys(qrSecret), advert), plaintext));
  assert.equal(await decryptAdvert(await deriveEidKeys(randomBytes(16)), advert), null);
  const tampered = advert.slice();
  tampered[3] ^= 1;
  assert.equal(await decryptAdvert(await deriveEidKeys(qrSecret), tampered), null);
});

test('handshake + transport round-trip', async () => {
  const { qrSecret, staticKey, plaintext } = await setup();
  const psk = await derivePsk(qrSecret, plaintext);
  const initiator = new Initiator({ staticKey, psk });
  const responder = new Responder({ initiatorStaticPub: staticKey.publicKey, psk });

  await responder.readMessage1(await initiator.writeMessage1());
  const r = await responder.writeMessage2(utf8.encode('hello'));
  const i = await initiator.readMessage2(r.msg);

  assert.equal(utf8.decode(i.payload), 'hello');
  assert.ok(equalBytes(i.handshakeHash, r.handshakeHash));
  const ad = new Uint8Array(0);
  assert.equal(utf8.decode(await r.recv.decryptWithAd(ad, await i.send.encryptWithAd(ad, utf8.encode('ping')))), 'ping');
  assert.equal(utf8.decode(await i.recv.decryptWithAd(ad, await r.send.encryptWithAd(ad, utf8.encode('pong')))), 'pong');
});

test('responder rejects message 1 when psk differs (advert not received)', async () => {
  const { qrSecret, staticKey, plaintext } = await setup();
  const initiator = new Initiator({ staticKey, psk: await derivePsk(qrSecret, newAdvertPlaintext()) });
  const responder = new Responder({
    initiatorStaticPub: staticKey.publicKey,
    psk: await derivePsk(qrSecret, plaintext),
  });
  await assert.rejects(responder.readMessage1(await initiator.writeMessage1()));
});

test('responder rejects message 1 when the QR static key differs', async () => {
  const { qrSecret, staticKey, plaintext } = await setup();
  const psk = await derivePsk(qrSecret, plaintext);
  const initiator = new Initiator({ staticKey, psk });
  const other = await p256Generate();
  const responder = new Responder({ initiatorStaticPub: other.publicKey, psk });
  await assert.rejects(responder.readMessage1(await initiator.writeMessage1()));
});

test('vectors.json is up to date', async () => {
  const stored = JSON.parse(await readFile(new URL('./vectors.json', import.meta.url), 'utf8'));
  assert.deepEqual(stored, await buildVectors());
});
