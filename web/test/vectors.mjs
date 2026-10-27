// Deterministic test vectors shared with the Android unit tests (android NoiseVectorsTest).
// Regenerate with: node test/vectors.mjs > test/vectors.json

import { createECDH } from 'node:crypto';
import {
  b64urlEncode,
  fromHex,
  toHex,
  utf8,
  p256ImportPrivateJwk,
  deriveEidKeys,
  derivePsk,
  encryptAdvert,
} from '../crypto.js';
import { Initiator, Responder } from '../noise.js';

export async function keyFromScalar(hex) {
  const ecdhKey = createECDH('prime256v1');
  ecdhKey.setPrivateKey(Buffer.from(hex, 'hex'));
  const pub = ecdhKey.getPublicKey();
  return p256ImportPrivateJwk({
    kty: 'EC',
    crv: 'P-256',
    d: b64urlEncode(fromHex(hex)),
    x: b64urlEncode(pub.subarray(1, 33)),
    y: b64urlEncode(pub.subarray(33, 65)),
  });
}

export async function buildVectors() {
  const v = {
    qrSecret: '000102030405060708090a0b0c0d0e0f',
    initiatorStaticPriv: '1111111111111111111111111111111111111111111111111111111111111111',
    initiatorEphemeralPriv: '2222222222222222222222222222222222222222222222222222222222222222',
    responderEphemeralPriv: '3333333333333333333333333333333333333333333333333333333333333333',
    advertPlaintext: '00a1a2a3a4a5a6a7a8a9aa0000000000',
    payload2: toHex(utf8.encode('{"device":"Pixel","model":"test"}')),
    transport1: toHex(utf8.encode('{"type":"challenge","challenge":"abc"}')),
    transport2: toHex(utf8.encode('{"type":"result","approved":true,"echo":"abc"}')),
  };

  const qrSecret = fromHex(v.qrSecret);
  const plaintext = fromHex(v.advertPlaintext);
  const s = await keyFromScalar(v.initiatorStaticPriv);
  const ei = await keyFromScalar(v.initiatorEphemeralPriv);
  const er = await keyFromScalar(v.responderEphemeralPriv);

  v.initiatorStaticPub = toHex(s.publicKey);
  v.initiatorEphemeralPub = toHex(ei.publicKey);
  v.responderEphemeralPub = toHex(er.publicKey);
  v.advert = toHex(await encryptAdvert(await deriveEidKeys(qrSecret), plaintext));
  const psk = await derivePsk(qrSecret, plaintext);
  v.psk = toHex(psk);

  const initiator = new Initiator({ staticKey: s, psk, genKeyPair: async () => ei });
  const responder = new Responder({ initiatorStaticPub: s.publicKey, psk, genKeyPair: async () => er });

  const msg1 = await initiator.writeMessage1();
  await responder.readMessage1(msg1);
  const r = await responder.writeMessage2(fromHex(v.payload2));
  const i = await initiator.readMessage2(r.msg);

  v.msg1 = toHex(msg1);
  v.msg2 = toHex(r.msg);
  v.handshakeHash = toHex(r.handshakeHash);
  v.transport1Ciphertext = toHex(await i.send.encryptWithAd(new Uint8Array(0), fromHex(v.transport1)));
  v.transport2Ciphertext = toHex(await r.send.encryptWithAd(new Uint8Array(0), fromHex(v.transport2)));
  return v;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(JSON.stringify(await buildVectors(), null, 2));
}
