import {
  b64urlEncode,
  equalBytes,
  p256Generate,
  randomBytes,
  toHex,
  utf8,
  deriveEidKeys,
  derivePsk,
  decryptAdvert,
} from './crypto.js';
import { Initiator } from './noise.js';
import { BleLink, MsgType, isWebBluetoothAvailable } from './ble.js';

const QR_TTL_SECONDS = 120;
const HANDSHAKE_TIMEOUT_MS = 15_000;
const APPROVAL_TIMEOUT_MS = 60_000;

const $ = (id) => document.getElementById(id);
const ui = {
  qr: $('qr'),
  expiry: $('expiry'),
  newQr: $('newQr'),
  connect: $('connect'),
  code: $('code'),
  codeValue: $('codeValue'),
  result: $('result'),
  log: $('log'),
};

let session = null; // { staticKey, qrSecret, expiresAt, used }
let countdown = null;
let busy = false;

function log(msg) {
  const ts = new Date().toLocaleTimeString();
  ui.log.textContent += `[${ts}] ${msg}\n`;
  ui.log.scrollTop = ui.log.scrollHeight;
}

function setStep(step, state) {
  const el = document.querySelector(`[data-step="${step}"]`);
  el.classList.remove('done', 'failed');
  if (state) el.classList.add(state);
}

function resetSteps() {
  for (const el of document.querySelectorAll('[data-step]')) el.classList.remove('done', 'failed');
}

function showResult(ok, text) {
  ui.result.hidden = false;
  ui.result.className = `result ${ok ? 'ok' : 'err'}`;
  ui.result.textContent = text;
}

function updateConnectButton() {
  ui.connect.disabled = busy || !session || session.used || Date.now() > session.expiresAt;
}

async function newSession() {
  const staticKey = await p256Generate();
  const qrSecret = randomBytes(16);
  const expiresAt = Date.now() + QR_TTL_SECONDS * 1000;
  session = { staticKey, qrSecret, expiresAt, used: false };

  const payload = {
    v: 1,
    pk: b64urlEncode(staticKey.publicKey),
    s: b64urlEncode(qrSecret),
    t: Math.floor(Date.now() / 1000),
  };
  const text = `BLEDEMO:${b64urlEncode(utf8.encode(JSON.stringify(payload)))}`;
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  ui.qr.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true });
  ui.qr.classList.remove('expired');

  resetSteps();
  setStep('qr', 'done');
  ui.code.hidden = true;
  ui.result.hidden = true;
  log(`New QR (${text.length} chars), static key ${toHex(staticKey.publicKey.slice(1, 5))}…`);

  clearInterval(countdown);
  countdown = setInterval(tick, 1000);
  tick();
}

function tick() {
  const left = Math.max(0, Math.round((session.expiresAt - Date.now()) / 1000));
  ui.expiry.textContent = session.used ? 'QR used' : left > 0 ? `Expires in ${left}s` : 'QR expired';
  if (left === 0 || session.used) {
    ui.qr.classList.add('expired');
    clearInterval(countdown);
  }
  updateConnectButton();
}

async function connectFlow() {
  busy = true;
  updateConnectButton();
  ui.result.hidden = true;
  let link = null;
  const current = session;
  try {
    // 1. Chooser (requires the click gesture). Only nearby devices advertising our service show up.
    link = await BleLink.request(log);
    setStep('device', 'done');
    log(`Selected device: ${link.device.name ?? link.device.id}`);

    // 2. Prove the phone scanned *this* QR: the EID decrypts only with keys derived from qrSecret.
    const advertEid = await link.readAdvertEid();
    log(advertEid ? `EID from advertisement: ${toHex(advertEid)}` : 'EID not available from advertisement, reading over GATT');
    await link.connect();
    log('GATT connected, notifications enabled');
    const gattEid = await link.readGattEid();
    if (advertEid && !equalBytes(advertEid, gattEid)) throw new Error('Advertised EID does not match GATT EID');

    const eidKeys = await deriveEidKeys(current.qrSecret);
    const plaintext = await decryptAdvert(eidKeys, advertEid ?? gattEid);
    if (!plaintext) throw new Error('EID check failed: this phone did not scan the current QR code');
    setStep('eid', 'done');
    log(`EID verified, connection nonce ${toHex(plaintext.slice(1, 11))}`);

    // QR is single-use from here on: a second phone cannot reuse it.
    current.used = true;
    tick();

    // 3. Noise KNpsk0: psk depends on the advert plaintext, so only a client that received the advert can start.
    const psk = await derivePsk(current.qrSecret, plaintext);
    const initiator = new Initiator({ staticKey: current.staticKey, psk });
    await link.send(MsgType.HANDSHAKE_1, await initiator.writeMessage1());
    log('-> handshake message 1 (psk, e)');

    const reply = await expect(link, MsgType.HANDSHAKE_2, HANDSHAKE_TIMEOUT_MS);
    const channel = await initiator.readMessage2(reply);
    log('<- handshake message 2 (e, ee, se)');
    const phoneInfo = JSON.parse(utf8.decode(channel.payload));
    const code = toHex(channel.handshakeHash.slice(0, 3)).toUpperCase();
    ui.codeValue.textContent = code;
    ui.code.hidden = false;
    setStep('handshake', 'done');
    log(`Secure channel up with ${phoneInfo.device} (${phoneInfo.model}), handshake hash ${toHex(channel.handshakeHash)}`);

    // 4. Encrypted application exchange.
    const challenge = b64urlEncode(randomBytes(16));
    const request = { type: 'challenge', challenge, origin: location.origin, browser: browserLabel() };
    await link.send(MsgType.DATA, await channel.send.encryptWithAd(new Uint8Array(0), utf8.encode(JSON.stringify(request))));
    log(`-> encrypted challenge ${challenge}, waiting for approval on the phone`);

    const encrypted = await expect(link, MsgType.DATA, APPROVAL_TIMEOUT_MS);
    const result = JSON.parse(utf8.decode(await channel.recv.decryptWithAd(new Uint8Array(0), encrypted)));
    log(`<- encrypted result ${JSON.stringify(result)}`);
    if (result.type !== 'result' || result.echo !== challenge) throw new Error('Phone response does not match the challenge');

    if (result.approved) {
      setStep('approve', 'done');
      showResult(true, 'Approved by nearby phone');
    } else {
      setStep('approve', 'failed');
      showResult(false, 'Rejected on the phone');
    }
  } catch (err) {
    if (err.name === 'NotFoundError') {
      log('Chooser closed without selecting a device');
    } else {
      log(`Error: ${err.message}`);
      showResult(false, err.message);
      const pending = document.querySelector('[data-step]:not(.done)');
      if (pending) setStep(pending.dataset.step, 'failed');
    }
  } finally {
    link?.disconnect();
    busy = false;
    updateConnectButton();
  }
}

async function expect(link, type, timeoutMs) {
  const msg = await link.receive(timeoutMs);
  if (msg.type === MsgType.ERROR) throw new Error(`Phone reported: ${utf8.decode(msg.payload)}`);
  if (msg.type !== type) throw new Error(`Unexpected message type 0x${msg.type.toString(16)}`);
  return msg.payload;
}

function browserLabel() {
  const brands = navigator.userAgentData?.brands?.filter((b) => !/Not.?A.?Brand/i.test(b.brand)) ?? [];
  const platform = navigator.userAgentData?.platform ?? navigator.platform;
  return `${brands.map((b) => b.brand).pop() ?? 'Browser'} on ${platform}`;
}

ui.newQr.addEventListener('click', () => !busy && newSession());
ui.connect.addEventListener('click', connectFlow);

if (!isWebBluetoothAvailable()) {
  $('unsupported').hidden = false;
}
newSession().catch((err) => log(`Failed to create QR: ${err.message}`));
