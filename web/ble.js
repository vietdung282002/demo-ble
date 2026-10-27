// Web Bluetooth transport: the phone is the GATT server, the browser is the central.

export const SERVICE_UUID = '0000fff3-0000-1000-8000-00805f9b34fb';
export const EID_CHAR_UUID = 'b1e0a001-6f2c-4d6e-9d1a-5c3e0f7a2b01';
export const RX_CHAR_UUID = 'b1e0a001-6f2c-4d6e-9d1a-5c3e0f7a2b02'; // browser -> phone (write)
export const TX_CHAR_UUID = 'b1e0a001-6f2c-4d6e-9d1a-5c3e0f7a2b03'; // phone -> browser (notify)

export const MsgType = Object.freeze({
  HANDSHAKE_1: 0x01,
  HANDSHAKE_2: 0x02,
  DATA: 0x03,
  ERROR: 0x7f,
});

const CHUNK_PAYLOAD = 180;
const LAST_CHUNK = 0x80;

export function isWebBluetoothAvailable() {
  return typeof navigator !== 'undefined' && !!navigator.bluetooth;
}

export class BleLink {
  constructor(device, log) {
    this.device = device;
    this.log = log;
    this.rxBuffer = [];
    this.inbox = [];
    this.waiters = [];
    this.onDisconnect = this.onDisconnect.bind(this);
    this.device.addEventListener('gattserverdisconnected', this.onDisconnect);
  }

  // Must be called from a user gesture. The chooser only lists devices advertising SERVICE_UUID.
  static async request(log) {
    const device = await navigator.bluetooth.requestDevice({ filters: [{ services: [SERVICE_UUID] }] });
    return new BleLink(device, log);
  }

  // Reads the 20-byte service data straight from the advertisement, if the browser supports it.
  async readAdvertEid(timeoutMs = 4000) {
    if (typeof this.device.watchAdvertisements !== 'function') return null;
    const controller = new AbortController();
    try {
      const got = new Promise((resolve) => {
        this.device.addEventListener(
          'advertisementreceived',
          (event) => {
            const data = event.serviceData.get(SERVICE_UUID);
            resolve(data ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength).slice() : null);
          },
          { once: true },
        );
      });
      await this.device.watchAdvertisements({ signal: controller.signal });
      return await Promise.race([got, new Promise((r) => setTimeout(() => r(null), timeoutMs))]);
    } catch (err) {
      this.log(`watchAdvertisements unavailable: ${err.message}`);
      return null;
    } finally {
      controller.abort();
    }
  }

  async connect() {
    this.server = await this.device.gatt.connect();
    const service = await this.server.getPrimaryService(SERVICE_UUID);
    this.eidChar = await service.getCharacteristic(EID_CHAR_UUID);
    this.rxChar = await service.getCharacteristic(RX_CHAR_UUID);
    this.txChar = await service.getCharacteristic(TX_CHAR_UUID);
    this.txChar.addEventListener('characteristicvaluechanged', (e) => this.onChunk(e.target.value));
    await this.txChar.startNotifications();
  }

  async readGattEid() {
    const v = await this.eidChar.readValue();
    return new Uint8Array(v.buffer, v.byteOffset, v.byteLength).slice();
  }

  async send(type, payload = new Uint8Array(0)) {
    const msg = new Uint8Array(1 + payload.length);
    msg[0] = type;
    msg.set(payload, 1);
    for (let off = 0; off < msg.length; off += CHUNK_PAYLOAD) {
      const part = msg.subarray(off, off + CHUNK_PAYLOAD);
      const chunk = new Uint8Array(1 + part.length);
      chunk[0] = off + CHUNK_PAYLOAD >= msg.length ? LAST_CHUNK : 0;
      chunk.set(part, 1);
      await this.rxChar.writeValueWithResponse(chunk);
    }
  }

  // Resolves with the next complete message { type, payload }.
  receive(timeoutMs) {
    if (this.inbox.length) return Promise.resolve(this.inbox.shift());
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject };
      waiter.timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        reject(new Error(`Timed out after ${timeoutMs / 1000}s waiting for the phone`));
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }

  onChunk(view) {
    const chunk = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    if (chunk.length === 0) return;
    this.rxBuffer.push(...chunk.subarray(1));
    if (!(chunk[0] & LAST_CHUNK)) return;
    const msg = Uint8Array.from(this.rxBuffer);
    this.rxBuffer = [];
    if (msg.length === 0) return;
    this.deliver({ type: msg[0], payload: msg.slice(1) });
  }

  deliver(message) {
    const waiter = this.waiters.shift();
    if (waiter) {
      clearTimeout(waiter.timer);
      waiter.resolve(message);
    } else {
      this.inbox.push(message);
    }
  }

  onDisconnect() {
    this.log('GATT disconnected');
    for (const w of this.waiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(new Error('Phone disconnected'));
    }
  }

  disconnect() {
    this.device.removeEventListener('gattserverdisconnected', this.onDisconnect);
    if (this.device.gatt.connected) this.device.gatt.disconnect();
  }
}
