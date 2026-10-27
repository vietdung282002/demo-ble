# BLE proximity login demo (CTAP 2.3 hybrid–inspired)

Two actors only: a **web page** (Chrome/Edge, Web Bluetooth central) and an **Android app** (BLE peripheral / GATT server).
The demo shows that a login QR code can only be completed by a phone that is physically within Bluetooth range of the browser.
A photo of the QR sent to someone elsewhere is useless: their phone's advert never reaches the browser.

No tunnel server and no extra socket are used. The handshake and all application messages go over BLE GATT.
CTAP 2.3 uses an L2CAP CoC for this, but web pages cannot open L2CAP channels, so GATT is used instead.
Security comes from the Noise layer either way.

```
web/        static page + crypto (WebCrypto) + Web Bluetooth
android/    Kotlin app: QR scanner, BLE advertiser + GATT server, Noise responder
```

## Protocol

1. **QR (browser)**: `BLEDEMO:` + base64url(JSON `{v:1, pk, s, t}`)
   - `pk` = initiator static P-256 key (uncompressed, 65 B), fresh per QR
   - `s` = `qrSecret` (16 random bytes)
   - `t` = issue time; the QR is valid for 120 s and is single-use
2. **Advert (phone)**: 16-bit service UUID `0xFFF3` + 20-byte service data (same layout as CTAP hybrid)
   - `aesKey ‖ hmacKey = HKDF-SHA256(qrSecret, salt=∅, info=LE32(1))`
   - `plaintext = [0x00 | nonce(10) | 0x00×5]`
   - `EID = AES-256-ECB(aesKey, plaintext) ‖ HMAC-SHA256(hmacKey, ct)[0..4]`
   - Advertised at low TX power to keep the range short.
3. **Connect (browser)**: `requestDevice({filters:[{services:[0xFFF3]}]})`. The browser reads the EID (from the advert via `watchAdvertisements` if available, otherwise from the `EID` characteristic), verifies the HMAC and decrypts it. Failure means the phone did not scan this QR.
4. **Handshake**: `Noise_KNpsk0_P256_AESGCM_SHA256`, prologue `BLEDEMO-v1`
   - `psk = HKDF-SHA256(qrSecret, salt=advert plaintext, info=LE32(3))`, so only a client that saw the advert can start
   - `-> s` (pre-message, from QR) · `-> psk, e` · `<- e, ee, se`
   - The first 3 bytes of the handshake hash are shown on both screens as a 6-hex code.
5. **Application data** (AES-256-GCM transport keys): browser sends `{type:"challenge", challenge, origin, browser}`. The phone asks the user, then replies `{type:"result", approved, echo}`.

GATT service `0000fff3-0000-1000-8000-00805f9b34fb`:

| Characteristic | UUID | Use |
|---|---|---|
| EID | `b1e0a001-…-2b01` | read, 20-byte EID |
| RX | `b1e0a001-…-2b02` | write, browser → phone |
| TX | `b1e0a001-…-2b03` | notify, phone → browser |

Framing: message = `[type][payload]`, type `0x01` handshake 1, `0x02` handshake 2, `0x03` data, `0x7f` error.
Each write or notification is `[flags][chunk]`, where bit 7 of `flags` marks the last chunk.

## Run

Requirements: Node 18+, JDK 17, Android SDK, an Android 8+ phone with BLE advertising support, Chrome or Edge on desktop.

```bash
# Web
cd web
npm test            # crypto + Noise tests, checks test vectors
npm start           # http://localhost:8080 (localhost = secure context for Web Bluetooth)

# Android
cd android
./gradlew test assembleDebug       # NoiseVectorsTest checks byte-compatibility with web/noise.js
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

macOS: allow Bluetooth for Chrome in *System Settings → Privacy & Security → Bluetooth*.

Demo steps:

1. Open `http://localhost:8080` in Chrome.
2. In the app, tap **Scan QR** and scan the code. The phone starts advertising.
3. In the browser, click **Connect nearby phone** and pick the device in the chooser. It may be listed by phone name or as "Unknown device".
4. Both screens show the same handshake code. Tap **Approve** on the phone, and the browser shows "Approved by nearby phone".

Negative checks:

- Phone out of range or Bluetooth off: the chooser shows no device.
- Scan an old QR, then connect from a reloaded page: the EID check fails.
- Two phones scan the same QR: only the first one that the browser handshakes with is accepted, because the QR becomes single-use.

## Limitations

- Web Bluetooth only works in Chromium browsers (not Safari, Firefox or iOS). It also needs a user click plus the device chooser.
- **Not phishing-resistant.** The `origin` is asserted by page JavaScript, not by the browser as in real WebAuthn. A look-alike site running this same code next to the victim still passes the proximity check.
- A BLE relay (an attacker radio near the victim forwarding to a remote browser) can defeat proximity. This is the same residual risk as CTAP hybrid.
- No authenticator signature or server verification: this demo covers only the Bluetooth connection and handshake. Integrating with Keycloak/Odoo means signing the challenge with a device key (Android Keystore) and verifying it server-side.
