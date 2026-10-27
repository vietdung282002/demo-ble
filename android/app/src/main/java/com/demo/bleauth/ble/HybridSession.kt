package com.demo.bleauth.ble

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import com.demo.bleauth.QrPayload
import com.demo.bleauth.crypto.Bytes
import com.demo.bleauth.crypto.Eid
import com.demo.bleauth.noise.CipherState
import com.demo.bleauth.noise.NoiseResponder
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * One login attempt for one scanned QR code:
 * ADVERTISING -> CONNECTED -> HANDSHAKE_DONE -> AWAIT_USER -> DONE (or ERROR at any point).
 *
 * BLE callbacks arrive on binder threads; all protocol work runs on a single worker thread and
 * every [Ui] callback is posted to the main thread.
 */
class HybridSession(
    context: Context,
    private val qr: QrPayload,
    private val ui: Ui,
) : BlePeripheral.Listener {

    enum class State { ADVERTISING, CONNECTED, HANDSHAKE_DONE, AWAIT_USER, DONE, ERROR }

    class ApprovalRequest(val origin: String, val browser: String, val challenge: String, val code: String)

    interface Ui {
        fun onState(state: State, detail: String)
        fun onLog(message: String)
        fun onApprovalRequest(request: ApprovalRequest)
    }

    companion object {
        private const val MAX_HANDSHAKE_ATTEMPTS = 3
        private const val MAX_CLOCK_SKEW_SECONDS = 60L
    }

    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private val advertPlaintext = Eid.newPlaintext()
    private val eid = Eid.encrypt(Eid.deriveKeys(qr.qrSecret), advertPlaintext)
    private val peripheral = BlePeripheral(context.applicationContext, eid, this)

    private var state = State.ADVERTISING
    private var handshakeAttempts = 0
    private var send: CipherState? = null
    private var recv: CipherState? = null
    private var pendingChallenge: String? = null
    private var handshakeCode = ""
    private val timeout = Runnable { onWorker { fail("Session expired") } }

    fun start() {
        val left = qr.secondsLeft()
        if (left <= 0) return fail("QR code expired")
        if (left > QrPayload.TTL_SECONDS + MAX_CLOCK_SKEW_SECONDS) return fail("QR timestamp is in the future (check clock)")
        log("EID ${Bytes.toHex(eid)}")
        peripheral.start()
        main.postDelayed(timeout, left * 1000)
    }

    fun respond(approved: Boolean) = onWorker {
        val challenge = pendingChallenge
        val cipher = send
        if (state != State.AWAIT_USER || challenge == null || cipher == null) return@onWorker
        val result = JSONObject()
            .put("type", "result")
            .put("approved", approved)
            .put("echo", challenge)
        peripheral.send(BlePeripheral.MSG_DATA, cipher.encryptWithAd(ByteArray(0), result.toString().toByteArray()))
        setState(State.DONE, if (approved) "Approved" else "Rejected")
        // Give the last notification time to leave before tearing down the GATT server.
        main.postDelayed({ shutdown() }, 1500)
    }

    fun cancel() = onWorker {
        if (state != State.DONE && state != State.ERROR) fail("Cancelled")
    }

    // ---------- BlePeripheral.Listener (binder threads) ----------

    override fun onLog(message: String) = log(message)

    override fun onAdvertising() = onWorker {
        if (state == State.ADVERTISING) setState(State.ADVERTISING, "Advertising, waiting for the browser")
    }

    override fun onCentralConnected(address: String) = onWorker {
        if (state == State.ADVERTISING) setState(State.CONNECTED, "Browser connected ($address)")
    }

    override fun onCentralDisconnected(address: String) = onWorker {
        when (state) {
            State.CONNECTED -> setState(State.ADVERTISING, "Browser disconnected, advertising again")
            State.HANDSHAKE_DONE, State.AWAIT_USER -> fail("Browser disconnected")
            else -> Unit
        }
    }

    override fun onMessage(type: Int, payload: ByteArray) = onWorker {
        try {
            when (type) {
                BlePeripheral.MSG_HANDSHAKE_1 -> onHandshake1(payload)
                BlePeripheral.MSG_DATA -> onData(payload)
                else -> log("Ignoring message type 0x%02x".format(type))
            }
        } catch (e: Exception) {
            fail("Protocol error: ${e.message}")
        }
    }

    override fun onFatal(message: String) = onWorker { fail(message) }

    // ---------- protocol (worker thread) ----------

    private fun onHandshake1(msg: ByteArray) {
        if (state != State.CONNECTED) return log("Unexpected handshake message in state $state")
        log("<- handshake message 1 (${msg.size} B)")
        val responder = NoiseResponder(qr.initiatorStaticPub, Eid.psk(qr.qrSecret, advertPlaintext))
        try {
            responder.readMessage1(msg)
        } catch (e: Exception) {
            // Wrong psk/static key: the peer did not see our advert or holds a different QR.
            handshakeAttempts++
            peripheral.send(BlePeripheral.MSG_ERROR, "handshake failed".toByteArray())
            if (handshakeAttempts >= MAX_HANDSHAKE_ATTEMPTS) fail("Too many failed handshakes")
            else log("Handshake message 1 rejected (${e.javaClass.simpleName})")
            return
        }

        val info = JSONObject()
            .put("device", "${Build.MANUFACTURER} ${Build.MODEL}")
            .put("model", "Android ${Build.VERSION.RELEASE}")
        val result = responder.writeMessage2(info.toString().toByteArray())
        send = result.send
        recv = result.recv
        handshakeCode = Bytes.toHex(result.handshakeHash.copyOfRange(0, 3)).uppercase()
        peripheral.send(BlePeripheral.MSG_HANDSHAKE_2, result.message)
        // Channel is bound to this browser now; stop announcing ourselves.
        peripheral.stopAdvertising()
        log("-> handshake message 2, hash ${Bytes.toHex(result.handshakeHash)}")
        setState(State.HANDSHAKE_DONE, "Secure channel established, code $handshakeCode")
    }

    private fun onData(ciphertext: ByteArray) {
        val cipher = recv ?: return log("Data before handshake ignored")
        if (state != State.HANDSHAKE_DONE) return log("Unexpected data in state $state")
        val json = JSONObject(String(cipher.decryptWithAd(ByteArray(0), ciphertext)))
        require(json.getString("type") == "challenge") { "Expected challenge" }
        val request = ApprovalRequest(
            origin = json.getString("origin"),
            browser = json.optString("browser", "unknown"),
            challenge = json.getString("challenge"),
            code = handshakeCode,
        )
        pendingChallenge = request.challenge
        log("<- encrypted challenge ${request.challenge} from ${request.origin}")
        setState(State.AWAIT_USER, "Waiting for your approval")
        main.post { ui.onApprovalRequest(request) }
    }

    private fun fail(reason: String) {
        if (state == State.DONE || state == State.ERROR) return
        setState(State.ERROR, reason)
        shutdown()
    }

    private fun shutdown() {
        main.removeCallbacks(timeout)
        main.post { peripheral.stop() }
        worker.shutdown()
    }

    private fun setState(newState: State, detail: String) {
        state = newState
        log("[$newState] $detail")
        main.post { ui.onState(newState, detail) }
    }

    private fun onWorker(block: () -> Unit) {
        try {
            worker.execute(block)
        } catch (_: RejectedExecutionException) {
            // Session already shut down; late BLE callbacks are dropped.
        }
    }

    private fun log(message: String) {
        main.post { ui.onLog(message) }
    }
}
