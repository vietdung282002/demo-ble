package com.demo.bleauth

import com.demo.bleauth.crypto.Bytes.fromHex
import com.demo.bleauth.crypto.Bytes.toHex
import com.demo.bleauth.crypto.Eid
import com.demo.bleauth.crypto.P256
import com.demo.bleauth.noise.NoiseResponder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File

/** Checks byte-for-byte compatibility with web/noise.js using web/test/vectors.json. */
class NoiseVectorsTest {
    private val v = JSONObject(File("../../web/test/vectors.json").readText())

    private fun hex(name: String) = fromHex(v.getString(name))

    private fun responder(psk: ByteArray = hex("psk")) = NoiseResponder(
        initiatorStaticPub = hex("initiatorStaticPub"),
        psk = psk,
        genKeyPair = { P256.keyPair(hex("responderEphemeralPriv"), hex("responderEphemeralPub")) },
    )

    @Test
    fun advertAndPskMatch() {
        val keys = Eid.deriveKeys(hex("qrSecret"))
        assertEquals(v.getString("advert"), toHex(Eid.encrypt(keys, hex("advertPlaintext"))))
        assertEquals(v.getString("psk"), toHex(Eid.psk(hex("qrSecret"), hex("advertPlaintext"))))
    }

    @Test
    fun handshakeAndTransportMatch() {
        val r = responder()
        assertEquals(0, r.readMessage1(hex("msg1")).size)
        val result = r.writeMessage2(hex("payload2"))
        assertEquals(v.getString("msg2"), toHex(result.message))
        assertEquals(v.getString("handshakeHash"), toHex(result.handshakeHash))
        assertEquals(v.getString("transport1"), toHex(result.recv.decryptWithAd(ByteArray(0), hex("transport1Ciphertext"))))
        assertEquals(v.getString("transport2Ciphertext"), toHex(result.send.encryptWithAd(ByteArray(0), hex("transport2"))))
    }

    @Test
    fun wrongPskIsRejected() {
        val wrongPsk = hex("psk").also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { responder(wrongPsk).readMessage1(hex("msg1")) }
    }

    @Test
    fun invalidPointIsRejected() {
        val bad = hex("initiatorStaticPub").also { it[64] = (it[64].toInt() xor 1).toByte() }
        assertThrows(IllegalArgumentException::class.java) { P256.decode(bad) }
    }
}
