package com.demo.bleauth.noise

import com.demo.bleauth.crypto.Aes
import com.demo.bleauth.crypto.Bytes
import com.demo.bleauth.crypto.Hkdf
import com.demo.bleauth.crypto.P256
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey

/*
 * Noise_KNpsk0_P256_AESGCM_SHA256, responder side (the phone).
 *
 *   -> s
 *   ...
 *   -> psk, e
 *   <- e, ee, se
 *
 * Must stay byte-compatible with web/noise.js (checked by NoiseVectorsTest).
 */

const val PROTOCOL_NAME = "Noise_KNpsk0_P256_AESGCM_SHA256"
val PROLOGUE = "BLEDEMO-v1".toByteArray()
private const val TAG_LEN = 16

class CipherState(private val key: ByteArray?) {
    private var n = 0L

    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        val k = key ?: return plaintext
        return Aes.gcmEncrypt(k, nonce(), ad, plaintext).also { n++ }
    }

    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val k = key ?: return ciphertext
        return Aes.gcmDecrypt(k, nonce(), ad, ciphertext).also { n++ }
    }

    private fun nonce(): ByteArray = ByteBuffer.allocate(12).putInt(0).putLong(n).array()
}

private class SymmetricState(initiatorStaticPub: ByteArray) {
    var h: ByteArray
    private var ck: ByteArray
    private var cipher = CipherState(null)

    init {
        val name = PROTOCOL_NAME.toByteArray()
        h = if (name.size <= 32) name.copyOf(32) else sha256(name)
        ck = h
        mixHash(PROLOGUE)
        mixHash(initiatorStaticPub) // pre-message "-> s"
    }

    fun mixHash(data: ByteArray) {
        h = sha256(h + data)
    }

    fun mixKey(ikm: ByteArray) {
        val (newCk, k) = hkdf(ck, ikm, 2)
        ck = newCk
        cipher = CipherState(k)
    }

    fun mixKeyAndHash(ikm: ByteArray) {
        val (newCk, tempH, k) = hkdf(ck, ikm, 3)
        ck = newCk
        mixHash(tempH)
        cipher = CipherState(k)
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray =
        cipher.encryptWithAd(h, plaintext).also { mixHash(it) }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray =
        cipher.decryptWithAd(h, ciphertext).also { mixHash(ciphertext) }

    fun split(): Pair<CipherState, CipherState> {
        val (k1, k2) = hkdf(ck, ByteArray(0), 2)
        return CipherState(k1) to CipherState(k2)
    }

    private fun hkdf(chainingKey: ByteArray, ikm: ByteArray, n: Int): List<ByteArray> {
        val tempKey = Hkdf.hmacSha256(chainingKey, ikm)
        val out1 = Hkdf.hmacSha256(tempKey, byteArrayOf(1))
        val out2 = Hkdf.hmacSha256(tempKey, out1 + byteArrayOf(2))
        if (n == 2) return listOf(out1, out2)
        val out3 = Hkdf.hmacSha256(tempKey, out2 + byteArrayOf(3))
        return listOf(out1, out2, out3)
    }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}

class NoiseResponder(
    private val initiatorStaticPub: ByteArray,
    private val psk: ByteArray,
    private val genKeyPair: () -> KeyPair = P256::generate,
) {
    class Result(
        val message: ByteArray,
        val send: CipherState,
        val recv: CipherState,
        val handshakeHash: ByteArray,
    )

    private lateinit var ss: SymmetricState
    private lateinit var re: ByteArray

    /** Throws if the initiator used a different psk or static key (wrong QR / no advert). */
    fun readMessage1(msg: ByteArray): ByteArray {
        require(msg.size >= P256.PUBLIC_KEY_LEN + TAG_LEN) { "Handshake message 1 too short" }
        ss = SymmetricState(initiatorStaticPub)
        ss.mixKeyAndHash(psk) // psk
        re = msg.copyOfRange(0, P256.PUBLIC_KEY_LEN) // e
        P256.decode(re)
        ss.mixHash(re)
        ss.mixKey(re)
        return ss.decryptAndHash(msg.copyOfRange(P256.PUBLIC_KEY_LEN, msg.size))
    }

    fun writeMessage2(payload: ByteArray): Result {
        val e = genKeyPair()
        val ePub = P256.encode(e.public as ECPublicKey)
        ss.mixHash(ePub) // e
        ss.mixKey(ePub)
        ss.mixKey(P256.ecdh(e.private, re)) // ee
        ss.mixKey(P256.ecdh(e.private, initiatorStaticPub)) // se
        val msg = Bytes.concat(ePub, ss.encryptAndHash(payload))
        val (c1, c2) = ss.split()
        return Result(msg, send = c2, recv = c1, handshakeHash = ss.h)
    }
}
