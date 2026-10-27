package com.demo.bleauth.crypto

/** BLE advert payload derived from the QR secret (layout follows CTAP hybrid). */
object Eid {
    const val ADVERT_LEN = 20

    class Keys(val aesKey: ByteArray, val hmacKey: ByteArray)

    fun deriveKeys(qrSecret: ByteArray): Keys {
        val okm = Hkdf.derive(qrSecret, ByteArray(0), Hkdf.purpose(1), 64)
        return Keys(okm.copyOfRange(0, 32), okm.copyOfRange(32, 64))
    }

    /** [flags=0 | connection nonce 10B | reserved 5B (zero)] */
    fun newPlaintext(): ByteArray = Bytes.concat(byteArrayOf(0), Bytes.random(10), ByteArray(5))

    fun encrypt(keys: Keys, plaintext: ByteArray): ByteArray {
        val ct = Aes.ecbEncryptBlock(keys.aesKey, plaintext)
        val tag = Hkdf.hmacSha256(keys.hmacKey, ct).copyOfRange(0, 4)
        return ct + tag
    }

    fun psk(qrSecret: ByteArray, plaintext: ByteArray): ByteArray =
        Hkdf.derive(qrSecret, plaintext, Hkdf.purpose(3), 32)
}
