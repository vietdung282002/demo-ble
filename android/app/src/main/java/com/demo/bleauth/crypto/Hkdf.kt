package com.demo.bleauth.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object Hkdf {
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /**
     * RFC 5869 HKDF-SHA256. An empty salt is replaced by 32 zero bytes, which is what the RFC
     * specifies (and SecretKeySpec rejects empty keys).
     */
    fun derive(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var off = 0
        var counter = 1
        while (off < length) {
            t = hmacSha256(prk, Bytes.concat(t, info, byteArrayOf(counter.toByte())))
            val n = minOf(t.size, length - off)
            t.copyInto(out, off, 0, n)
            off += n
            counter++
        }
        return out
    }

    /** CTAP hybrid style "purpose" info: 4-byte little-endian integer. */
    fun purpose(value: Int): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
}
