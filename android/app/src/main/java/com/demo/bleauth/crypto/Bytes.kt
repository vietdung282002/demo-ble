package com.demo.bleauth.crypto

import java.security.SecureRandom

object Bytes {
    private val random = SecureRandom()

    fun random(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var off = 0
        for (p in parts) {
            p.copyInto(out, off)
            off += p.size
        }
        return out
    }

    fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun fromHex(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    fun b64urlDecode(s: String): ByteArray = java.util.Base64.getUrlDecoder().decode(s)

    fun b64urlEncode(b: ByteArray): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b)
}
