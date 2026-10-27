package com.demo.bleauth

import com.demo.bleauth.crypto.Bytes
import com.demo.bleauth.crypto.P256
import org.json.JSONObject

/** Parsed `BLEDEMO:` QR code: base64url(JSON {v, pk, s, t}). */
class QrPayload(val initiatorStaticPub: ByteArray, val qrSecret: ByteArray, val issuedAtSeconds: Long) {
    companion object {
        private const val PREFIX = "BLEDEMO:"
        const val TTL_SECONDS = 120L

        fun parse(text: String): QrPayload {
            require(text.startsWith(PREFIX)) { "Not a BLEDEMO QR code" }
            val json = JSONObject(String(Bytes.b64urlDecode(text.removePrefix(PREFIX))))
            require(json.getInt("v") == 1) { "Unsupported QR version" }
            val pk = Bytes.b64urlDecode(json.getString("pk"))
            P256.decode(pk)
            val secret = Bytes.b64urlDecode(json.getString("s"))
            require(secret.size == 16) { "Invalid QR secret" }
            return QrPayload(pk, secret, json.getLong("t"))
        }
    }

    fun secondsLeft(nowSeconds: Long = System.currentTimeMillis() / 1000): Long =
        TTL_SECONDS - (nowSeconds - issuedAtSeconds)
}
