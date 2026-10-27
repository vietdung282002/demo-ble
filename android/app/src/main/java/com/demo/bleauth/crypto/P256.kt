package com.demo.bleauth.crypto

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECFieldFp
import javax.crypto.KeyAgreement

object P256 {
    const val PUBLIC_KEY_LEN = 65

    val params: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
    }

    fun generate(): KeyPair =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }

    /** Uncompressed SEC1 encoding: 0x04 || X(32) || Y(32). */
    fun encode(pub: ECPublicKey): ByteArray =
        Bytes.concat(byteArrayOf(4), fixed32(pub.w.affineX), fixed32(pub.w.affineY))

    fun decode(raw: ByteArray): ECPublicKey {
        require(raw.size == PUBLIC_KEY_LEN && raw[0] == 4.toByte()) { "Invalid P-256 public key encoding" }
        val x = BigInteger(1, raw.copyOfRange(1, 33))
        val y = BigInteger(1, raw.copyOfRange(33, 65))
        require(isOnCurve(x, y)) { "P-256 point is not on the curve" }
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params)) as ECPublicKey
    }

    /** Builds a key pair from a fixed scalar and its public key (test vectors only). */
    fun keyPair(privateScalar: ByteArray, publicRaw: ByteArray): KeyPair {
        val priv = KeyFactory.getInstance("EC")
            .generatePrivate(ECPrivateKeySpec(BigInteger(1, privateScalar), params))
        return KeyPair(decode(publicRaw), priv)
    }

    /** Returns the 32-byte x-coordinate of the shared point. */
    fun ecdh(priv: PrivateKey, peerPublicRaw: ByteArray): ByteArray =
        KeyAgreement.getInstance("ECDH").run {
            init(priv)
            doPhase(decode(peerPublicRaw), true)
            generateSecret()
        }

    private fun isOnCurve(x: BigInteger, y: BigInteger): Boolean {
        val p = (params.curve.field as ECFieldFp).p
        if (x.signum() < 0 || x >= p || y.signum() < 0 || y >= p) return false
        val lhs = y.modPow(BigInteger.valueOf(2), p)
        val rhs = x.pow(3).add(params.curve.a.multiply(x)).add(params.curve.b).mod(p)
        return lhs == rhs
    }

    private fun fixed32(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        return when {
            b.size == 32 -> b
            b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
            else -> ByteArray(32 - b.size) + b
        }
    }
}
