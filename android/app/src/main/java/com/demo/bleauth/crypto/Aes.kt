package com.demo.bleauth.crypto

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object Aes {
    fun gcmEncrypt(key: ByteArray, nonce: ByteArray, ad: ByteArray, plaintext: ByteArray): ByteArray =
        gcm(Cipher.ENCRYPT_MODE, key, nonce, ad, plaintext)

    /** Throws [javax.crypto.AEADBadTagException] when authentication fails. */
    fun gcmDecrypt(key: ByteArray, nonce: ByteArray, ad: ByteArray, ciphertext: ByteArray): ByteArray =
        gcm(Cipher.DECRYPT_MODE, key, nonce, ad, ciphertext)

    private fun gcm(mode: Int, key: ByteArray, nonce: ByteArray, ad: ByteArray, input: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(ad)
        return cipher.doFinal(input)
    }

    fun ecbEncryptBlock(key: ByteArray, block: ByteArray): ByteArray {
        require(block.size == 16)
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(block)
    }
}
