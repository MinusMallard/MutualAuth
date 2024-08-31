package com.example.mutualauth.Utility

import android.util.Base64
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom


object TestKeyPair {
    private val keyPair: KeyPair by lazy { generateKeyPair() }

    val publicKey: PublicKey
        get() = keyPair.public

    val privateKey: PrivateKey
        get() = keyPair.private

    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        val secureRandom = SecureRandom.getInstance("SHA1PRNG")

        // Use a fixed seed
        val seed = "fixed_seed_for_testing".toByteArray()
        secureRandom.setSeed(seed)

        keyPairGenerator.initialize(2048, secureRandom)
        return keyPairGenerator.generateKeyPair()
    }

    fun getPublicKeyString(): String {
        return Base64.encodeToString(publicKey.encoded, Base64.DEFAULT)
    }

    fun getPrivateKeyString(): String {
        return Base64.encodeToString(privateKey.encoded, Base64.DEFAULT)
    }
}