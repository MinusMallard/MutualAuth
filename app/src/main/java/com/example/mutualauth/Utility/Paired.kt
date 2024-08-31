package com.example.mutualauth.Utility

import java.security.PublicKey
import java.security.cert.X509Certificate

object Paired {

    private var publicKey: PublicKey? = null

    private var certificate: X509Certificate? = null

    fun getPublicKey(): PublicKey? {
        return publicKey
    }

    fun getCertificate(): X509Certificate? {
        return certificate
    }

    var recievedPackets: ByteArray = byteArrayOf()

    fun generateCertificate() {
        if (certificate == null) {
            certificate = KeyGeneratorUtility.byteArrayToX509Certificate(recievedPackets)
            publicKey = certificate?.publicKey
        }
    }
}