package com.example.mutualauth.Utility;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.NonNull;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyGeneratorUtility {

    // Initialize Bouncy Castle security provider
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private X509Certificate certificate;

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public KeyGeneratorUtility() {
        try {
            this.keyPair = generateKeyRSAPair("alias");
            this.privateKey = keyPair.getPrivate();
            this.publicKey = keyPair.getPublic();
            this.certificate = generateSelfSignedCertificate(keyPair);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Generate RSA Key Pair using Bouncy Castle
    public KeyPair generateKeyRSAPair(String alias) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

        keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build());

        return keyPairGenerator.generateKeyPair();
    }

    // Generate a self-signed certificate using Bouncy Castle
    public X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365 * 24 * 60 * 60 * 1000L); // Valid for 1 year
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        X500Name dnName = new X500Name("CN=Self-Signed Certificate");


        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, serialNumber, startDate, endDate, dnName, keyPair.getPublic());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    // Generate AES Key using Bouncy Castle
    public SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(256);  // AES with 256-bit key size
        return keyGenerator.generateKey();
    }

    // AES Encryption with SecretKey (Symmetric Encryption)
    public byte[] aesEncryptData(SecretKey secretKey, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] iv = cipher.getIV();  // Get the IV for GCM mode
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] encryptedData = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(ciphertext, 0, encryptedData, iv.length, ciphertext.length);

        return encryptedData;
    }

    // AES Decryption with SecretKey (Symmetric Decryption)
    public String aesDecryptData(SecretKey secretKey, byte[] encryptedData) throws Exception {
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, 12);  // Extract the IV
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, 12, encryptedData.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);  // 128-bit authentication tag
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] plaintextBytes = cipher.doFinal(ciphertext);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    // RSA Public Key Encryption (Asymmetric)
    public static byte[] encryptWithPublicKey(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // RSA Private Key Decryption (Asymmetric)
    public static byte[] decryptWithPrivateKey(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    // RSA Private Key Encryption (Signing - Asymmetric)
    public static byte[] encryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // RSA Public Key Decryption (Verifying - Asymmetric)
    public static byte[] decryptWithPublicKey(byte[] encryptedData, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedData);
    }

    public static byte[] encryptCertificate(X509Certificate cert, PrivateKey publicKey) throws Exception {
        // Generate a random AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt the certificate with AES
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] encryptedCert = aesCipher.doFinal(cert.getEncoded());

        // Encrypt the AES key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Combine everything: [IV length (4 bytes)][IV][Encrypted AES key length (4 bytes)][Encrypted AES key][Encrypted cert]
        byte[] result = new byte[4 + iv.length + 4 + encryptedAesKey.length + encryptedCert.length];
        System.arraycopy(intToByteArray(iv.length), 0, result, 0, 4);
        System.arraycopy(iv, 0, result, 4, iv.length);
        System.arraycopy(intToByteArray(encryptedAesKey.length), 0, result, 4 + iv.length, 4);
        System.arraycopy(encryptedAesKey, 0, result, 8 + iv.length, encryptedAesKey.length);
        System.arraycopy(encryptedCert, 0, result, 8 + iv.length + encryptedAesKey.length, encryptedCert.length);

        return result;
    }

    private static byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value
        };
    }

    public static X509Certificate decryptCertificate(byte[] encryptedData, PublicKey privateKey) throws Exception {
        // Extract IV, encrypted AES key, and encrypted cert from the input
        int ivLength = byteArrayToInt(encryptedData, 0);
        byte[] iv = new byte[ivLength];
        System.arraycopy(encryptedData, 4, iv, 0, ivLength);

        int encryptedAesKeyLength = byteArrayToInt(encryptedData, 4 + ivLength);
        byte[] encryptedAesKey = new byte[encryptedAesKeyLength];
        System.arraycopy(encryptedData, 8 + ivLength, encryptedAesKey, 0, encryptedAesKeyLength);

        byte[] encryptedCert = new byte[encryptedData.length - (8 + ivLength + encryptedAesKeyLength)];
        System.arraycopy(encryptedData, 8 + ivLength + encryptedAesKeyLength, encryptedCert, 0, encryptedCert.length);

        // Decrypt the AES key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Decrypt the certificate with AES
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        byte[] decryptedCertBytes = aesCipher.doFinal(encryptedCert);

        // Convert bytes back to X509Certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decryptedCertBytes));
    }

    private static int byteArrayToInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 24) |
                ((bytes[offset + 1] & 0xFF) << 16) |
                ((bytes[offset + 2] & 0xFF) << 8) |
                (bytes[offset + 3] & 0xFF);
    }
}
