package com.keremsen.kriptoloji_app.cipher

import android.util.Base64
import android.util.Log
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object CipherFactory {
    const val METHOD_AES = "aes"
    const val METHOD_DES = "des"
    private const val TAG = "CipherFactory"

    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun encrypt(text: String, method: String, key: Any, useLibrary: Boolean = true): String {
        return when (method) {
            METHOD_AES -> AESCipher.encrypt(text, key, useLibrary)
            METHOD_DES -> DESCipher.encrypt(text, key, useLibrary)
            else -> throw IllegalArgumentException("Bilinmeyen metod: $method")
        }
    }

    fun decrypt(text: String, method: String, key: Any, useLibrary: Boolean = true): String {
        return when (method) {
            METHOD_AES -> AESCipher.decrypt(text, key, useLibrary)
            METHOD_DES -> DESCipher.decrypt(text, key, useLibrary)
            else -> throw IllegalArgumentException("Bilinmeyen metod: $method")
        }
    }
}

object ECCCipher {
    private const val TAG = "ECCCipher"

    fun generateKeyPair(): Pair<String, String> {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(256)
        val kp = kpg.generateKeyPair()
        return Pair(
            Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP),
            Base64.encodeToString(kp.private.encoded, Base64.NO_WRAP)
        )
    }

    fun deriveSharedKey(privateKeyPem: String, serverPublicKeyPem: String): String {
        val kf = KeyFactory.getInstance("EC")
        val clean = { k: String -> k.replace(Regex("-----(.*?)-----"), "").replace("\n", "").replace("\r", "").trim() }

        val privBytes = Base64.decode(clean(privateKeyPem), Base64.NO_WRAP)
        val privKey = kf.generatePrivate(PKCS8EncodedKeySpec(privBytes))
        val pubBytes = Base64.decode(clean(serverPublicKeyPem), Base64.NO_WRAP)
        val pubKey = kf.generatePublic(X509EncodedKeySpec(pubBytes))

        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(privKey)
        ka.doPhase(pubKey, true)

        val md = MessageDigest.getInstance("SHA-256")
        val derived = md.digest(ka.generateSecret()).sliceArray(0 until 16)
        return Base64.encodeToString(derived, Base64.NO_WRAP)
    }
}

object RSACipher {
    fun generateKeyPair(): Pair<String, String> {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        return Pair(
            Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP),
            Base64.encodeToString(kp.private.encoded, Base64.NO_WRAP)
        )
    }

    fun encrypt(text: String, publicKeyPem: String): String {
        val clean = publicKeyPem.replace(Regex("-----(.*?)-----"), "").replace("\n", "").trim()
        val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(Base64.decode(clean, Base64.NO_WRAP)))
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return Base64.encodeToString(cipher.doFinal(text.toByteArray()), Base64.NO_WRAP)
    }

    fun decrypt(ciphertext: String, privateKeyPem: String): String {
        val clean = privateKeyPem.replace(Regex("-----(.*?)-----"), "").replace("\n", "").trim()
        val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(Base64.decode(clean, Base64.NO_WRAP)))
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, key)
        return String(cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP)))
    }
}

object AESCipher {
    private fun prepareKey(key: Any): ByteArray {
        val bytes = if (key is String) key.toByteArray() else key as ByteArray
        return MessageDigest.getInstance("MD5").digest(bytes) // 16 byte
    }

    fun encrypt(text: String, key: Any, lib: Boolean): String {
        val k = prepareKey(key)
        val textBytes = text.toByteArray(Charsets.UTF_8)

        // MANUEL MOD
        if (!lib) {
            val encrypted = textBytes.mapIndexed { i, b ->
                (b.toInt() xor k[i % k.size].toInt()).toByte()
            }.toByteArray()
            return Base64.encodeToString(encrypted, Base64.NO_WRAP)
        }

        // KÜTÜPHANE MODU
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"))
        val iv = cipher.iv
        val encrypted = cipher.doFinal(textBytes)
        return Base64.encodeToString(iv + encrypted, Base64.NO_WRAP)
    }

    fun decrypt(data: String, key: Any, lib: Boolean): String {
        val k = prepareKey(key)
        val bytes = Base64.decode(data, Base64.NO_WRAP)

        // MANUEL MOD -
        if (!lib) {
            val decrypted = bytes.mapIndexed { i, b ->
                (b.toInt() xor k[i % k.size].toInt()).toByte()
            }.toByteArray()
            return String(decrypted, Charsets.UTF_8)
        }

        // KÜTÜPHANE MODU
        val iv = bytes.sliceArray(0 until 16)
        val content = bytes.sliceArray(16 until bytes.size)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), IvParameterSpec(iv))
        return String(cipher.doFinal(content), Charsets.UTF_8)
    }
}

object DESCipher {
    private fun prepareKey(key: Any): ByteArray {
        val bytes = if (key is String) key.toByteArray(Charsets.UTF_8) else key as ByteArray
        val digest = MessageDigest.getInstance("MD5").digest(bytes)
        return digest.sliceArray(0 until 8)
    }

    fun encrypt(text: String, key: Any, lib: Boolean): String {
        val k = prepareKey(key)
        val textBytes = text.toByteArray(Charsets.UTF_8)

        // MANUEL MOD
        if (!lib) {
            val encrypted = textBytes.mapIndexed { i, b ->
                (b.toInt() xor k[i % k.size].toInt()).toByte()
            }.toByteArray()
            return Base64.encodeToString(encrypted, Base64.NO_WRAP)
        }

        // KÜTÜPHANE MODU
        val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "DES"))
        val iv = cipher.iv // 8 byte
        val encrypted = cipher.doFinal(textBytes)
        return Base64.encodeToString(iv + encrypted, Base64.NO_WRAP)
    }

    fun decrypt(data: String, key: Any, lib: Boolean): String {
        val k = prepareKey(key)
        val bytes = Base64.decode(data, Base64.NO_WRAP)

        // MANUEL MOD
        if (!lib) {
            val decrypted = bytes.mapIndexed { i, b ->
                (b.toInt() xor k[i % k.size].toInt()).toByte()
            }.toByteArray()
            return String(decrypted, Charsets.UTF_8)
        }

        // KÜTÜPHANE MODU
        val iv = bytes.sliceArray(0 until 8) // DES İÇİN 8 BYTE!
        val content = bytes.sliceArray(8 until bytes.size)
        val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "DES"), IvParameterSpec(iv))
        return String(cipher.doFinal(content), Charsets.UTF_8)
    }
}