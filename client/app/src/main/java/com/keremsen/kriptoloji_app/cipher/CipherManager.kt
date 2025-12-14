package com.keremsen.kriptoloji_app.cipher

import android.util.Base64
import android.util.Log
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.Security
import java.security.spec.X509EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.KeyPairGenerator
import org.json.JSONArray
import java.security.MessageDigest

object CipherFactory {
    const val METHOD_AES = "aes"
    const val METHOD_DES = "des"
    const val METHOD_RSA = "rsa"

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
            METHOD_RSA -> {
                val publicKey = key as? String ?: throw IllegalArgumentException("RSA için public key string olmalı")
                RSACipher.encrypt(text, publicKey, useLibrary)
            }
            else -> throw IllegalArgumentException("Bilinmeyen şifreleme yöntemi: $method")
        }
    }

    fun decrypt(text: String, method: String, key: Any, useLibrary: Boolean = true): String {
        return when (method) {
            METHOD_AES -> AESCipher.decrypt(text, key, useLibrary)
            METHOD_DES -> DESCipher.decrypt(text, key, useLibrary)
            METHOD_RSA -> {
                val privateKey = key as? String ?: throw IllegalArgumentException("RSA için private key string olmalı")
                RSACipher.decrypt(text, privateKey, useLibrary)
            }
            else -> throw IllegalArgumentException("Bilinmeyen şifreleme yöntemi: $method")
        }
    }
}

object AESCipher {
    private const val TAG = "AESCipher"
    private const val KEY_SIZE = 16 // AES-128 için 16 byte

    private fun ensureKey(key: Any): ByteArray {
        return when (key) {
            is String -> {
                // String anahtarı MD5 ile hash'le (16 byte)
                val md = MessageDigest.getInstance("MD5")
                md.digest(key.toByteArray())
            }
            is ByteArray -> {
                if (key.size >= KEY_SIZE) key.sliceArray(0 until KEY_SIZE)
                else key + ByteArray(KEY_SIZE - key.size) { 0 }
            }
            else -> throw IllegalArgumentException("AES anahtarı string veya ByteArray olmalı")
        }
    }

    fun encrypt(text: String, key: Any, useLibrary: Boolean = true): String {
        val keyBytes = ensureKey(key)
        val textBytes = text.toByteArray(Charsets.UTF_8)

        return if (useLibrary) {
            encryptLibrary(textBytes, keyBytes)
        } else {
            encryptManual(textBytes, keyBytes)
        }
    }

    fun decrypt(ciphertext: String, key: Any, useLibrary: Boolean = true): String {
        val keyBytes = ensureKey(key)

        return if (useLibrary) {
            decryptLibrary(ciphertext, keyBytes)
        } else {
            decryptManual(ciphertext, keyBytes)
        }
    }

    private fun encryptLibrary(textBytes: ByteArray, key: ByteArray): String {
        try {
            val secretKey = SecretKeySpec(key, "AES")
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            
            val iv = cipher.iv
            val encrypted = cipher.doFinal(textBytes)
            
            // IV + encrypted data
            val combined = iv + encrypted
            return Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "AES şifreleme hatası: ${e.message}", e)
            throw RuntimeException("AES şifreleme hatası", e)
        }
    }

    private fun decryptLibrary(ciphertext: String, key: ByteArray): String {
        try {
            val data = Base64.decode(ciphertext, Base64.NO_WRAP)
            val iv = data.sliceArray(0 until 16)
            val encrypted = data.sliceArray(16 until data.size)
            
            val secretKey = SecretKeySpec(key, "AES")
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
            
            val decrypted = cipher.doFinal(encrypted)
            return String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "AES deşifreleme hatası: ${e.message}", e)
            throw RuntimeException("AES deşifreleme hatası", e)
        }
    }

    private fun encryptManual(textBytes: ByteArray, key: ByteArray): String {
        // Basitleştirilmiş manuel AES (XOR tabanlı - eğitim amaçlı)
        val iv = ByteArray(16) { 0 } // Basit IV
        val result = mutableListOf<Byte>()
        
        // Basit XOR şifreleme (gerçek AES yerine)
        for (i in textBytes.indices step 16) {
            val block = textBytes.sliceArray(i until minOf(i + 16, textBytes.size))
            val paddedBlock = block + ByteArray(16 - block.size) { 0 }
            val encryptedBlock = paddedBlock.mapIndexed { idx, byte ->
                (byte.toInt() xor key[idx % key.size].toInt()).toByte()
            }
            result.addAll(encryptedBlock)
        }
        
        val combined = iv + result.toByteArray()
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decryptManual(ciphertext: String, key: ByteArray): String {
        val data = Base64.decode(ciphertext, Base64.NO_WRAP)
        val iv = data.sliceArray(0 until 16)
        val encrypted = data.sliceArray(16 until data.size)
        
        val result = mutableListOf<Byte>()
        for (i in encrypted.indices step 16) {
            val block = encrypted.sliceArray(i until minOf(i + 16, encrypted.size))
            val decryptedBlock = block.mapIndexed { idx, byte ->
                (byte.toInt() xor key[idx % key.size].toInt()).toByte()
            }
            result.addAll(decryptedBlock)
        }

        val decrypted = result.toByteArray().dropLastWhile { it == 0.toByte() }.toByteArray()
        return String(decrypted, Charsets.UTF_8)
    }
}

object DESCipher {
    private const val TAG = "DESCipher"
    private const val KEY_SIZE = 8 // DES için 8 byte

    private fun ensureKey(key: Any): ByteArray {
        return when (key) {
            is String -> {
                val md = MessageDigest.getInstance("MD5")
                md.digest(key.toByteArray()).sliceArray(0 until KEY_SIZE)
            }
            is ByteArray -> {
                if (key.size >= KEY_SIZE) key.sliceArray(0 until KEY_SIZE)
                else key + ByteArray(KEY_SIZE - key.size) { 0 }
            }
            else -> throw IllegalArgumentException("DES anahtarı string veya ByteArray olmalı")
        }
    }

    fun encrypt(text: String, key: Any, useLibrary: Boolean = true): String {
        val keyBytes = ensureKey(key)
        val textBytes = text.toByteArray(Charsets.UTF_8)

        return if (useLibrary) {
            encryptLibrary(textBytes, keyBytes)
        } else {
            encryptManual(textBytes, keyBytes)
        }
    }

    fun decrypt(ciphertext: String, key: Any, useLibrary: Boolean = true): String {
        val keyBytes = ensureKey(key)

        return if (useLibrary) {
            decryptLibrary(ciphertext, keyBytes)
        } else {
            decryptManual(ciphertext, keyBytes)
        }
    }

    private fun encryptLibrary(textBytes: ByteArray, key: ByteArray): String {
        try {
            val secretKey = SecretKeySpec(key, "DES")
            val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            
            val iv = cipher.iv
            val encrypted = cipher.doFinal(textBytes)
            
            val combined = iv + encrypted
            return Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "DES şifreleme hatası: ${e.message}", e)
            throw RuntimeException("DES şifreleme hatası", e)
        }
    }

    private fun decryptLibrary(ciphertext: String, key: ByteArray): String {
        try {
            val data = Base64.decode(ciphertext, Base64.NO_WRAP)
            val iv = data.sliceArray(0 until 8)
            val encrypted = data.sliceArray(8 until data.size)
            
            val secretKey = SecretKeySpec(key, "DES")
            val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
            
            val decrypted = cipher.doFinal(encrypted)
            return String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "DES deşifreleme hatası: ${e.message}", e)
            throw RuntimeException("DES deşifreleme hatası", e)
        }
    }

    private fun encryptManual(textBytes: ByteArray, key: ByteArray): String {
        val iv = ByteArray(8) { 0 }
        val result = mutableListOf<Byte>()
        
        for (i in textBytes.indices step 8) {
            val block = textBytes.sliceArray(i until minOf(i + 8, textBytes.size))
            val paddedBlock = block + ByteArray(8 - block.size) { 0 }
            val encryptedBlock = paddedBlock.mapIndexed { idx, byte ->
                (byte.toInt() xor key[idx % key.size].toInt()).toByte()
            }
            result.addAll(encryptedBlock)
        }
        
        val combined = iv + result.toByteArray()
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decryptManual(ciphertext: String, key: ByteArray): String {
        val data = Base64.decode(ciphertext, Base64.NO_WRAP)
        val iv = data.sliceArray(0 until 8)
        val encrypted = data.sliceArray(8 until data.size)
        
        val result = mutableListOf<Byte>()
        for (i in encrypted.indices step 8) {
            val block = encrypted.sliceArray(i until minOf(i + 8, encrypted.size))
            val decryptedBlock = block.mapIndexed { idx, byte ->
                (byte.toInt() xor key[idx % key.size].toInt()).toByte()
            }
            result.addAll(decryptedBlock)
        }
        
        val decrypted = result.toByteArray().dropLastWhile { it == 0.toByte() }.toByteArray()
        return String(decrypted, Charsets.UTF_8)
    }
}

object RSACipher {
    private const val TAG = "RSACipher"
    private const val KEY_SIZE = 2048
    private const val CHUNK_SIZE = 190

    fun generateKeyPair(): Pair<String, String> {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(KEY_SIZE)
            val keyPair = keyPairGenerator.generateKeyPair()
            
            val publicKeyPem = Base64.encodeToString(
                keyPair.public.encoded,
                Base64.NO_WRAP
            )
            val privateKeyPem = Base64.encodeToString(
                keyPair.private.encoded,
                Base64.NO_WRAP
            )
            
            return Pair(publicKeyPem, privateKeyPem)
        } catch (e: Exception) {
            Log.e(TAG, "RSA anahtar oluşturma hatası: ${e.message}", e)
            throw RuntimeException("RSA anahtar oluşturma hatası", e)
        }
    }

    fun encrypt(text: String, publicKeyPem: String, useLibrary: Boolean = true): String {
        if (!useLibrary) {
            return encryptManual(text, publicKeyPem)
        }
        
        try {
            Log.d(TAG, "RSA şifreleme başlatılıyor, key uzunluğu: ${publicKeyPem.length}")
            val pemContent = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\n", "")
                .replace(" ", "")
            

            val publicKeyBytes = Base64.decode(pemContent, Base64.NO_WRAP)
            Log.d(TAG, "Key decode edildi, byte uzunluğu: ${publicKeyBytes.size}")
            

            val keySpec = X509EncodedKeySpec(publicKeyBytes)
            val keyFactory = KeyFactory.getInstance("RSA")
            val publicKey = keyFactory.generatePublic(keySpec)
            Log.d(TAG, "Public key oluşturuldu")
            

            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            Log.d(TAG, "Cipher hazır, metin şifreleniyor: ${text.length} byte")
            
            val textBytes = text.toByteArray(Charsets.UTF_8)
            val encryptedChunks = mutableListOf<String>()

            for (i in textBytes.indices step CHUNK_SIZE) {
                val chunk = textBytes.sliceArray(i until minOf(i + CHUNK_SIZE, textBytes.size))
                val encrypted = cipher.doFinal(chunk)
                encryptedChunks.add(Base64.encodeToString(encrypted, Base64.NO_WRAP))
            }
            
            Log.d(TAG, "Şifreleme tamamlandı, ${encryptedChunks.size} chunk oluşturuldu")
            return JSONArray(encryptedChunks).toString()
        } catch (e: Exception) {
            Log.e(TAG, "RSA şifreleme hatası: ${e.message}", e)
            Log.e(TAG, "Hata stack trace: ${e.stackTraceToString()}")
            throw RuntimeException("RSA şifreleme hatası: ${e.message}", e)
        }
    }

    fun decrypt(ciphertext: String, privateKeyPem: String, useLibrary: Boolean = true): String {
        if (!useLibrary) {
            return decryptManual(ciphertext, privateKeyPem)
        }
        
        try {
            val pemContent = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("\n", "")
                .replace(" ", "")
            
            val privateKeyBytes = Base64.decode(pemContent, Base64.NO_WRAP)
            val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
            val keyFactory = KeyFactory.getInstance("RSA")
            val privateKey = keyFactory.generatePrivate(keySpec)
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            
            val encryptedChunks = JSONArray(ciphertext)
            val decryptedChunks = mutableListOf<Byte>()
            
            for (i in 0 until encryptedChunks.length()) {
                val chunkBase64 = encryptedChunks.getString(i)
                val chunk = Base64.decode(chunkBase64, Base64.NO_WRAP)
                val decrypted = cipher.doFinal(chunk)
                decryptedChunks.addAll(decrypted.toList())
            }
            
            return String(decryptedChunks.toByteArray(), Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "RSA deşifreleme hatası: ${e.message}", e)
            throw RuntimeException("RSA deşifreleme hatası", e)
        }
    }


    private fun encryptManual(text: String, publicKeyPem: String): String {
        try {
            Log.d(TAG, "Manuel RSA şifreleme başlatılıyor")

            val md = MessageDigest.getInstance("MD5")
            val keyHash = md.digest(publicKeyPem.toByteArray(Charsets.UTF_8))
            val keyHashHex = keyHash.joinToString("") { "%02x".format(it) }
            val keyBytes = keyHashHex.toByteArray(Charsets.UTF_8)
            
            val textBytes = text.toByteArray(Charsets.UTF_8)
            val encrypted = ByteArray(textBytes.size)

            for (i in textBytes.indices) {
                encrypted[i] = (textBytes[i].toInt() xor keyBytes[i % keyBytes.size].toInt()).toByte()
            }
            val encryptedBase64 = Base64.encodeToString(encrypted, Base64.NO_WRAP)
            return JSONArray(listOf(encryptedBase64)).toString()
        } catch (e: Exception) {
            Log.e(TAG, "Manuel RSA şifreleme hatası: ${e.message}", e)
            throw RuntimeException("Manuel RSA şifreleme hatası: ${e.message}", e)
        }
    }


    private fun decryptManual(ciphertext: String, keyPem: String): String {
        try {
            Log.d(TAG, "Manuel RSA deşifreleme başlatılıyor")
            Log.d(TAG, "Key uzunluğu: ${keyPem.length}, Key başlangıcı: ${keyPem.take(50)}")
            val md = MessageDigest.getInstance("MD5")
            val keyBytesForHash = keyPem.toByteArray(Charsets.UTF_8)
            val keyHash = md.digest(keyBytesForHash)
            val keyHashHex = keyHash.joinToString("") { "%02x".format(it) }
            val keyBytes = keyHashHex.toByteArray(Charsets.UTF_8)
            
            Log.d(TAG, "Key hash (MD5): $keyHashHex")
            
            val encryptedChunks = JSONArray(ciphertext)
            val encryptedBase64 = encryptedChunks.getString(0)
            val encrypted = Base64.decode(encryptedBase64, Base64.NO_WRAP)
            val decrypted = ByteArray(encrypted.size)

            for (i in encrypted.indices) {
                decrypted[i] = (encrypted[i].toInt() xor keyBytes[i % keyBytes.size].toInt()).toByte()
            }
            
            return String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "Manuel RSA deşifreleme hatası: ${e.message}", e)
            throw RuntimeException("Manuel RSA deşifreleme hatası: ${e.message}", e)
        }
    }
}
