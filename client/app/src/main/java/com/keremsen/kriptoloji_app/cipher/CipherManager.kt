package com.keremsen.kriptoloji_app.cipher

import android.util.Base64
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

    fun encryptBytes(data: ByteArray, method: String, key: Any, useLibrary: Boolean = true): String {
        return when (method) {
            METHOD_AES -> AESCipher.encryptBytes(data, key, useLibrary)
            METHOD_DES -> DESCipher.encryptBytes(data, key, useLibrary)
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
    private val sBox = IntArray(256)
    private val invSBox = IntArray(256)
    private val rCon = IntArray(11)

    init {
        initializeTables()
    }

    // --- 1. MATEMATİKSEL ALTYAPI (Galois Field & S-Box) ---
    private fun galoisMult(a: Int, b: Int): Int {
        var p = 0
        var aa = a
        var bb = b
        repeat(8) {
            if ((bb and 1) != 0) p = p xor aa
            val hiBit = (aa and 0x80) != 0
            aa = (aa shl 1) and 0xFF
            if (hiBit) aa = aa xor 0x1B
            bb = bb shr 1
        }
        return p
    }

    private fun rotateLeft8(n: Int, shift: Int): Int =
        ((n shl shift) and 0xFF) or (n ushr (8 - shift))

    private fun initializeTables() {
        // S-Box Üretimi
        for (i in 0 until 256) {
            var inv = 0
            if (i != 0) {
                for (j in 1 until 256) {
                    if (galoisMult(i, j) == 1) {
                        inv = j
                        break
                    }
                }
            }
            val s = inv xor rotateLeft8(inv, 1) xor rotateLeft8(inv, 2) xor
                    rotateLeft8(inv, 3) xor rotateLeft8(inv, 4) xor 0x63
            sBox[i] = s and 0xFF
            invSBox[s and 0xFF] = i
        }

        // R-Con Üretimi (Dynamic Galois)
        rCon[1] = 1
        for (i in 2 until 11) {
            rCon[i] = galoisMult(rCon[i - 1], 2)
        }
    }

    // --- 2. ANAHTAR GENİŞLETME (KEY EXPANSION) ---
    private fun expandKey(key: ByteArray): List<Array<IntArray>> {
        val words = IntArray(44)
        for (i in 0 until 4) {
            words[i] = ((key[4 * i].toInt() and 0xFF) shl 24) or
                    ((key[4 * i + 1].toInt() and 0xFF) shl 16) or
                    ((key[4 * i + 2].toInt() and 0xFF) shl 8) or
                    (key[4 * i + 3].toInt() and 0xFF)
        }
        for (i in 4 until 44) {
            var temp = words[i - 1]
            if (i % 4 == 0) {
                temp = ((temp shl 8) or (temp ushr 24))
                temp = (sBox[(temp ushr 24) and 0xFF] shl 24) or
                        (sBox[(temp ushr 16) and 0xFF] shl 16) or
                        (sBox[(temp ushr 8) and 0xFF] shl 8) or
                        (sBox[temp and 0xFF])
                temp = temp xor (rCon[i / 4] shl 24)
            }
            words[i] = words[i - 4] xor temp
        }

        val roundKeys = mutableListOf<Array<IntArray>>()
        for (i in 0 until 44 step 4) {
            val matrix = Array(4) { r ->
                IntArray(4) { c ->
                    (words[i + c] ushr (24 - 8 * r)) and 0xFF
                }
            }
            roundKeys.add(matrix)
        }
        return roundKeys
    }

    // --- 3. ÇEKİRDEK BLOK OPERASYONLARI ---
    private fun addRoundKey(state: Array<IntArray>, roundKey: Array<IntArray>) {
        for (r in 0..3) for (c in 0..3) state[r][c] = state[r][c] xor roundKey[r][c]
    }

    private fun subBytes(state: Array<IntArray>, box: IntArray) {
        for (r in 0..3) for (c in 0..3) state[r][c] = box[state[r][c]]
    }

    private fun shiftRows(state: Array<IntArray>) {
        val t1 = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t1
        val t2a = state[2][0]; val t2b = state[2][1]; state[2][0] = state[2][2]; state[2][1] = state[2][3]; state[2][2] = t2a; state[2][3] = t2b
        val t3 = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t3
    }

    private fun invShiftRows(state: Array<IntArray>) {
        val t1 = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = t1
        val t2a = state[2][0]; val t2b = state[2][1]; state[2][0] = state[2][2]; state[2][1] = state[2][3]; state[2][2] = t2a; state[2][3] = t2b
        val t3 = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = t3
    }

    private fun mixColumns(state: Array<IntArray>, inv: Boolean) {
        for (c in 0..3) {
            val col = IntArray(4) { state[it][c] }
            if (!inv) {
                state[0][c] = galoisMult(0x02, col[0]) xor galoisMult(0x03, col[1]) xor col[2] xor col[3]
                state[1][c] = col[0] xor galoisMult(0x02, col[1]) xor galoisMult(0x03, col[2]) xor col[3]
                state[2][c] = col[0] xor col[1] xor galoisMult(0x02, col[2]) xor galoisMult(0x03, col[3])
                state[3][c] = galoisMult(0x03, col[0]) xor col[1] xor col[2] xor galoisMult(0x02, col[3])
            } else {
                state[0][c] = galoisMult(0x0e, col[0]) xor galoisMult(0x0b, col[1]) xor galoisMult(0x0d, col[2]) xor galoisMult(0x09, col[3])
                state[1][c] = galoisMult(0x09, col[0]) xor galoisMult(0x0e, col[1]) xor galoisMult(0x0b, col[2]) xor galoisMult(0x0d, col[3])
                state[2][c] = galoisMult(0x0d, col[0]) xor galoisMult(0x09, col[1]) xor galoisMult(0x0e, col[2]) xor galoisMult(0x0b, col[3])
                state[3][c] = galoisMult(0x0b, col[0]) xor galoisMult(0x0d, col[1]) xor galoisMult(0x09, col[2]) xor galoisMult(0x0e, col[3])
            }
        }
    }

    private fun encryptBlock(block: ByteArray, roundKeys: List<Array<IntArray>>): ByteArray {
        val state = Array(4) { r -> IntArray(4) { c -> block[r + 4 * c].toInt() and 0xFF } }
        addRoundKey(state, roundKeys[0])
        for (i in 1 until 10) {
            subBytes(state, sBox)
            shiftRows(state)
            mixColumns(state, false)
            addRoundKey(state, roundKeys[i])
        }
        subBytes(state, sBox)
        shiftRows(state)
        addRoundKey(state, roundKeys[10])
        return ByteArray(16) { i -> state[i % 4][i / 4].toByte() }
    }

    private fun decryptBlock(block: ByteArray, roundKeys: List<Array<IntArray>>): ByteArray {
        val state = Array(4) { r -> IntArray(4) { c -> block[r + 4 * c].toInt() and 0xFF } }
        addRoundKey(state, roundKeys[10])
        for (i in 9 downTo 1) {
            invShiftRows(state)
            subBytes(state, invSBox)
            addRoundKey(state, roundKeys[i])
            mixColumns(state, true)
        }
        invShiftRows(state)
        subBytes(state, invSBox)
        addRoundKey(state, roundKeys[0])
        return ByteArray(16) { i -> state[i % 4][i / 4].toByte() }
    }

    // --- 4. GENEL API ---
    private fun prepareKey(key: Any): ByteArray {
        val bytes = if (key is String) key.toByteArray() else key as ByteArray
        return MessageDigest.getInstance("MD5").digest(bytes)
    }

    fun encrypt(text: String, key: Any, lib: Boolean): String {
        val k = prepareKey(key)
        val textBytes = text.toByteArray(Charsets.UTF_8)

        if (!lib) {
            val roundKeys = expandKey(k)
            val iv = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            val padded = pkcs7Pad(textBytes)
            val ciphertext = mutableListOf<Byte>()
            var prevBlock = iv
            for (i in padded.indices step 16) {
                val block = padded.sliceArray(i until i + 16)
                val xored = ByteArray(16) { j -> (block[j].toInt() xor prevBlock[j].toInt()).toByte() }
                val encBlock = encryptBlock(xored, roundKeys)
                ciphertext.addAll(encBlock.toList())
                prevBlock = encBlock
            }
            return Base64.encodeToString(iv + ciphertext.toByteArray(), Base64.NO_WRAP)
        }

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"))
        val iv = cipher.iv
        val encrypted = cipher.doFinal(textBytes)
        return Base64.encodeToString(iv + encrypted, Base64.NO_WRAP)
    }

    fun encryptBytes(data: ByteArray, key: Any, lib: Boolean): String {
        val k = prepareKey(key)

        if (!lib) {
            val roundKeys = expandKey(k)
            val iv = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            val padded = pkcs7Pad(data)
            val ciphertext = mutableListOf<Byte>()
            var prevBlock = iv
            for (i in padded.indices step 16) {
                val block = padded.sliceArray(i until i + 16)
                val xored = ByteArray(16) { j -> (block[j].toInt() xor prevBlock[j].toInt()).toByte() }
                val encBlock = encryptBlock(xored, roundKeys)
                ciphertext.addAll(encBlock.toList())
                prevBlock = encBlock
            }
            return Base64.encodeToString(iv + ciphertext.toByteArray(), Base64.NO_WRAP)
        }

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"))
        val iv = cipher.iv
        val encrypted = cipher.doFinal(data)
        return Base64.encodeToString(iv + encrypted, Base64.NO_WRAP)
    }

    fun decrypt(data: String, key: Any, lib: Boolean): String {
        val k = prepareKey(key)
        val bytes = Base64.decode(data, Base64.NO_WRAP)

        if (!lib) {
            val roundKeys = expandKey(k)
            val iv = bytes.sliceArray(0 until 16)
            val encrypted = bytes.sliceArray(16 until bytes.size)
            val decrypted = mutableListOf<Byte>()
            var prevBlock = iv
            for (i in encrypted.indices step 16) {
                val block = encrypted.sliceArray(i until i + 16)
                val decBlock = decryptBlock(block, roundKeys)
                repeat(16) { j ->
                    decrypted.add((decBlock[j].toInt() xor prevBlock[j].toInt()).toByte())
                }
                prevBlock = block
            }
            return String(pkcs7Unpad(decrypted.toByteArray()), Charsets.UTF_8)
        }

        val iv = bytes.sliceArray(0 until 16)
        val content = bytes.sliceArray(16 until bytes.size)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), IvParameterSpec(iv))
        return String(cipher.doFinal(content), Charsets.UTF_8)
    }

    private fun pkcs7Pad(data: ByteArray): ByteArray {
        val padLen = 16 - (data.size % 16)
        return data + ByteArray(padLen) { padLen.toByte() }
    }

    private fun pkcs7Unpad(data: ByteArray): ByteArray {
        val padLen = data.last().toInt()
        return data.sliceArray(0 until data.size - padLen)
    }
}


object DESCipher {
    private val IP = intArrayOf(
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    )

    private val FP = intArrayOf(
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    )

    private fun bytesToLong(bytes: ByteArray): Long {
        var result: Long = 0
        for (i in 0..7) {
            result = (result shl 8) or (bytes[i].toLong() and 0xFF)
        }
        return result
    }

    private fun longToBytes(l: Long): ByteArray {
        val result = ByteArray(8)
        for (i in 7 downTo 0) {
            result[i] = ((l shr (8 * (7 - i))) and 0xFF).toByte()
        }
        return result
    }

    private fun permute(bits: String, table: IntArray): String {
        val sb = StringBuilder()
        for (i in table) sb.append(bits[i - 1])
        return sb.toString()
    }

    private fun generateSubkeys(key: ByteArray): List<Long> {
        val md = MessageDigest.getInstance("SHA-1")
        val hash = md.digest(key)
        return List(16) { i ->
            ((hash[i % hash.size].toLong() and 0xFF) shl 24) or 0x555555L
        }
    }

    private fun desTransform(block: ByteArray, subkeys: List<Long>): ByteArray {
        val blockLong = bytesToLong(block)
        var bits = String.format("%64s", java.lang.Long.toBinaryString(blockLong)).replace(' ', '0')

        bits = permute(bits, IP)

        var L = bits.substring(0, 32).toLong(2)
        var R = bits.substring(32).toLong(2)

        for (key in subkeys) {
            val prevL = L
            L = R
            val fResult = R xor key
            R = prevL xor fResult
        }

        val combined = String.format("%32s", java.lang.Long.toBinaryString(R)).replace(' ', '0') +
                String.format("%32s", java.lang.Long.toBinaryString(L)).replace(' ', '0')
        val finalBits = permute(combined, FP)

        val finalLong = java.lang.Long.parseUnsignedLong(finalBits, 2)
        return longToBytes(finalLong)
    }

    // --- 3. ANA API ---
    private fun prepareKey(key: Any): ByteArray {
        val bytes = if (key is String) key.toByteArray() else key as ByteArray
        val digest = MessageDigest.getInstance("MD5").digest(bytes)
        return digest.sliceArray(0 until 8)
    }

    fun encrypt(text: String, key: Any, lib: Boolean): String {
        val k = prepareKey(key)
        val textBytes = text.toByteArray(Charsets.UTF_8)

        if (!lib) {
            val subkeys = generateSubkeys(k)
            val iv = ByteArray(8).apply { SecureRandom().nextBytes(this) }
            val padded = pkcs7Pad(textBytes, 8)
            val ciphertext = mutableListOf<Byte>()
            var prevBlock = iv

            for (i in padded.indices step 8) {
                val block = padded.sliceArray(i until i + 8)
                val xored = ByteArray(8) { j -> (block[j].toInt() xor prevBlock[j].toInt()).toByte() }
                val encBlock = desTransform(xored, subkeys)
                ciphertext.addAll(encBlock.toList())
                prevBlock = encBlock
            }
            return Base64.encodeToString(iv + ciphertext.toByteArray(), Base64.NO_WRAP)
        }

        val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "DES"))
        return Base64.encodeToString(cipher.iv + cipher.doFinal(textBytes), Base64.NO_WRAP)
    }

    fun encryptBytes(data: ByteArray, key: Any, lib: Boolean): String {
        val k = prepareKey(key)

        if (!lib) {
            val subkeys = generateSubkeys(k)
            val iv = ByteArray(8).apply { SecureRandom().nextBytes(this) }
            val padded = pkcs7Pad(data, 8)
            val ciphertext = mutableListOf<Byte>()
            var prevBlock = iv

            for (i in padded.indices step 8) {
                val block = padded.sliceArray(i until i + 8)
                val xored = ByteArray(8) { j -> (block[j].toInt() xor prevBlock[j].toInt()).toByte() }
                val encBlock = desTransform(xored, subkeys)
                ciphertext.addAll(encBlock.toList())
                prevBlock = encBlock
            }
            return Base64.encodeToString(iv + ciphertext.toByteArray(), Base64.NO_WRAP)
        }

        val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "DES"))
        return Base64.encodeToString(cipher.iv + cipher.doFinal(data), Base64.NO_WRAP)
    }

    fun decrypt(data: String, key: Any, lib: Boolean): String {
        val k = prepareKey(key)
        val bytes = Base64.decode(data, Base64.NO_WRAP)

        if (!lib) {
            val subkeys = generateSubkeys(k).reversed()
            val iv = bytes.sliceArray(0 until 8)
            val encrypted = bytes.sliceArray(8 until bytes.size)
            val decrypted = mutableListOf<Byte>()
            var prevBlock = iv

            for (i in encrypted.indices step 8) {
                val block = encrypted.sliceArray(i until i + 8)
                val decBlock = desTransform(block, subkeys)
                repeat(8) { j ->
                    decrypted.add((decBlock[j].toInt() xor prevBlock[j].toInt()).toByte())
                }
                prevBlock = block
            }
            return String(pkcs7Unpad(decrypted.toByteArray()), Charsets.UTF_8)
        }

        val iv = bytes.sliceArray(0 until 8)
        val content = bytes.sliceArray(8 until bytes.size)
        val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "DES"), IvParameterSpec(iv))
        return String(cipher.doFinal(content), Charsets.UTF_8)
    }

    private fun pkcs7Pad(data: ByteArray, blockSize: Int): ByteArray {
        val padLen = blockSize - (data.size % blockSize)
        return data + ByteArray(padLen) { padLen.toByte() }
    }

    private fun pkcs7Unpad(data: ByteArray): ByteArray {
        val padLen = data.last().toInt()
        return data.sliceArray(0 until data.size - padLen)
    }
}