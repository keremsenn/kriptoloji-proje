package com.keremsen.kriptoloji_app.cipher

object CipherFactory {
    const val METHOD_CAESAR = "caesar"
    const val METHOD_VIGENERE = "vigenere"
    const val METHOD_ROUTED = "routed"

    fun encrypt(text: String, method: String, key: Any): String {
        return when (method) {
            METHOD_CAESAR -> CaesarCipher.encrypt(text, (key as? Int) ?: 3)
            METHOD_VIGENERE -> VigenereCipher.encrypt(text, (key as? String) ?: "SECRET")
            METHOD_ROUTED -> RouteCipher.encrypt(text, (key as? Int) ?: 4)
            else -> throw IllegalArgumentException("Bilinmeyen şifreleme yöntemi: $method")
        }
    }

    fun decrypt(text: String, method: String, key: Any): String {
        return when (method) {
            METHOD_CAESAR -> CaesarCipher.decrypt(text, (key as? Int) ?: 3)
            METHOD_VIGENERE -> VigenereCipher.decrypt(text, (key as? String) ?: "SECRET")
            METHOD_ROUTED -> RouteCipher.decrypt(text, (key as? Int) ?: 4)
            else -> throw IllegalArgumentException("Bilinmeyen şifreleme yöntemi: $method")
        }
    }
}

object CaesarCipher {
    fun encrypt(text: String, shift: Int): String {
        val result = StringBuilder()
        for (ch in text) {
            when {
                ch in 'a'..'z' -> {
                    val base = 'a'.code
                    result.append(((ch.code - base + shift).mod(26) + base).toChar())
                }
                ch in 'A'..'Z' -> {
                    val base = 'A'.code
                    result.append(((ch.code - base + shift).mod(26) + base).toChar())
                }
                else -> result.append(ch)
            }
        }
        return result.toString()
    }

    fun decrypt(text: String, shift: Int): String {
        return encrypt(text, -shift)
    }
}

object VigenereCipher {
    private fun processKey(key: String): String {
        return key.filter { it.isLetter() }.uppercase()
    }

    fun encrypt(text: String, key: String): String {
        val processedKey = processKey(key)
        if (processedKey.isEmpty()) {
            throw IllegalArgumentException("Vigenere anahtarı en az bir harf içermeli")
        }

        val result = StringBuilder()
        var keyIdx = 0

        for (ch in text) {
            when {
                ch.isLetter() -> {
                    val isUpper = ch.isUpperCase()
                    val upperCh = ch.uppercaseChar()

                    val shift = processedKey[keyIdx % processedKey.length].code - 'A'.code
                    val base = 'A'.code
                    val encrypted = ((upperCh.code - base + shift) % 26 + base).toChar()

                    result.append(if (isUpper) encrypted else encrypted.lowercaseChar())
                    keyIdx++
                }
                else -> result.append(ch)
            }
        }

        return result.toString()
    }

    fun decrypt(text: String, key: String): String {
        val processedKey = processKey(key)
        if (processedKey.isEmpty()) {
            throw IllegalArgumentException("Vigenere anahtarı en az bir harf içermeli")
        }

        val result = StringBuilder()
        var keyIdx = 0

        for (ch in text) {
            when {
                ch.isLetter() -> {
                    val isUpper = ch.isUpperCase()
                    val upperCh = ch.uppercaseChar()

                    val shift = processedKey[keyIdx % processedKey.length].code - 'A'.code
                    val base = 'A'.code
                    val decrypted = ((upperCh.code - base - shift).mod(26) + base).toChar()

                    result.append(if (isUpper) decrypted else decrypted.lowercaseChar())
                    keyIdx++
                }
                else -> result.append(ch)
            }
        }

        return result.toString()
    }
}

object RouteCipher {
    private fun padText(text: String, cols: Int): String {
        val paddingNeeded = (cols - text.length % cols) % cols
        return text + "X".repeat(paddingNeeded)
    }

    fun encrypt(text: String, key: Int = 4): String {
        val cols = if (key > 0) key else 4
        val paddedText = padText(text, cols)
        val rows = paddedText.length / cols

        // Grid oluştur
        val grid = Array(rows) { i ->
            paddedText.substring(i * cols, (i + 1) * cols)
        }

        // Sütunları oku
        val result = StringBuilder()
        for (col in 0 until cols) {
            for (row in 0 until rows) {
                result.append(grid[row][col])
            }
        }

        return result.toString()
    }

    fun decrypt(text: String, key: Int = 4): String {
        val cols = if (key > 0) key else 4
        val rows = text.length / cols

        // Grid oluştur
        val grid = Array(rows) { CharArray(cols) }
        var idx = 0

        for (col in 0 until cols) {
            for (row in 0 until rows) {
                grid[row][col] = text[idx]
                idx++
            }
        }

        // Satırları oku
        val result = StringBuilder()
        for (row in 0 until rows) {
            for (col in 0 until cols) {
                result.append(grid[row][col])
            }
        }

        return result.toString().trimEnd('X')
    }
}