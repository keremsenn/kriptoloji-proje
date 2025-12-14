package com.keremsen.kriptoloji_app.viewmodel

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import com.keremsen.kriptoloji_app.view.SocketManager
import com.keremsen.kriptoloji_app.cipher.CipherFactory
import com.keremsen.kriptoloji_app.cipher.RSACipher
import java.security.MessageDigest

class ChatViewModel : ViewModel() {

    private var socketManager: SocketManager? = null

    private val _messages = MutableStateFlow<List<String>>(emptyList())
    val messages = _messages.asStateFlow()

    private val _isConnected = MutableStateFlow(false)
    val isConnected = _isConnected.asStateFlow()

    private val _connectionStatus = MutableStateFlow("Bağlantı yok")
    val connectionStatus = _connectionStatus.asStateFlow()

    private val _cipherMethod = MutableStateFlow("aes")
    val cipherMethod = _cipherMethod.asStateFlow()

    private val _cipherKey = MutableStateFlow("default_key_16")
    val cipherKey = _cipherKey.asStateFlow()

    private val _useLibrary = MutableStateFlow(true)
    val useLibrary = _useLibrary.asStateFlow()

    private var serverPublicKey: String? = null
    private var symmetricKey: String? = null
    private var clientPublicKey: String? = null
    private var clientPrivateKey: String? = null

    private val TAG = "ChatViewModel"

    fun setCipherMethod(method: String) {
        _cipherMethod.value = method
        Log.d(TAG, "Şifreleme yöntemi değiştirildi: $method")
        when (method) {
            "aes" -> _cipherKey.value = "default_aes_key_16"
            "des" -> _cipherKey.value = "default_des"
            "rsa" -> _cipherKey.value = ""
        }

        appendMessage("[sistem] 🔐 Şifreleme yöntemi: ${method.uppercase()}")
    }

    fun setCipherKey(key: String) {
        _cipherKey.value = key
        Log.d(TAG, "Şifreleme anahtarı değiştirildi: $key")
    }

    fun setUseLibrary(useLibrary: Boolean) {
        _useLibrary.value = useLibrary
        appendMessage("[sistem] 📚 Mod: ${if (useLibrary) "Kütüphaneli" else "Kütüphanesiz (Manuel)"}")
    }

    fun startSocket(wsUrl: String = "ws://192.168.0.5:5000/ws") {
        if (socketManager != null) {
            Log.w(TAG, "Socket zaten bağlı")
            appendMessage("[sistem] ⚠️ WebSocket zaten aktif")
            return
        }

        Log.d(TAG, "WebSocket bağlanıyor: $wsUrl")
        appendMessage("[sistem] 🔄 Bağlantı kuruluyor: $wsUrl")
        _connectionStatus.value = "Bağlantı kuruluyor..."

        socketManager = SocketManager(
            url = wsUrl,
            onMessage = { text ->
                Log.d(TAG, "Sunucudan veri alındı: $text")
                handleServerMessage(text)
            },
            onOpen = {
                Log.d(TAG, "WebSocket bağlantısı açıldı")
                _isConnected.value = true
                _connectionStatus.value = "Bağlı ✅"
                appendMessage("[sistem] ✅ Sunucuya bağlandı!")
                appendMessage("[sistem] 🔐 Aktif Yöntem: ${_cipherMethod.value.uppercase()}")
                appendMessage("[sistem] 📚 Mod: ${if (_useLibrary.value) "Kütüphaneli" else "Kütüphanesiz"}")
                try {
                    val (publicKey, privateKey) = RSACipher.generateKeyPair()
                    clientPublicKey = publicKey
                    clientPrivateKey = privateKey
                    Log.d(TAG, "Client RSA key çifti oluşturuldu")

                    val clientKeyPacket = JSONObject().apply {
                        put("type", "client_rsa_public_key")
                        put("public_key", publicKey)
                    }
                    socketManager?.send(clientKeyPacket.toString())
                    Log.d(TAG, "Client RSA public key gönderildi")
                } catch (e: Exception) {
                    Log.e(TAG, "Client RSA key oluşturma hatası: ${e.message}", e)
                    appendMessage("[sistem] ⚠️ Client RSA key oluşturulamadı: ${e.message}")
                }
                
                appendMessage("[sistem] Şu anda mesaj gönderebilirsiniz")
            },
            onClose = {
                Log.d(TAG, "WebSocket bağlantısı kapandı")
                _isConnected.value = false
                _connectionStatus.value = "Bağlantı kapandı"
                serverPublicKey = null
                symmetricKey = null
                clientPublicKey = null
                clientPrivateKey = null
                socketManager = null
            }
        )

        try {
            socketManager?.connect()
            Log.d(TAG, "connect() çağrıldı")
        } catch (e: Exception) {
            Log.e(TAG, "Bağlantı hatası: ${e.message}", e)
            _connectionStatus.value = "Bağlantı hatası: ${e.message}"
            appendMessage("[sistem] ❌ Hata: ${e.message}")
            socketManager = null
            _isConnected.value = false
        }
    }

    private fun handleServerMessage(text: String) {
        try {
            val packet = JSONObject(text)
            val packetType = packet.optString("type", "message")

            when (packetType) {
                "rsa_public_key" -> {
                    serverPublicKey = packet.getString("public_key")
                    Log.d(TAG, "RSA public key alındı")
                    appendMessage("[sistem] 🔑 RSA public key alındı")
                    performKeyExchange()
                }
                "key_exchange_ack" -> {
                    val status = packet.optString("status", "error")
                    if (status == "success") {
                        appendMessage("[sistem] ✅ Anahtar değişimi başarılı")
                    } else {
                        appendMessage("[sistem] ❌ Anahtar değişimi başarısız: ${packet.optString("message", "")}")
                    }
                }
                "message" -> {
                    val encrypted = packet.optString("message", text)
                    val method = packet.optString("method", _cipherMethod.value)
                    val useLibrary = packet.optBoolean("use_library", _useLibrary.value)

                    val decrypted = if (method == "rsa") {
                        if (encrypted.startsWith("[") && encrypted.endsWith("]")) {
                            if (useLibrary) {
                                if (clientPrivateKey == null) {
                                    appendMessage("[sistem] ⚠️ Client private key bulunamadı!")
                                    "[RSA şifreli mesaj - deşifrelenemedi]"
                                } else {
                                    try {
                                        Log.d(TAG, "RSA ile mesaj deşifreleniyor... (Kütüphaneli)")
                                        RSACipher.decrypt(encrypted, clientPrivateKey!!, useLibrary)
                                    } catch (e: Exception) {
                                        Log.e(TAG, "RSA deşifreleme hatası: ${e.message}", e)
                                        appendMessage("[sistem] ⚠️ RSA deşifreleme hatası: ${e.message}")
                                        "[RSA deşifreleme hatası]"
                                    }
                                }
                            } else {
                                if (clientPublicKey == null) {
                                    appendMessage("[sistem] ⚠️ Client public key bulunamadı!")
                                    "[RSA şifreli mesaj - deşifrelenemedi]"
                                } else {
                                    try {
                                        Log.d(TAG, "RSA ile mesaj deşifreleniyor... (Manuel)")
                                        RSACipher.decrypt(encrypted, clientPublicKey!!, useLibrary)
                                    } catch (e: Exception) {
                                        Log.e(TAG, "RSA deşifreleme hatası: ${e.message}", e)
                                        appendMessage("[sistem] ⚠️ RSA deşifreleme hatası: ${e.message}")
                                        "[RSA deşifreleme hatası]"
                                    }
                                }
                            }
                        } else {
                            encrypted
                        }
                    } else {
                        val key = symmetricKey ?: _cipherKey.value
                        CipherFactory.decrypt(encrypted, method, key, useLibrary)
                    }
                    Log.d(TAG, "Mesaj çözüldü: $decrypted")
                    appendMessage("[sunucudan] $decrypted")
                }
                "error" -> {
                    val errorMsg = packet.optString("message", "Bilinmeyen hata")
                    appendMessage("[hata] $errorMsg")
                }
                else -> {
                    val encrypted = packet.optString("message", text)
                    val method = packet.optString("method", _cipherMethod.value)
                    val key = symmetricKey ?: _cipherKey.value
                    val decrypted = CipherFactory.decrypt(encrypted, method, key, _useLibrary.value)
                    appendMessage("[sunucudan] $decrypted")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Paket işleme hatası: ${e.message}", e)
            appendMessage("[hata] Paket işleme hatası: ${e.message}")
        }
    }

    private fun performKeyExchange() {
        if (serverPublicKey == null) {
            Log.w(TAG, "RSA public key henüz alınmadı")
            return
        }

        try {
            val method = _cipherMethod.value
            val key = when (method) {
                "aes" -> {
                    val md = MessageDigest.getInstance("MD5")
                    md.digest(_cipherKey.value.toByteArray()).joinToString("") { "%02x".format(it) }
                }
                "des" -> {
                    val md = MessageDigest.getInstance("MD5")
                    md.digest(_cipherKey.value.toByteArray()).sliceArray(0 until 8).joinToString("") { "%02x".format(it) }
                }
                else -> _cipherKey.value
            }
            symmetricKey = key
            val encryptedKey = RSACipher.encrypt(key, serverPublicKey!!)
            val keyExchangePacket = JSONObject().apply {
                put("type", "key_exchange")
                put("encrypted_key", encryptedKey)
                put("method", method)
            }

            socketManager?.send(keyExchangePacket.toString())
            Log.d(TAG, "Anahtar değişim paketi gönderildi")
            appendMessage("[sistem] 🔄 Anahtar değişimi başlatıldı")
        } catch (e: Exception) {
            Log.e(TAG, "Anahtar değişimi hatası: ${e.message}", e)
            appendMessage("[hata] Anahtar değişimi hatası: ${e.message}")
        }
    }

    fun stopSocket() {
        Log.d(TAG, "WebSocket kapatılıyor...")
        if (socketManager == null) {
            appendMessage("[sistem] ⚠️ Socket zaten kapalı")
            return
        }

        try {
            socketManager?.close()
            appendMessage("[sistem] 🔌 Bağlantı kapatıldı")
        } catch (e: Exception) {
            Log.e(TAG, "Kapatırken hata: ${e.message}")
            appendMessage("[sistem] ⚠️ Kapatırken hata: ${e.message}")
        }
    }

    fun sendMessage(plainText: String) {
        if (!_isConnected.value) {
            Log.w(TAG, "Bağlantı yok, mesaj gönderilemedi")
            appendMessage("[sistem] ⚠️ Sunucuya bağlı değilsiniz!")
            return
        }

        Log.d(TAG, "Mesaj gönderiliyor: $plainText")
        val method = _cipherMethod.value
        val useLibrary = _useLibrary.value

        try {
            val encrypted = if (method == "rsa") {
                if (serverPublicKey == null) {
                    appendMessage("[sistem] ⚠️ RSA public key henüz alınmadı!")
                    return
                }
                Log.d(TAG, "RSA ile mesaj şifreleniyor... (Manuel: ${!useLibrary})")
                RSACipher.encrypt(plainText, serverPublicKey!!, useLibrary)
            } else {
                val key = symmetricKey ?: _cipherKey.value
                CipherFactory.encrypt(plainText, method, key, useLibrary)
            }
            Log.d(TAG, "Mesaj şifrelendi [$method]: ${encrypted.take(100)}...")

            val packet = JSONObject().apply {
                put("type", "message")
                put("message", encrypted)
                put("method", method)
                put("use_library", useLibrary)
            }

            socketManager?.send(packet.toString())
            Log.d(TAG, "Paket gönderildi")

            appendMessage("[ben] $plainText ✓")
        } catch (e: Exception) {
            Log.e(TAG, "Gönderim hatası: ${e.message}", e)
            appendMessage("[sistem] ❌ Gönderim hatası: ${e.message}")
        }
    }

    private fun appendMessage(m: String) {
        viewModelScope.launch {
            val cur = _messages.value.toMutableList()
            cur.add(m)
            _messages.value = cur
            Log.v(TAG, "Mesaj eklendi: $m")
        }
    }
}
