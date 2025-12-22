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
import com.keremsen.kriptoloji_app.cipher.ECCCipher
import java.util.UUID

class ChatViewModel : ViewModel() {

    private var socketManager: SocketManager? = null
    private val TAG = "ChatViewModel"

    private val _messages = MutableStateFlow<List<String>>(emptyList())
    val messages = _messages.asStateFlow()

    private val _isConnected = MutableStateFlow(false)
    val isConnected = _isConnected.asStateFlow()

    private val _connectionStatus = MutableStateFlow("Bağlantı yok")
    val connectionStatus = _connectionStatus.asStateFlow()

    // UI'dan seçilen şifreleme metodu
    private val _cipherMethod = MutableStateFlow("aes")
    val cipherMethod = _cipherMethod.asStateFlow()

    // UI'dan seçilen el sıkışma yöntemi
    private val _handshakeMethod = MutableStateFlow("rsa")
    val handshakeMethod = _handshakeMethod.asStateFlow()

    private val _useLibrary = MutableStateFlow(true)
    val useLibrary = _useLibrary.asStateFlow()

    // Kriptografik Durumlar
    private var serverPublicKey: String? = null
    private var serverEccPublicKey: String? = null
    private var symmetricKey: String? = null
    private var clientRsaPublicKey: String? = null
    private var clientRsaPrivateKey: String? = null
    private var clientEccPublicKey: String? = null
    private var clientEccPrivateKey: String? = null

    fun setCipherMethod(method: String) {
        _cipherMethod.value = method
        appendMessage("[sistem] 🔐 Şifreleme yöntemi: ${method.uppercase()}")
    }

    fun setHandshakeMethod(method: String) {
        _handshakeMethod.value = method
        appendMessage("[sistem] 🔑 El sıkışma tercihi: ${method.uppercase()}")
    }

    fun setUseLibrary(useLibrary: Boolean) {
        _useLibrary.value = useLibrary
    }

    fun startSocket(wsUrl: String) {
        if (socketManager != null) return

        _connectionStatus.value = "Bağlantı kuruluyor..."
        socketManager = SocketManager(
            url = wsUrl,
            onMessage = { handleServerMessage(it) },
            onOpen = {
                _isConnected.value = true
                _connectionStatus.value = "Bağlı ✅"
                appendMessage("[sistem] ✅ Sunucuya bağlandı!")

                // 1. ADIM: Sunucuya bağlantı tercihini bildir
                val setupPacket = JSONObject().apply {
                    put("type", "setup_connection")
                    put("preferred_method", _handshakeMethod.value)
                }
                socketManager?.send(setupPacket.toString())
            },
            onClose = {
                _isConnected.value = false
                _connectionStatus.value = "Bağlantı kapandı"
                resetCryptoState()
                socketManager = null
            }
        )
        socketManager?.connect()
    }

    private fun handleServerMessage(text: String) {
        try {
            val packet = JSONObject(text)
            val packetType = packet.optString("type", "message")

            when (packetType) {
                "rsa_public_key" -> {
                    serverPublicKey = packet.getString("public_key")
                    appendMessage("[sistem] 🔑 Sunucu RSA anahtarı alındı")

                    val (pub, priv) = RSACipher.generateKeyPair()
                    clientRsaPublicKey = pub
                    clientRsaPrivateKey = priv

                    socketManager?.send(JSONObject().apply {
                        put("type", "client_rsa_public_key")
                        put("public_key", pub)
                    }.toString())
                    performRsaKeyExchange()
                }

                "ecc_public_key" -> {
                    serverEccPublicKey = packet.getString("public_key")
                    appendMessage("[sistem] 🔑 Sunucu ECC anahtarı alındı (ECDH)")

                    val (myPub, myPriv) = ECCCipher.generateKeyPair()
                    clientEccPublicKey = myPub
                    clientEccPrivateKey = myPriv

                    // ECDH ile ortak anahtarı (Shared Secret) otomatik türet
                    symmetricKey = ECCCipher.deriveSharedKey(myPriv, serverEccPublicKey!!)

                    val eccResponse = JSONObject().apply {
                        put("type", "client_ecc_public_key")
                        put("public_key", myPub)
                        put("method", _cipherMethod.value)
                    }

                    socketManager?.send(eccResponse.toString())
                    Log.d(TAG, "✅ ECC El sıkışma paketi gönderildi. Metod: ${_cipherMethod.value}")
                }

                "key_exchange_ack" -> {
                    if (packet.optString("status") == "success") {
                        appendMessage("[sistem] ✅ Güvenli hat kuruldu.")
                    }
                }

                "message" -> {
                    val encrypted = packet.getString("message")
                    val method = packet.optString("method", _cipherMethod.value)
                    val useLib = packet.optBoolean("use_library", _useLibrary.value)

                    try {
                        val key = symmetricKey
                        if (key == null) {
                            appendMessage("[sistem] ⚠️ Hata: Anahtar henüz hazır değil!")
                        } else {
                            val decrypted = CipherFactory.decrypt(encrypted, method, key, useLib)
                            appendMessage("[sunucudan] $decrypted")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Deşifreleme hatası: ${e.message}")
                        appendMessage("[hata] Mesaj çözülemedi.")
                    }
                }

                "error" -> {
                    val errorMsg = packet.optString("message", "Bilinmeyen hata")
                    appendMessage("[hata] Sunucu hatası: $errorMsg")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Paket işleme hatası: ${e.message}")
        }
    }

    private fun performRsaKeyExchange() {
        try {
            val method = _cipherMethod.value

            val randomKey = UUID.randomUUID().toString().substring(0, 16)
            symmetricKey = randomKey

            val encryptedKey = RSACipher.encrypt(randomKey, serverPublicKey!!)

            socketManager?.send(JSONObject().apply {
                put("type", "key_exchange")
                put("encrypted_key", encryptedKey)
                put("method", method)
            }.toString())

            appendMessage("[sistem] 🔐 Oturum anahtarı otomatik oluşturuldu.")
        } catch (e: Exception) {
            appendMessage("[hata] RSA Değişim Hatası")
        }
    }

    fun sendMessage(plainText: String) {
        if (!_isConnected.value) {
            appendMessage("[sistem] ⚠️ Bağlı değilsiniz.")
            return
        }

        val activeKey = symmetricKey
        if (activeKey == null) {
            appendMessage("[sistem] ⚠️ Önce anahtar değişimi tamamlanmalı!")
            return
        }

        val method = _cipherMethod.value
        val useLib = _useLibrary.value

        try {
            val encrypted = CipherFactory.encrypt(plainText, method, activeKey, useLib)

            val packet = JSONObject().apply {
                put("type", "message")
                put("message", encrypted)
                put("method", method)
                put("use_library", useLib)
            }

            socketManager?.send(packet.toString())
            appendMessage("[ben] $plainText ✓")

        } catch (e: Exception) {
            Log.e(TAG, "Gönderim hatası: ${e.message}")
            appendMessage("[hata] Mesaj şifrelenemedi.")
        }
    }

    private fun resetCryptoState() {
        serverPublicKey = null
        serverEccPublicKey = null
        symmetricKey = null
        clientRsaPublicKey = null
        clientRsaPrivateKey = null
        clientEccPublicKey = null
        clientEccPrivateKey = null
    }

    private fun appendMessage(m: String) {
        viewModelScope.launch { _messages.value = _messages.value + m }
    }

    fun stopSocket() {
        socketManager?.close()
    }
}