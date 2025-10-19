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

class ChatViewModel : ViewModel() {

    private var socketManager: SocketManager? = null

    private val _messages = MutableStateFlow<List<String>>(emptyList())
    val messages = _messages.asStateFlow()

    private val _isConnected = MutableStateFlow(false)
    val isConnected = _isConnected.asStateFlow()

    private val _connectionStatus = MutableStateFlow("Bağlantı yok")
    val connectionStatus = _connectionStatus.asStateFlow()

    // Şifreleme ayarları
    private val _cipherMethod = MutableStateFlow("caesar")
    val cipherMethod = _cipherMethod.asStateFlow()

    private val _cipherKey = MutableStateFlow("3")
    val cipherKey = _cipherKey.asStateFlow()

    private val TAG = "ChatViewModel"

    fun setCipherMethod(method: String) {
        _cipherMethod.value = method
        Log.d(TAG, "Şifreleme yöntemi değiştirildi: $method")

        // Yönteme göre varsayılan anahtarı ayarla
        when (method) {
            "caesar" -> _cipherKey.value = "3"
            "vigenere" -> _cipherKey.value = "SECRET"
            "routed" -> _cipherKey.value = "4"
        }

        appendMessage("[sistem] 🔐 Şifreleme yöntemi: $method")
    }

    fun setCipherKey(key: String) {
        _cipherKey.value = key
        Log.d(TAG, "Şifreleme anahtarı değiştirildi: $key")
    }

    fun startSocket(wsUrl: String = "ws://172.25.190.84:5001/ws") {
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
                try {
                    val packet = JSONObject(text)
                    val encrypted = packet.optString("message", text)
                    val method = packet.optString("method", "caesar")
                    val keyStr = packet.optString("key", null)

                    Log.d(TAG, "Paket - Method: $method, Encrypted: $encrypted")

                    // Anahtarı ayarla
                    val key: Any = when (method) {
                        "caesar" -> keyStr?.toIntOrNull() ?: 3
                        "vigenere" -> keyStr ?: "SECRET"
                        "routed" -> keyStr?.toIntOrNull() ?: 4
                        else -> 3
                    }

                    // Deşifre et
                    val decrypted = CipherFactory.decrypt(encrypted, method, key)
                    Log.d(TAG, "Mesaj çözüldü: $decrypted")
                    appendMessage("[sunucudan] $decrypted")
                } catch (e: Exception) {
                    Log.e(TAG, "Paket işleme hatası: ${e.message}")
                    try {
                        // Fallback: raw string deşifre
                        val method = _cipherMethod.value
                        val keyStr = _cipherKey.value
                        val key: Any = when (method) {
                            "caesar" -> keyStr.toIntOrNull() ?: 3
                            "vigenere" -> keyStr
                            "routed" -> keyStr.toIntOrNull() ?: 4
                            else -> 3
                        }
                        val decrypted = CipherFactory.decrypt(text, method, key)
                        appendMessage("[sunucudan] $decrypted")
                    } catch (e2: Exception) {
                        Log.e(TAG, "Fallback deşifreleme başarısız: ${e2.message}")
                        appendMessage("[hata] Deşifreleme hatası: ${e2.message}")
                    }
                }
            },
            onOpen = {
                Log.d(TAG, "WebSocket bağlantısı açıldı")
                _isConnected.value = true
                _connectionStatus.value = "Bağlı ✅"
                appendMessage("[sistem] ✅ Sunucuya bağlandı!")
                appendMessage("[sistem] 🔐 Aktif Yöntem: ${_cipherMethod.value}")
                appendMessage("[sistem] Şu anda mesaj gönderebilirsiniz")
            },
            onClose = {
                Log.d(TAG, "WebSocket bağlantısı kapandı")
                _isConnected.value = false
                _connectionStatus.value = "Bağlantı kapandı"
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
        val keyStr = _cipherKey.value

        try {
            // Anahtarı belirle
            val key: Any = when (method) {
                "caesar" -> keyStr.toIntOrNull() ?: 3
                "vigenere" -> keyStr
                "routed" -> keyStr.toIntOrNull() ?: 4
                else -> 3
            }

            // Şifrele
            val encrypted = CipherFactory.encrypt(plainText, method, key)
            Log.d(TAG, "Mesaj şifrelendi [$method]: $encrypted")

            // Paket oluştur
            val packet = JSONObject()
            packet.put("message", encrypted)
            packet.put("method", method)
            packet.put("key", keyStr)

            socketManager?.send(packet.toString())
            Log.d(TAG, "Paket gönderildi: ${packet}")

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