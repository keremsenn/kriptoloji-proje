package com.keremsen.kriptoloji_app.view

import android.util.Log
import okhttp3.*
import okio.ByteString
import java.util.concurrent.TimeUnit

class SocketManager(
    private val url: String,
    private val onMessage: (String) -> Unit,
    private val onOpen: () -> Unit = {},
    private val onClose: () -> Unit = {}
) {
    private val TAG = "SocketManager"

    private val client = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .connectTimeout(10, TimeUnit.SECONDS)
        .build()

    private var webSocket: WebSocket? = null

    fun connect() {
        Log.d(TAG, "=== BAĞLANTIYA BAŞLANIYYOR ===")
        Log.d(TAG, "URL: $url")

        val request = Request.Builder()
            .url(url)
            .build()

        try {
            webSocket = client.newWebSocket(request, socketListener)
            Log.d(TAG, "WebSocket nesnesi oluşturuldu")
        } catch (e: Exception) {
            Log.e(TAG, "Bağlantı hatası: ${e.message}", e)
            onClose()
        }
    }

    fun close() {
        Log.d(TAG, "=== BAĞLANTIYA KAPATILIYOR ===")
        try {
            webSocket?.close(1000, "Client closing")
            Log.d(TAG, "WebSocket kapalı komutası gönderildi")
            client.dispatcher.executorService.shutdown()
            Log.d(TAG, "HTTP client kapatıldı")
        } catch (e: Exception) {
            Log.e(TAG, "Kapatmada hata: ${e.message}", e)
        }
    }

    fun send(text: String) {
        if (webSocket == null) {
            Log.e(TAG, "❌ WebSocket null, mesaj gönderilemedi!")
            return
        }

        Log.d(TAG, "📤 Gönderiliyor: $text")
        try {
            val success = webSocket?.send(text) ?: false
            if (success) {
                Log.d(TAG, "✅ Mesaj gönderildi")
            } else {
                Log.e(TAG, "❌ Gönderme başarısız")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Gönderme hatası: ${e.message}", e)
        }
    }

    private val socketListener = object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            super.onOpen(webSocket, response)
            Log.d(TAG, "✅ ============ WebSocket AÇILDI ============")
            Log.d(TAG, "Status: ${response.code}")
            Log.d(TAG, "Message: ${response.message}")
            Log.d(TAG, "Headers: ${response.headers}")
            onOpen()
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            super.onMessage(webSocket, text)
            Log.d(TAG, "📨 Metin mesajı alındı: $text")
            onMessage(text)
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            super.onMessage(webSocket, bytes)
            val utf8Text = bytes.utf8()
            Log.d(TAG, "📨 Binary mesaj alındı: $utf8Text")
            onMessage(utf8Text)
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            super.onClosing(webSocket, code, reason)
            Log.d(TAG, "⚠️  KAPATILIYOR - Code: $code, Reason: $reason")
            webSocket.close(1000, "Client responding to close")
            onClose()
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            super.onClosed(webSocket, code, reason)
            Log.d(TAG, "❌ ============ WebSocket KAPANDI ============")
            Log.d(TAG, "Close Code: $code")
            Log.d(TAG, "Close Reason: $reason")
            onClose()
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            super.onFailure(webSocket, t, response)
            Log.e(TAG, "❌ ============ BAĞLANTIYA HATASI ============", t)
            Log.e(TAG, "Hata Mesajı: ${t.localizedMessage}")
            Log.e(TAG, "Hata Sınıfı: ${t.javaClass.simpleName}")
            if (response != null) {
                Log.e(TAG, "HTTP Status: ${response.code}")
                Log.e(TAG, "HTTP Message: ${response.message}")
            }
            onClose()
        }
    }
}