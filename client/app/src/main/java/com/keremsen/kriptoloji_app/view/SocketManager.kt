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
        .connectTimeout(15, TimeUnit.SECONDS)
        .build()

    private var webSocket: WebSocket? = null

    fun connect() {
        Log.d(TAG, "📡 Bağlantı kuruluyor: $url")
        val request = Request.Builder().url(url).build()

        try {
            webSocket?.close(1000, "New connection starting")
            webSocket = client.newWebSocket(request, socketListener)
        } catch (e: Exception) {
            Log.e(TAG, "❌ Socket başlatma hatası: ${e.message}")
            onClose()
        }
    }

    fun close() {
        try {
            webSocket?.close(1000, "User logout")
            webSocket = null
            Log.d(TAG, "🔌 Bağlantı kullanıcı tarafından kapatıldı")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Kapatma hatası: ${e.message}")
        }
    }

    fun send(text: String) {
        val currentSocket = webSocket
        if (currentSocket == null) {
            Log.e(TAG, "⚠️ Gönderilemedi: WebSocket bağlı değil!")
            return
        }

        try {
            val success = currentSocket.send(text)
            if (!success) Log.e(TAG, "⚠️ Mesaj kuyruğa alınamadı")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Gönderim hatası: ${e.message}")
        }
    }

    private val socketListener = object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            Log.d(TAG, "✅ WebSocket Bağlantısı Başarılı")
            onOpen()
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            onMessage(text)
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            onMessage(bytes.utf8())
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            Log.d(TAG, "⚠️ Sunucu bağlantıyı kapatıyor: $reason")
            webSocket.close(1000, null)
            onClose()
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            Log.d(TAG, "🚫 WebSocket Kapandı")
            onClose()
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            Log.e(TAG, "❌ Bağlantı Hatası: ${t.message}")
            onClose()
        }
    }
}