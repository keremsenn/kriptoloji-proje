package com.keremsen.kriptoloji_app.view

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.keremsen.kriptoloji_app.viewmodel.ChatViewModel

@Composable
fun ChatScreen(viewModel: ChatViewModel = viewModel()) {
    var messageText by remember { mutableStateOf("") }
    val messages by viewModel.messages.collectAsState()
    val isConnected by viewModel.isConnected.collectAsState()
    val connectionStatus by viewModel.connectionStatus.collectAsState()
    val cipherMethod by viewModel.cipherMethod.collectAsState()
    val handshakeMethod by viewModel.handshakeMethod.collectAsState()
    val useLibrary by viewModel.useLibrary.collectAsState()
    val listState = rememberLazyListState()

    var expandedMethod by remember { mutableStateOf(false) }
    val cipherMethods = listOf("aes", "des")

    // Yeni mesaj geldiğinde otomatik aşağı kaydır
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(12.dp)) {

        // 1. ÜST PANEL: Bağlantı Durumu
        Card(
            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (isConnected) Color(0xFFE8F5E9) else Color(0xFFFFEBEE)
            )
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("🔐 Kriptoloji Güvenli Sohbet", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(connectionStatus, style = MaterialTheme.typography.bodySmall,
                        color = if (isConnected) Color(0xFF2E7D32) else Color(0xFFC62828))
                }
                Surface(
                    shape = RoundedCornerShape(50),
                    color = if (isConnected) Color(0xFF4CAF50) else Color(0xFFF44336),
                    modifier = Modifier.size(12.dp)
                ) {}
            }
        }

        // 2. ANAHTAR DEĞİŞİM (HANDSHAKE) SEÇİMİ
        Card(
            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFFE3F2FD))
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("🔑 El Sıkışma (Key Exchange) Yöntemi",
                    style = MaterialTheme.typography.labelMedium, color = Color.DarkGray)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(
                        selected = handshakeMethod == "rsa",
                        onClick = { viewModel.setHandshakeMethod("rsa") },
                        enabled = !isConnected
                    )
                    Text("RSA", style = MaterialTheme.typography.bodySmall)

                    Spacer(modifier = Modifier.width(16.dp))

                    RadioButton(
                        selected = handshakeMethod == "ecc",
                        onClick = { viewModel.setHandshakeMethod("ecc") },
                        enabled = !isConnected
                    )
                    Text("ECC (ECDH)", style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        // 3. BAĞLANTI BUTONLARI
        Row(
            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { viewModel.startSocket("ws://10.118.72.84:5000/ws") },
                modifier = Modifier.weight(1f),
                enabled = !isConnected
            ) { Text("Bağlan") }

            Button(
                onClick = { viewModel.stopSocket() },
                modifier = Modifier.weight(1f),
                enabled = isConnected,
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) { Text("Bağlantıyı Kes") }
        }

        // 4. ŞİFRELEME AYARLARI
        Card(
            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFFF5F5F5))
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("⚙️ Güvenlik Ayarları", style = MaterialTheme.typography.labelMedium)

                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Yöntem Seçimi
                    Box(modifier = Modifier.weight(1f)) {
                        OutlinedButton(
                            onClick = { expandedMethod = !expandedMethod },
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !isConnected
                        ) {
                            Text(cipherMethod.uppercase())
                            Icon(Icons.Default.KeyboardArrowDown, contentDescription = null)
                        }
                        DropdownMenu(expanded = expandedMethod, onDismissRequest = { expandedMethod = false }) {
                            cipherMethods.forEach { method ->
                                DropdownMenuItem(
                                    text = { Text(method.uppercase()) },
                                    onClick = {
                                        viewModel.setCipherMethod(method)
                                        expandedMethod = false
                                    }
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.width(8.dp))

                    // Kütüphane Modu Switch
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Switch(
                            checked = useLibrary,
                            onCheckedChange = { viewModel.setUseLibrary(it) },
                            enabled = !isConnected
                        )
                        Text(if (useLibrary) "Kütüphane" else "Manuel", fontSize = 10.sp)
                    }
                }

                Divider(modifier = Modifier.padding(vertical = 4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (isConnected) Icons.Default.Lock else Icons.Default.Refresh,
                        contentDescription = null,
                        tint = if (isConnected) Color(0xFF2E7D32) else Color.Gray,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (isConnected)
                            "Oturum anahtarı $handshakeMethod ile otomatik türetildi."
                        else "Bağlantı kurulduğunda anahtar otomatik oluşturulacak.",
                        style = MaterialTheme.typography.bodySmall,
                        fontSize = 11.sp,
                        color = if (isConnected) Color(0xFF2E7D32) else Color.DarkGray
                    )
                }
            }
        }

        // 5. MESAJ LİSTESİ
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Color(0xFFFAFAFA), RoundedCornerShape(8.dp))
                .padding(8.dp),
            state = listState,
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            items(messages) { m -> MessageItem(m) }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // 6. MESAJ GİRİŞİ VE GÖNDERME
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = messageText,
                onValueChange = { messageText = it },
                placeholder = { Text("Mesaj yaz...") },
                modifier = Modifier.weight(1f),
                enabled = isConnected,
                maxLines = 2,
                shape = RoundedCornerShape(12.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            IconButton(
                onClick = {
                    if (messageText.isNotBlank()) {
                        viewModel.sendMessage(messageText)
                        messageText = ""
                    }
                },
                enabled = isConnected && messageText.isNotBlank(),
                modifier = Modifier
                    .size(56.dp)
                    .background(
                        if (isConnected && messageText.isNotBlank()) MaterialTheme.colorScheme.primary
                        else Color.LightGray,
                        RoundedCornerShape(12.dp)
                    )
            ) {
                Icon(
                    imageVector = Icons.Default.Send,
                    contentDescription = "Gönder",
                    tint = Color.White
                )
            }
        }
    }
}

@Composable
fun MessageItem(message: String) {
    val isSystem = message.startsWith("[sistem]")
    val isError = message.startsWith("[hata]")
    val isServer = message.startsWith("[sunucudan]")
    val isSent = message.startsWith("[ben]")

    val backgroundColor = when {
        isSystem -> Color(0xFFE3F2FD)
        isError -> Color(0xFFFFEBEE)
        isServer -> Color(0xFFE8F5E9)
        isSent -> Color(0xFFFFF9C4)
        else -> Color.White
    }

    val alignment = if (isSent) Alignment.CenterEnd else Alignment.CenterStart

    Box(modifier = Modifier.fillMaxWidth(), contentAlignment = alignment) {
        Surface(
            modifier = Modifier
                .padding(vertical = 2.dp)
                .widthIn(max = 300.dp),
            color = backgroundColor,
            shape = RoundedCornerShape(
                topStart = 12.dp,
                topEnd = 12.dp,
                bottomStart = if (isSent) 12.dp else 0.dp,
                bottomEnd = if (isSent) 0.dp else 12.dp
            ),
            shadowElevation = 1.dp
        ) {
            Text(
                message,
                modifier = Modifier.padding(12.dp),
                style = MaterialTheme.typography.bodySmall,
                fontSize = 13.sp,
                color = if (isError) Color.Red else Color.Black
            )
        }
    }
}