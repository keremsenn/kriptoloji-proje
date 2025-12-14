package com.keremsen.kriptoloji_app.view

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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
    val cipherKey by viewModel.cipherKey.collectAsState()
    val useLibrary by viewModel.useLibrary.collectAsState()
    val listState = rememberLazyListState()

    var expandedMethod by remember { mutableStateOf(false) }

    val cipherMethods = listOf("aes", "des", "rsa")

    // Son mesaja kaydır
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(12.dp)) {
        // Başlık ve Bağlantı Durumu
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (isConnected) Color(0xFFE8F5E9) else Color(0xFFFFEBEE)
            )
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        "🔐 Kriptoloji Projesi",
                        style = MaterialTheme.typography.titleMedium,
                        fontSize = 18.sp
                    )
                    Text(
                        connectionStatus,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (isConnected) Color(0xFF2E7D32) else Color(0xFFC62828),
                        fontSize = 12.sp
                    )
                }

                // Bağlantı göstergesi
                Surface(
                    shape = RoundedCornerShape(50),
                    color = if (isConnected) Color(0xFF4CAF50) else Color(0xFFF44336),
                    modifier = Modifier.size(12.dp)
                ) {}
            }
        }

        // Bağlan/Kapat Butonları
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = {
                    viewModel.startSocket("ws://192.168.0.4:5000/ws")
                },
                modifier = Modifier.weight(1f),
                enabled = !isConnected
            ) {
                Text("Bağlan")
            }

            Button(
                onClick = { viewModel.stopSocket() },
                modifier = Modifier.weight(1f),
                enabled = isConnected,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text("Kapat")
            }
        }

        // Şifreleme Yöntemi Seçimi
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFFF5F5F5)
            )
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text(
                    "🔐 Şifreleme Yöntemi",
                    style = MaterialTheme.typography.labelMedium,
                    fontSize = 12.sp,
                    color = Color.Gray
                )

                Spacer(modifier = Modifier.height(8.dp))

                // Yöntem Seçimi
                Box(modifier = Modifier.fillMaxWidth()) {
                    Button(
                        onClick = { expandedMethod = !expandedMethod },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isConnected
                    ) {
                        Text(cipherMethod.uppercase())
                        Icon(Icons.Default.KeyboardArrowDown, contentDescription = null)
                    }

                    DropdownMenu(
                        expanded = expandedMethod,
                        onDismissRequest = { expandedMethod = false },
                        modifier = Modifier.fillMaxWidth()
                    ) {
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

                Spacer(modifier = Modifier.height(8.dp))

                // Kütüphane Modu Seçimi
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "📚 Mod:",
                        style = MaterialTheme.typography.bodySmall,
                        fontSize = 12.sp
                    )
                    Switch(
                        checked = useLibrary,
                        onCheckedChange = { viewModel.setUseLibrary(it) },
                        enabled = !isConnected
                    )
                    Text(
                        if (useLibrary) "Kütüphaneli" else "Kütüphanesiz",
                        style = MaterialTheme.typography.bodySmall,
                        fontSize = 12.sp,
                        color = Color.Gray
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                // Anahtar Giriş (RSA için gizle)
                if (cipherMethod != "rsa") {
                    OutlinedTextField(
                        value = cipherKey,
                        onValueChange = { viewModel.setCipherKey(it) },
                        label = { Text("Şifreleme Anahtarı") },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isConnected,
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodySmall.copy(fontSize = 12.sp)
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        when (cipherMethod) {
                            "aes" -> "💡 AES-128: 16 byte anahtar (örn: default_aes_key_16)"
                            "des" -> "💡 DES: 8 byte anahtar (örn: default_des)"
                            else -> ""
                        },
                        style = MaterialTheme.typography.bodySmall,
                        fontSize = 10.sp,
                        color = Color.Gray
                    )
                } else {
                    Text(
                        "💡 RSA: Mesajlar server'ın public key'i ile şifrelenir",
                        style = MaterialTheme.typography.bodySmall,
                        fontSize = 10.sp,
                        color = Color(0xFFFF9800)
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "⚠️ RSA yavaştır, büyük mesajlar için AES/DES önerilir",
                        style = MaterialTheme.typography.bodySmall,
                        fontSize = 10.sp,
                        color = Color(0xFFF44336)
                    )
                }
            }
        }

        // Mesajlar
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Color(0xFFFAFAFA), RoundedCornerShape(8.dp))
                .padding(8.dp),
            state = listState,
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            items(messages) { m ->
                MessageItem(m)
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Mesaj Giriş Alanı
        OutlinedTextField(
            value = messageText,
            onValueChange = { messageText = it },
            placeholder = { Text("Mesaj yaz...") },
            modifier = Modifier.fillMaxWidth(),
            enabled = isConnected,
            singleLine = false,
            maxLines = 3
        )

        Spacer(modifier = Modifier.height(8.dp))

        // Gönder Butonu
        Button(
            onClick = {
                if (messageText.isNotBlank()) {
                    viewModel.sendMessage(messageText)
                    messageText = ""
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = isConnected && messageText.isNotBlank()
        ) {
            Text("Gönder")
        }
    }
}

@Composable
fun MessageItem(message: String) {
    val isSystemMessage = message.startsWith("[sistem]")
    val isErrorMessage = message.startsWith("[hata]")
    val isServerMessage = message.startsWith("[sunucudan]")
    val isSentMessage = message.startsWith("[ben]")

    val backgroundColor = when {
        isSystemMessage -> Color(0xFFE3F2FD)
        isErrorMessage -> Color(0xFFFFEBEE)
        isServerMessage -> Color(0xFFE8F5E9)
        isSentMessage -> Color(0xFFFFF9C4)
        else -> Color(0xFFFFFFFF)
    }

    val textColor = when {
        isSystemMessage -> Color(0xFF1976D2)
        isErrorMessage -> Color(0xFFC62828)
        isServerMessage -> Color(0xFF2E7D32)
        isSentMessage -> Color(0xFFF57F17)
        else -> Color.Black
    }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(4.dp),
        color = backgroundColor,
        shape = RoundedCornerShape(8.dp)
    ) {
        Text(
            message,
            modifier = Modifier.padding(vertical = 6.dp, horizontal = 8.dp),
            style = MaterialTheme.typography.bodySmall,
            fontSize = 11.sp,
            color = textColor
        )
    }
}
