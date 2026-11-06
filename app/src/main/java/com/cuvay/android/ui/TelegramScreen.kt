package com.cuvay.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import org.drinkless.tdlib.TdApi

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TelegramScreen() {
    val context = LocalContext.current
    LaunchedEffect(Unit) { Tg.start(context) }

    val authState = Tg.auth

    Column(modifier = Modifier.fillMaxSize().background(Color(0xFF1E1E1E))) {
        when (authState) {
            is TgAuth.Idle, is TgAuth.Starting -> LoadingView("Iniciando Telegram...")
            is TgAuth.NeedPhone -> PhoneInputView()
            is TgAuth.NeedCode -> CodeInputView()
            is TgAuth.NeedPassword -> PasswordInputView()
            is TgAuth.Ready -> TelegramMainView()
            is TgAuth.Failed -> ErrorView(authState.why)
        }
    }
}

@Composable
fun LoadingView(text: String) {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator(color = Color.White)
            Spacer(modifier = Modifier.height(16.dp))
            Text(text, color = Color.White)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PhoneInputView() {
    var phone by remember { mutableStateOf("") }
    Column(modifier = Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.Center) {
        Text("Inicia sesión en Telegram", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(16.dp))
        OutlinedTextField(
            value = phone,
            onValueChange = { phone = it },
            label = { Text("Número de teléfono (+código)", color = Color.LightGray) },
            modifier = Modifier.fillMaxWidth()
        )
        if (Tg.hint.isNotEmpty()) {
            Text(Tg.hint, color = Color.Red, modifier = Modifier.padding(top = 8.dp))
        }
        Spacer(modifier = Modifier.height(16.dp))
        Button(
            onClick = { Tg.sendPhone(phone) },
            modifier = Modifier.fillMaxWidth(),
            enabled = !Tg.busy
        ) {
            Text("Siguiente")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CodeInputView() {
    var code by remember { mutableStateOf("") }
    Column(modifier = Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.Center) {
        Text("Introduce el código", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Text("Te hemos enviado un código por Telegram.", color = Color.LightGray)
        Spacer(modifier = Modifier.height(16.dp))
        OutlinedTextField(
            value = code,
            onValueChange = { code = it },
            label = { Text("Código", color = Color.LightGray) },
            modifier = Modifier.fillMaxWidth()
        )
        if (Tg.hint.isNotEmpty()) {
            Text(Tg.hint, color = Color.Red, modifier = Modifier.padding(top = 8.dp))
        }
        Spacer(modifier = Modifier.height(16.dp))
        Button(
            onClick = { Tg.sendCode(code) },
            modifier = Modifier.fillMaxWidth(),
            enabled = !Tg.busy
        ) {
            Text("Verificar")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordInputView() {
    var password by remember { mutableStateOf("") }
    Column(modifier = Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.Center) {
        Text("Verificación en dos pasos", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Text("Pista: ${Tg.pwHint}", color = Color.LightGray)
        Spacer(modifier = Modifier.height(16.dp))
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Contraseña", color = Color.LightGray) },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth()
        )
        if (Tg.hint.isNotEmpty()) {
            Text(Tg.hint, color = Color.Red, modifier = Modifier.padding(top = 8.dp))
        }
        Spacer(modifier = Modifier.height(16.dp))
        Button(
            onClick = { Tg.sendPassword(password) },
            modifier = Modifier.fillMaxWidth(),
            enabled = !Tg.busy
        ) {
            Text("Iniciar sesión")
        }
    }
}

@Composable
fun ErrorView(error: String) {
    val context = LocalContext.current
    Column(modifier = Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.Center) {
        Text("Error", color = Color.Red, fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(16.dp))
        Text(error, color = Color.White)
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = { Tg.start(context) }) {
            Text("Reintentar")
        }
    }
}

@Composable
fun TelegramMainView() {
    val currentChatId = Tg.currentChatId
    var showInfo by remember { mutableStateOf(false) }

    if (currentChatId == null) {
        ChatListView()
    } else {
        if (showInfo) {
            ChatInfoView(chatId = currentChatId, onBack = { showInfo = false })
        } else {
            ChatView(chatId = currentChatId, onInfoClick = { showInfo = true })
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatListView() {
    val coroutineScope = rememberCoroutineScope()
    LaunchedEffect(Unit) { Tg.loadChats() }

    val chats = Tg.chatsList
    var searchQuery by remember { mutableStateOf("") }
    var searchResult by remember { mutableStateOf<TdApi.Chat?>(null) }

    Column(modifier = Modifier.fillMaxSize()) {
        Text("Chats y Canales", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(16.dp))

        OutlinedTextField(
            value = searchQuery,
            onValueChange = { q ->
                searchQuery = q
                if (q.length > 3) {
                    coroutineScope.launch { searchResult = Tg.searchPublicChat(q) }
                } else {
                    searchResult = null
                }
            },
            placeholder = { Text("Buscar chat o canal (@usuario)...", color = Color.Gray) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search", tint = Color.Gray) },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)
        )

        if (searchResult != null) {
            Text("Resultado de búsqueda:", color = Color.Cyan, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
            ChatListItem(chat = searchResult!!) {
                coroutineScope.launch { Tg.openChat(searchResult!!.id) }
            }
            Divider(color = Color.DarkGray)
        }

        if (chats.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize().weight(1f), contentAlignment = Alignment.Center) {
                Text("Cargando chats...", color = Color.Gray)
            }
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize().weight(1f)) {
                items(chats) { chat ->
                    ChatListItem(chat = chat, onClick = {
                        coroutineScope.launch { Tg.openChat(chat.id) }
                    })
                }
            }
        }
    }
}

@Composable
fun ChatListItem(chat: TdApi.Chat, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(modifier = Modifier.size(48.dp).background(Color.Gray, shape = androidx.compose.foundation.shape.CircleShape))

        Spacer(modifier = Modifier.width(16.dp))

        Column {
            Text(chat.title, color = Color.White, fontWeight = FontWeight.Bold, maxLines = 1)

            val lastContent = chat.lastMessage?.content
            val preview = when (lastContent) {
                is TdApi.MessageText -> lastContent.text.text
                is TdApi.MessagePhoto -> "[Foto]"
                is TdApi.MessageVideo -> "[Video]"
                is TdApi.MessageDocument -> "[Documento]"
                else -> "..."
            }

            Text(
                text = preview,
                color = Color.LightGray,
                maxLines = 1,
                fontSize = 14.sp
            )
        }
    }
}


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatView(chatId: Long, onInfoClick: () -> Unit) {
    val coroutineScope = rememberCoroutineScope()
    val messages by Tg.messagesFlow.collectAsState()
    var inputText by remember { mutableStateOf("") }
    val chat = Tg.chatsList.find { it.id == chatId }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().background(Color(0xFF2A2A2A)).padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color.Cyan, modifier = Modifier.clickable { coroutineScope.launch { Tg.closeChat() } })
            Spacer(modifier = Modifier.width(16.dp))
            Text(chat?.title ?: "Chat", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp, modifier = Modifier.weight(1f))
            Icon(Icons.Default.Info, contentDescription = "Info", tint = Color.Cyan, modifier = Modifier.clickable(onClick = onInfoClick))
        }

        LazyColumn(modifier = Modifier.weight(1f).fillMaxWidth(), reverseLayout = true) {
            items(messages) { message ->
                MessageItem(message, chat)
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth().background(Color(0xFF2A2A2A)).padding(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = inputText,
                onValueChange = { inputText = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Mensaje...", color = Color.Gray) }
            )
            Spacer(modifier = Modifier.width(8.dp))
            Button(onClick = {
                if (inputText.isNotBlank()) {
                    coroutineScope.launch { Tg.sendMessage(inputText); inputText = "" }
                }
            }) {
                Text("Enviar")
            }
        }
    }
}

@Composable
fun ChatInfoView(chatId: Long, onBack: () -> Unit) {
    val chat = Tg.chatsList.find { it.id == chatId }
    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().background(Color(0xFF2A2A2A)).padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color.Cyan, modifier = Modifier.clickable(onClick = onBack))
            Spacer(modifier = Modifier.width(16.dp))
            Text("Información", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        }

        Column(modifier = Modifier.padding(16.dp)) {
            Box(modifier = Modifier.size(100.dp).background(Color.Gray, shape = androidx.compose.foundation.shape.CircleShape).align(Alignment.CenterHorizontally))
            Spacer(modifier = Modifier.height(16.dp))
            Text(chat?.title ?: "Desconocido", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold, modifier = Modifier.align(Alignment.CenterHorizontally))
            Spacer(modifier = Modifier.height(32.dp))

            Text("ID del chat:", color = Color.LightGray)
            Text(chat?.id?.toString() ?: "", color = Color.White, fontSize = 16.sp)
            Spacer(modifier = Modifier.height(16.dp))

            Text("Tipo de chat:", color = Color.LightGray)
            Text(chat?.type?.javaClass?.simpleName?.replace("ChatType", "") ?: "", color = Color.White, fontSize = 16.sp)
        }
    }
}

@Composable
fun MessageItem(message: TdApi.Message, chat: TdApi.Chat?) {
    val isOutgoing = message.isOutgoing
    val alignment = if (isOutgoing) Alignment.CenterEnd else Alignment.CenterStart
    val bgColor = if (isOutgoing) Color(0xFF2B5278) else Color(0xFF2A2A2A)
    val coroutineScope = rememberCoroutineScope()
    var fwdState by remember { mutableStateOf<FwdState?>(null) }

    Box(modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp), contentAlignment = alignment) {
        Column(modifier = Modifier.background(bgColor, shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp)).padding(12.dp)) {
            val content = message.content
            when (content) {
                is TdApi.MessageText -> Text(content.text.text, color = Color.White)
                is TdApi.MessagePhoto -> {
                    val photoSize = content.photo.sizes.lastOrNull()
                    val fileId = photoSize?.photo?.id
                    if (fileId != null) {
                        val file = Tg.downloadedFiles.find { it.id == fileId } ?: photoSize.photo
                        if (file.local.isDownloadingCompleted) {
                            var bitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
                            LaunchedEffect(file.local.path) {
                                bitmap = withContext(Dispatchers.IO) { BitmapFactory.decodeFile(file.local.path) }
                            }
                            if (bitmap != null) {
                                Image(bitmap = bitmap!!.asImageBitmap(), contentDescription = "Foto", modifier = Modifier.size(200.dp))
                            } else {
                                MediaCard("Cargando foto...", Icons.Default.Info)
                            }
                        } else {
                            val coroutineScope = rememberCoroutineScope()
                            LaunchedEffect(fileId) { coroutineScope.launch { Tg.downloadFile(fileId) } }
                            MediaCard("Descargando...", Icons.Default.Info)
                        }
                    } else {
                        MediaCard("Foto", Icons.Default.Info)
                    }
                }
                is TdApi.MessageVideo -> {
                    val fileId = content.video.video.id
                    val file = Tg.downloadedFiles.find { it.id == fileId } ?: content.video.video
                    if (file.local.isDownloadingCompleted) {
                        MediaCard("Video guardado", Icons.Default.Info)
                    } else {
                        val coroutineScope = rememberCoroutineScope()
                        LaunchedEffect(fileId) { coroutineScope.launch { Tg.downloadFile(fileId) } }
                        MediaCard("Descargando video...", Icons.Default.Info)
                    }
                }
                is TdApi.MessageDocument -> {
                    val fileId = content.document.document.id
                    val file = Tg.downloadedFiles.find { it.id == fileId } ?: content.document.document
                    if (file.local.isDownloadingCompleted) {
                         MediaCard("Doc: ${content.document.fileName}", Icons.Default.Info)
                    } else {
                         val coroutineScope = rememberCoroutineScope()
                         LaunchedEffect(fileId) { coroutineScope.launch { Tg.downloadFile(fileId) } }
                         MediaCard("Descargando ${content.document.fileName}...", Icons.Default.Info)
                    }
                }
                else -> Text("[Mensaje no soportado]", color = Color.Gray, fontStyle = androidx.compose.ui.text.font.FontStyle.Italic)
            }

            if (chat != null && chat.type !is TdApi.ChatTypePrivate) {
                Spacer(modifier = Modifier.height(8.dp))
                Button(onClick = {
                    val channelName = chat.title // We use title as a fallback if it's not a public username
                    // To get real username, we'd need Supergroup info, but title works for search if it's public
                    coroutineScope.launch { Tg.forward(channelName, message.id, "Cuv_ai") { fwdState = it } }
                }) {
                    Text("Enviar a @Cuv_ai")
                }
                if (fwdState != null) {
                    Text(fwdState!!.text, color = Color.Yellow, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
                }
            }
        }
    }
}

@Composable
fun MediaCard(type: String, icon: androidx.compose.ui.graphics.vector.ImageVector) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = type, tint = Color.LightGray, modifier = Modifier.size(32.dp))
        Spacer(modifier = Modifier.width(8.dp))
        Text(type, color = Color.White, fontWeight = FontWeight.Bold)
    }
}
