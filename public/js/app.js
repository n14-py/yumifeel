document.addEventListener('DOMContentLoaded', () => {
    // Inicializa la conexión de Socket.IO
    const socket = io();

    // --- Referencias a elementos del DOM ---
    // Buscamos los elementos del chat. Si no existen (ej. en la pág de settings), no se hace nada.
    const chatForm = document.getElementById('chat-form');
    const msgInput = document.getElementById('msg-input');
    const sendBtn = document.getElementById('send-btn');
    const chatMessages = document.getElementById('chat-messages');
    const appContent = document.getElementById('app-content'); // Contenedor con scroll

    // Función para hacer scroll hasta el fondo
    const scrollToBottom = () => {
        if (appContent) {
            appContent.scrollTop = appContent.scrollHeight;
        }
    };

    // Hacer scroll al fondo al cargar la página de chat
    scrollToBottom();

    // --- Lógica de Socket.IO ---
    
    // 1. Unirse a la sala de la pareja al conectarse
    // (Las variables currentUserID y currentCoupleID vienen de index.html)
    if (typeof currentCoupleID !== 'undefined' && currentCoupleID) {
        socket.on('connect', () => {
            console.log('Conectado al servidor. Uniéndose a la sala:', currentCoupleID);
            socket.emit('joinRoom', currentCoupleID);
        });
    }

    // 2. Enviar un mensaje
    if (chatForm) {
        chatForm.addEventListener('submit', (e) => {
            e.preventDefault(); // Evita que la página se recargue

            const msg = msgInput.value.trim();
            if (msg) {
                // Deshabilitar el input y botón mientras se envía
                msgInput.disabled = true;
                sendBtn.disabled = true;
                
                // Enviar el mensaje al servidor
                socket.emit('chatMessage', {
                    msg: msg,
                    coupleId: currentCoupleID,
                    senderId: currentUserID
                });
                
                // Limpiar el input
                msgInput.value = '';
            }
        });
    }

    // 3. Recibir un mensaje (del usuario o de la IA)
    socket.on('message', (msg) => {
        // Volver a habilitar el input y botón
        if (msgInput) msgInput.disabled = false;
        if (sendBtn) sendBtn.disabled = false;

        // Añadir el mensaje a la ventana de chat
        appendMessage(msg);
        
        // Enfocar el input de nuevo (si es un mensaje del usuario)
        if (msg.senderId === currentUserID && !msg.isFromAI) {
            if (msgInput) msgInput.focus();
        }
    });

    // 4. Manejar errores del servidor
    socket.on('error', (errorMessage) => {
        alert(errorMessage); // Muestra un alerta simple
        // Volver a habilitar el input y botón
        if (msgInput) msgInput.disabled = false;
        if (sendBtn) sendBtn.disabled = false;
    });

    /**
     * Función para añadir un nuevo mensaje al DOM
     * @param {object} msg - El objeto del mensaje (con text, isFromAI, senderId, createdAt)
     */
    function appendMessage(msg) {
        if (!chatMessages) return;

        const msgDiv = document.createElement('div');
        const isUserMessage = !msg.isFromAI;
        
        // Usamos 'user' para el usuario actual y 'ai' para la IA
        // (El server.js se encarga de que solo recibas tus mensajes y los de la IA)
        msgDiv.classList.add('message', isUserMessage ? 'user' : 'ai');

        // Formatear la hora
        const time = new Date(msg.createdAt || Date.now()).toLocaleTimeString('es-ES', {
            hour: '2-digit',
            minute: '2-digit'
        });
        
        msgDiv.innerHTML = `
            <div class="message-content">
                ${msg.text}
                <div class="message-time">${time}</div>
            </div>
        `;
        
        chatMessages.appendChild(msgDiv);
        scrollToBottom(); // Hacer scroll para ver el nuevo mensaje
    }
});