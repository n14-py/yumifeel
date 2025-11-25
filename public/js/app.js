/* yumifeel/public/js/app.js - Versión: Draggable & Auto-Save */

const socket = io();

// Variables globales (definidas en el HTML)
const myUserID = (typeof currentUserID !== 'undefined') ? currentUserID : null;
// Si currentCoupleID no está definido, intenta usar currentUser.coupleId si está disponible en el scope global
const myCoupleID = (typeof currentCoupleID !== 'undefined') ? currentCoupleID : null;

// Elementos UI
const chatForm = document.getElementById('input-area');
const msgInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const chatContainer = document.getElementById('chat-container');
const missYouBtn = document.getElementById('miss-you-btn'); // El botón de corazón flotante

// Elementos Yumi Flotante
const yumiContainer = document.querySelector('.yumi-float-container');
const yumiBadge = document.getElementById('status-badge');

// Elementos Modal Estado
const partnerMoodEl = document.getElementById('partner-mood');
const partnerEnergyEl = document.getElementById('partner-energy');
const partnerHappyEl = document.getElementById('partner-happiness');

// ==========================================
//  1. LÓGICA DE CHAT & CONEXIÓN
// ==========================================

if (myCoupleID) {
    // Unirse a la sala
    socket.emit('join room', myCoupleID);
    console.log(`Unido a sala: ${myCoupleID}`);

    // Enviar Mensaje
    if (chatForm) {
        chatForm.addEventListener('submit', (e) => {
            e.preventDefault();
            sendMessage();
        });
    }

    function sendMessage() {
        const text = msgInput.value.trim();
        if (text) {
            // Emitir evento
            socket.emit('chat message', {
                text: text,
                userId: myUserID,
                coupleId: myCoupleID,
                timestamp: new Date()
            });
            // Limpiar
            msgInput.value = '';
            msgInput.focus();
        }
    }

    // Recibir Mensajes
    socket.on('chat message', (msg) => {
        // Solo mostramos mensaje si:
        // 1. Es mío (confirmación del server)
        // 2. Es de la IA (respuesta)
        // (Recordemos que el server ya filtra los de la pareja por privacidad)
        appendMessage(msg.text, msg.isFromAI ? 'bot' : 'user');
        scrollToBottom();
    });

    // ==========================================
    //  2. BOTÓN "TE EXTRAÑO"
    // ==========================================
    if (missYouBtn) {
        missYouBtn.addEventListener('click', () => {
            // Animación de pulsación
            missYouBtn.style.transform = "scale(0.8)";
            setTimeout(() => missYouBtn.style.transform = "scale(1)", 150);

            // Emitir evento
            socket.emit('miss you', {
                coupleId: myCoupleID,
                senderId: myUserID
            });
            
            showToast('💖 Le enviaste un latido');
        });
    }

    // Recibir "Te extraño" de la pareja
    socket.on('partner missed you', () => {
        showToast('🥰 ¡Tu pareja te extraña!');
        triggerHeartRain(); // Lluvia de corazones
        if (navigator.vibrate) navigator.vibrate([100, 50, 100]);
    });

    // ==========================================
    //  3. YUMI FLOTANTE & ESTADOS
    // ==========================================

    // Recibir actualización de estado de la pareja
    socket.on('partner status update', (status) => {
        // 1. Activar puntito rojo (Badge)
        if (yumiBadge) yumiBadge.classList.add('active');

        // 2. Actualizar textos del modal si existe
        if (partnerMoodEl) updateModalUI(status);
        
        showToast('🔔 Tu pareja actualizó su estado');
    });

    // Pedir estado al entrar
    socket.emit('get status', myCoupleID);
}

// ==========================================
//  4. LOGICA DE ARRASTRAR (DRAGGABLE)
// ==========================================
if (yumiContainer) {
    let isDragging = false;
    let startX, startY, initialLeft, initialTop;

    // Soporte Touch (Móvil)
    yumiContainer.addEventListener('touchstart', (e) => {
        isDragging = false; // Asumimos click primero
        const touch = e.touches[0];
        startX = touch.clientX;
        startY = touch.clientY;
        
        // Obtener posición actual (computada)
        const rect = yumiContainer.getBoundingClientRect();
        initialLeft = rect.left;
        initialTop = rect.top;
        
        // Timer para detectar si es un "hold" para arrastrar
        dragTimer = setTimeout(() => { isDragging = true; }, 200);
    }, {passive: false});

    yumiContainer.addEventListener('touchmove', (e) => {
        if (!isDragging) return;
        e.preventDefault(); // Evitar scroll de pantalla
        
        const touch = e.touches[0];
        const dx = touch.clientX - startX;
        const dy = touch.clientY - startY;

        // Mover el elemento
        yumiContainer.style.position = 'fixed';
        yumiContainer.style.left = `${initialLeft + dx}px`;
        yumiContainer.style.top = `${initialTop + dy}px`;
        yumiContainer.style.right = 'auto'; // Quitar right para que left mande
        yumiContainer.style.bottom = 'auto';
    }, {passive: false});

    yumiContainer.addEventListener('touchend', (e) => {
        clearTimeout(dragTimer);
        // Si no se movió mucho, dejar que el click (abrir modal) ocurra
    });
}


// ==========================================
//  5. AJUSTES: AUTO-GUARDADO (SLIDERS)
// ==========================================
const statusForm = document.getElementById('status-form');
if (statusForm) {
    // Sliders
    const inputs = ['mood', 'energy', 'happiness'];
    let timeout = null;
    const syncStatus = document.getElementById('sync-status');

    inputs.forEach(id => {
        const slider = document.getElementById(`${id}-slider`);
        const label = document.getElementById(`val-${id}`);
        
        if (slider) {
            // Al mover: Actualizar % visualmente
            slider.addEventListener('input', () => {
                label.innerText = `${slider.value}%`;
                label.style.fontWeight = '900';
                
                if(syncStatus) {
                    syncStatus.innerText = "Sincronizando...";
                    syncStatus.classList.add('visible');
                    syncStatus.style.color = "var(--secondary)";
                }

                // Debounce: Esperar a que deje de mover
                clearTimeout(timeout);
                timeout = setTimeout(sendStatusUpdate, 1000); // 1 seg de espera
            });
        }
    });

    // Switch de compartir
    const shareToggle = document.getElementById('share-status-toggle');
    if (shareToggle) {
        shareToggle.addEventListener('change', sendStatusUpdate);
    }

    function sendStatusUpdate() {
        const moodVal = document.getElementById('mood-slider').value;
        const energyVal = document.getElementById('energy-slider').value;
        const happinessVal = document.getElementById('happiness-slider').value;
        const shareVal = document.getElementById('share-status-toggle').checked;

        const data = {
            coupleId: myCoupleID,
            userId: myUserID,
            mood: moodVal,
            energy: energyVal,
            happiness: happinessVal,
            share: shareVal
        };

        socket.emit('status update', data);

        // Feedback visual
        if(syncStatus) {
            syncStatus.innerText = "✅ ¡Estado Actualizado!";
            syncStatus.style.color = "var(--primary)";
            setTimeout(() => {
                syncStatus.classList.remove('visible');
            }, 2000);
        }
    }
}

// ==========================================
//  FUNCIONES AUXILIARES
// ==========================================

function appendMessage(text, type) {
    if (!chatContainer) return;

    // Evitar duplicados simples (opcional)
    const lastMsg = chatContainer.lastElementChild;
    if (lastMsg && lastMsg.innerText.includes(text) && lastMsg.classList.contains(type)) {
        // return; // Descomentar si quieres evitar spam exacto
    }

    const div = document.createElement('div');
    div.classList.add('msg-bubble', type);
    
    // Hora
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    div.innerHTML = `
        ${text}
        <span class="msg-time">${time}</span>
    `;

    // Añadir al contenedor interno si existe (chat-wrapper) o directo
    const wrapper = document.querySelector('.chat-wrapper') || chatContainer;
    wrapper.appendChild(div);
}

function scrollToBottom() {
    if (chatContainer) {
        // Scroll suave al final
        setTimeout(() => {
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }, 100);
    }
}

function updateModalUI(status) {
    if (!status.share) {
        partnerMoodEl.innerText = "Privado 🔒";
        partnerEnergyEl.innerText = "Privado 🔒";
        partnerHappyEl.innerText = "Privado 🔒";
        return;
    }

    // Traducir % a texto (puedes personalizar esto)
    partnerMoodEl.innerText = getLabel(status.mood, ['Nublado ☁️', 'Algo mal', 'Bien', 'Radiante 🌞']);
    partnerEnergyEl.innerText = getLabel(status.energy, ['Agotad@ 🪫', 'Baja', 'Media', 'A tope ⚡']);
    partnerHappyEl.innerText = getLabel(status.happiness, ['Tranqui', 'Cariños@', 'Enamorad@ 😍', 'Explosiv@ 💖']);
}

function getLabel(val, arr) {
    const idx = Math.floor((val / 100) * (arr.length - 0.1)); 
    return arr[idx] || arr[arr.length - 1];
}

function showToast(msg) {
    // Eliminar anterior si existe
    const old = document.querySelector('.yumi-toast');
    if(old) old.remove();

    const toast = document.createElement('div');
    toast.className = 'yumi-toast';
    toast.innerText = msg;
    
    // Estilos inline para asegurar que funcione sin CSS extra
    Object.assign(toast.style, {
        position: 'fixed',
        top: '20px',
        left: '50%',
        transform: 'translateX(-50%)',
        background: 'rgba(50, 50, 50, 0.9)',
        color: 'white',
        padding: '12px 24px',
        borderRadius: '50px',
        fontSize: '0.9rem',
        zIndex: 9999,
        boxShadow: '0 5px 15px rgba(0,0,0,0.2)',
        opacity: '0',
        transition: 'opacity 0.3s'
    });

    document.body.appendChild(toast);
    
    // Animación
    requestAnimationFrame(() => toast.style.opacity = '1');
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function triggerHeartRain() {
    const symbols = ['💖', '💕', '🥰', '🐰'];
    for (let i = 0; i < 20; i++) {
        const heart = document.createElement('div');
        heart.innerText = symbols[Math.floor(Math.random() * symbols.length)];
        Object.assign(heart.style, {
            position: 'fixed',
            left: Math.random() * 100 + 'vw',
            top: '-50px',
            fontSize: (Math.random() * 20 + 20) + 'px',
            transition: `top ${Math.random() * 2 + 3}s ease-in, opacity 3s`,
            zIndex: 9999,
            pointerEvents: 'none'
        });
        document.body.appendChild(heart);

        setTimeout(() => {
            heart.style.top = '110vh';
            heart.style.opacity = '0';
        }, 100);

        setTimeout(() => heart.remove(), 5000);
    }
}