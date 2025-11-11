// =============================================
//               YumiFeel - server.js
//                 Parte 1 de 2
// =============================================

// --- IMPORTACIONES Y CONFIGURACIÓN INICIAL ---
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const MongoStore = require('connect-mongo');
const axios = require('axios'); // Para la IA de DeepSeek
const crypto = require('crypto'); // Para generar códigos de invitación

// Importaciones para Socket.IO
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app); // Creamos un servidor HTTP para Socket.IO
const io = new Server(server); // Socket.IO se adjunta al servidor HTTP

const PORT = process.env.PORT || 3000;

// --- CONFIGURACIÓN DE VISTAS (EJS) ---
// Usamos EJS como motor de plantillas, igual que tentacionpy
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', require('ejs').renderFile);

// --- MIDDLEWARES DE EXPRESS ---
app.use(express.json()); // Para parsear JSON
app.use(express.urlencoded({ extended: true })); // Para parsear formularios
app.use(express.static(path.join(__dirname, 'public'))); // Carpeta para CSS, JS, imágenes

// --- CONEXIÓN A MONGODB ---
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Conectado a MongoDB (YumiFeel)'))
  .catch(err => console.error('❌ Error de conexión a MongoDB:', err));

// --- CONFIGURACIÓN DE SESIÓN ---
// Usamos MongoStore para guardar las sesiones en la base de datos
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI,
  collectionName: 'sessions'
});

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        // --- CAMBIO IMPORTANTE AQUÍ ---
        // Desactivamos 'secure' temporalmente para debugging en Render.
        // Render usa un proxy, y esto a veces causa que la cookie no se guarde
        // si se fuerza 'secure: true' sin una configuración de proxy correcta.
        secure: false, // process.env.NODE_ENV === 'production',
        // --- FIN DEL CAMBIO ---
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 7 // 7 días
    }
}));

// --- CONFIGURACIÓN DE PASSPORT (AUTENTICACIÓN) ---
app.use(passport.initialize());
app.use(passport.session());

// --- MODELOS DE BASE DE DATOS (SCHEMAS) ---

// Esquema para la Pareja
const coupleSchema = new mongoose.Schema({
    userIds: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    // Aquí puedes guardar el estado emocional general, resúmenes de IA, etc.
    emotionalState: {
        type: String,
        default: 'Neutral'
    },
    emotionalSummary: String, // Resumen semanal de la IA
}, { timestamps: true });

const Couple = mongoose.model('Couple', coupleSchema);

// Esquema para el Usuario
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    
    coupleId: { // El ID de la "pareja" a la que pertenece
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Couple',
        default: null
    },
    partnerId: { // El ID del otro usuario vinculado
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    invitationCode: { // Código único para vincularse
        type: String,
        unique: true,
        sparse: true
    }
}, { timestamps: true });

// Middleware para generar un código de invitación único antes de guardar
userSchema.pre('save', function(next) {
    if (this.isNew && !this.invitationCode) {
        this.invitationCode = crypto.randomBytes(4).toString('hex').toUpperCase();
    }
    next();
});

const User = mongoose.model('User', userSchema);

// Esquema para los Mensajes (del chat con la IA)
const messageSchema = new mongoose.Schema({
    senderId: { // El ID del usuario que envía el mensaje
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    coupleId: { // El ID de la pareja, para agrupar mensajes
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Couple',
        required: true
    },
    text: { type: String, required: true },
    isFromAI: { type: Boolean, default: false } // Para diferenciar mensajes de IA y de usuario
}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

// --- CONFIGURACIÓN DE ESTRATEGIA LOCAL DE PASSPORT ---
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return done(null, false, { message: 'Email no registrado.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return done(null, false, { message: 'Contraseña incorrecta.' });
        }
        
        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

// Serializar y Deserializar usuario (para la sesión)
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// --- MIDDLEWARES GLOBALES ---

// Middleware para pasar datos a todas las vistas (EJS)
app.use((req, res, next) => {
    res.locals.currentUser = req.user; // Pasa el usuario logueado a las vistas
    res.locals.baseUrl = process.env.BASE_URL; // Pasa la URL base
    res.locals.path = req.path;
    res.locals.error = req.session.error; // Mensajes de error
    res.locals.success = req.session.success; // Mensajes de éxito
    delete req.session.error;
    delete req.session.success;
    next();
});

// Middleware para proteger rutas
const requireAuth = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next(); // Si está logueado, continúa
    }
    res.redirect('/login'); // Si no, al login
};

// --- RUTAS DE AUTENTICACIÓN (Login, Register, Logout) ---

// GET /login - Muestra el formulario de login
app.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/'); // Si ya está logueado, va al chat
    }
    res.render('login.html'); // Renderiza views/login.html
});

// POST /login - Procesa el formulario de login
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',         // A dónde ir si el login es exitoso
    failureRedirect: '/login',  // A dónde ir si falla
    failureFlash: false // Cambia a true si configuras connect-flash
}));

// GET /register - Muestra el formulario de registro
app.get('/register', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    res.render('register.html'); // Renderiza views/register.html
});

// POST /register - Procesa el formulario de registro
app.post('/register', async (req, res, next) => {
    try {
        const { name, email, password } = req.body;
        
        if (!name || !email || !password) {
            req.session.error = "Todos los campos son obligatorios.";
            return res.redirect('/register');
        }

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            req.session.error = "Ese email ya está en uso.";
            return res.redirect('/register');
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({
            name,
            email: email.toLowerCase(),
            password: hashedPassword
        });

        await newUser.save();

        // Loguear al usuario automáticamente después de registrarse
        req.login(newUser, (err) => {
            if (err) { return next(err); }
            req.session.success = "¡Cuenta creada con éxito! Bienvenido a YumiFeel.";
            return res.redirect('/');
        });

    } catch (err) {
        req.session.error = "Error al crear la cuenta.";
        res.redirect('/register');
    }
});

// GET /logout - Cierra la sesión
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        req.session.destroy(() => {
            res.redirect('/login');
        });
    });
});




// =============================================
//               YumiFeel - server.js
//                 Parte 2 de 2
// =============================================

// --- RUTAS DE LA APLICACIÓN PRINCIPAL ---

// GET / - Ruta principal (El Chat)
app.get('/', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        // 1. Si el usuario no está vinculado, mostrar la vista de "Vincular"
        if (!user.coupleId || !user.partnerId) {
            return res.render('index.html', { 
                view: 'link-partner', // Le decimos a EJS que renderice la vista de vincular
                invitationCode: user.invitationCode,
                partner: null,
                messages: []
            });
        }

        // 2. Si está vinculado, buscar los datos de la pareja y el historial de chat
        const partner = await User.findById(user.partnerId).select('name email');
        
        // Buscamos todos los mensajes que pertenezcan a esta pareja
        // y que sean del usuario actual O de la IA (para que no vea los de su pareja)
        const messages = await Message.find({
            coupleId: user.coupleId,
            $or: [
                { senderId: user._id },
                { isFromAI: true }
            ]
        }).sort({ createdAt: 'asc' });

        // 3. Renderizar la vista de chat
        res.render('index.html', {
            view: 'chat', // Le decimos a EJS que renderice el chat
            partner: partner,
            messages: messages,
            invitationCode: user.invitationCode // Sigue siendo útil para la vista de "settings"
        });

    } catch (err) {
        console.error(err);
        req.session.error = "Error al cargar la aplicación.";
        res.redirect('/login');
    }
});

// GET /settings - Página de Ajustes
app.get('/settings', requireAuth, (req, res) => {
    // Pasamos el código de invitación del usuario a la página de ajustes
    res.render('settings.html', {
        invitationCode: req.user.invitationCode
    });
});

// POST /link-partner - Procesa la vinculación con un código
app.post('/link-partner', requireAuth, async (req, res) => {
    const { partnerCode } = req.body;
    const currentUser = await User.findById(req.user.id);

    try {
        if (!partnerCode) {
            req.session.error = "Debes ingresar un código.";
            return res.redirect('/');
        }
        
        if (partnerCode.toUpperCase() === currentUser.invitationCode) {
            req.session.error = "No puedes vincularte contigo mismo.";
            return res.redirect('/');
        }

        const partner = await User.findOne({ invitationCode: partnerCode.toUpperCase() });

        if (!partner) {
            req.session.error = "Código de pareja no encontrado.";
            return res.redirect('/');
        }

        if (currentUser.coupleId || partner.coupleId) {
            req.session.error = "Tú o tu pareja ya están vinculados a otra persona.";
            return res.redirect('/');
        }

        // Crear la nueva entidad de Pareja
        const newCouple = new Couple({
            userIds: [currentUser._id, partner._id]
        });
        await newCouple.save();

        // Actualizar a ambos usuarios
        currentUser.coupleId = newCouple._id;
        currentUser.partnerId = partner._id;
        await currentUser.save();

        partner.coupleId = newCouple._id;
        partner.partnerId = currentUser._id;
        await partner.save();

        req.session.success = `¡Vinculación exitosa con ${partner.name}!`;
        res.redirect('/');

    } catch (err) {
        console.error("Error al vincular:", err);
        req.session.error = "Error interno al intentar vincular.";
        res.redirect('/');
    }
});

// --- LÓGICA DE LA IA (DEEPSEEK) ---
// (Esta parte no se toca, como pediste)
/**
 * Llama a la API de DeepSeek para obtener una respuesta.
 * @param {Array} history - Un array de objetos { role: 'user'/'assistant', content: '...' }
 * @returns {String} - El texto de la respuesta de la IA.
 */
// ...
// ...
async function callDeepSeek(history, currentUserName, partnerName) { // <-- AÑADIR NOMBRES
    try {
        // El prompt del sistema define la personalidad de la IA
        const systemPrompt = {
            role: "system",
            // INYECTAMOS LOS NOMBRES AQUÍ
            content: `Eres Yumi, una mediadora emocional. Tu tono es empático y humano.
IMPORTANTE: Estás hablando AHORA MISMO con ${currentUserName}. El nombre de su pareja es ${partnerName}. No confundas sus nombres ni sus géneros. Ayuda a ${currentUserName} a entender la situación con ${partnerName}.`
        };

        const response = await axios.post(
// ...
            'https://api.deepseek.com/chat/completions',
            {
                model: 'deepseek-chat', // O el modelo que prefieras
                messages: [systemPrompt, ...history],
                temperature: 0.7, // Un valor balanceado para creatividad y coherencia
            },
            {
                headers: {
                    'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        if (response.data && response.data.choices[0].message) {
            return response.data.choices[0].message.content;
        } else {
            return "Parece que tuve un problema al procesar mi respuesta. ¿Podrías intentarlo de nuevo?";
        }

    } catch (error) {
        console.error("Error llamando a la API de DeepSeek:", error.response ? error.response.data : error.message);
        return "Lo siento, estoy teniendo dificultades para conectarme en este momento. 😔";
    }
}

// --- LÓGICA DE CHAT EN TIEMPO REAL (Socket.IO) ---
// (Esta parte tampoco se toca)
io.on('connection', (socket) => {
    console.log('🔌 Un usuario se ha conectado:', socket.id);

    // 1. Unir al usuario a una "sala" basada en su ID de pareja
    socket.on('joinRoom', (coupleId) => {
        if (coupleId) {
            socket.join(coupleId);
            console.log(`Usuario ${socket.id} se unió a la sala ${coupleId}`);
        }
    });

    // 2. Escuchar un nuevo mensaje del chat
    socket.on('chatMessage', async (data) => {
        const { msg, coupleId, senderId } = data;

        try {
            // 1. Guardar el mensaje del usuario en la BD
            const userMessage = new Message({
                senderId: senderId,
                coupleId: coupleId,
                text: msg,
                isFromAI: false
            });
            await userMessage.save();

            // 2. Enviar el mensaje del usuario de vuelta a su propia pantalla
            socket.emit('message', userMessage);

            // 3. Preparar y ejecutar la lógica de la IA
            // Obtenemos el ID de la pareja
            const couple = await Couple.findById(coupleId);
            const partnerId = couple.userIds.find(id => id.toString() !== senderId);

            // +++ AÑADIR ESTE BLOQUE PARA OBTENER NOMBRES +++
            const currentUser = await User.findById(senderId).select('name');
            const partnerUser = await User.findById(partnerId).select('name');
            
            // Nombres que usaremos para la IA
            const currentUserName = currentUser ? currentUser.name : 'Usuario Actual';
            const partnerName = partnerUser ? partnerUser.name : 'Mi Pareja';
            // +++ FIN DEL BLOQUE +++

            // Verificamos si la pareja ya ha hablado
            const partnerMessages = await Message.find({
                coupleId: coupleId,
                senderId: partnerId,
                isFromAI: false
            }).limit(1);

            let aiResponseText;

            if (partnerMessages.length === 0) {
                // 4a. Si la pareja NO ha hablado, enviar mensaje de espera
                aiResponseText = `Entendido, gracias por compartir cómo te sientes. 💖 Aún no he hablado con tu pareja. Cuando me cuente su versión, podré ayudarles a ambos a entender mejor la situación. Mientras tanto, ¿quieres que te ayude a calmarte o a entender por qué te sientes así? 😊`;
                
                const aiWaitingMessage = new Message({
                    senderId: senderId, // Se guarda "para" el senderId
                    coupleId: coupleId,
                    text: aiResponseText,
                    isFromAI: true
                });
                await aiWaitingMessage.save();
                
                // Emitir solo al remitente
                socket.emit('message', aiWaitingMessage);

            // ...
            } else {
                // 4b. Si AMBOS han hablado, iniciar mediación
                const history = await Message.find({ coupleId: coupleId }).sort({ createdAt: -1 }).limit(10);
                
                // --- ARREGLO DEL HISTORIAL ---
                const formattedHistory = history.map(m => {
                    // Si es un mensaje de la IA, solo pasamos el contenido
                    if (m.isFromAI) {
                        return { role: 'assistant', content: m.text };
                    }
                    
                    // Si es de un usuario, usamos sus NOMBRES
                    const speakerName = (m.senderId.toString() === senderId) ? currentUserName : partnerName;
                    return {
                        role: 'user',
                        content: `[${speakerName} dijo]: ${m.text}`
                    };
                });
                // --- FIN ARREGLO ---


                // Creamos un prompt específico para el usuario que acaba de escribir
                const mediationPrompt = [
                    ...formattedHistory.reverse(), // Ponemos los mensajes más antiguos primero
                    {
                        role: "user",
                        // Usamos los nombres en el prompt final también
                        content: `Ese fue nuestro historial. Yo soy ${currentUserName}. Acabo de decir: "${msg}". Analiza todo (lo que dije yo y lo que dijo ${partnerName}) y dame tu respuesta como mediadora, hablándome solo a mí.`
                    }
                ];

                // --- PASAMOS LOS NOMBRES A LA IA ---
                aiResponseText = await callDeepSeek(mediationPrompt, currentUserName, partnerName);
                
                const aiMediationMessage = new Message({
// ...
                    senderId: senderId, // Se guarda "para" el senderId
                    coupleId: coupleId,
                    text: aiResponseText,
                    isFromAI: true
                });
                await aiMediationMessage.save();

                // Emitir la respuesta de mediación a AMBOS (para que la vean)
socket.emit('message', aiMediationMessage);            }

        } catch (err) {
            console.error("Error en evento 'chatMessage':", err);
            socket.emit('error', 'Error al procesar tu mensaje.');
        }
    });

    socket.on('disconnect', () => {
        console.log('🔌 Usuario desconectado:', socket.id);
    });
});


// --- INICIAR EL SERVIDOR ---
// Usamos server.listen en lugar de app.listen para que Socket.IO funcione
server.listen(PORT, () => {
    // Asegurarse de que BASE_URL esté definida en Render para que esto se vea bien
    console.log(`🚀 YumiFeel corriendo en ${process.env.BASE_URL || `http://localhost:${PORT}`}`);
});