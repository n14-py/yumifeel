// =============================================
//               YumiFeel - server.js
//       Versión: Production Completa (v2.0)
// =============================================

// ---------------------------------------------
// 1. IMPORTACIONES Y CONFIGURACIÓN DEL SISTEMA
// ---------------------------------------------
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const MongoStore = require('connect-mongo');
const axios = require('axios'); // Cliente HTTP para DeepSeek
const crypto = require('crypto'); // Para generar códigos seguros

// Configuración de Socket.IO (Tiempo Real)
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app); // Servidor HTTP base
const io = new Server(server); // Servidor de Websockets montado

const PORT = process.env.PORT || 3000;

// ---------------------------------------------
// 2. CONFIGURACIÓN DEL MOTOR DE VISTAS
// ---------------------------------------------
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', require('ejs').renderFile);

// ---------------------------------------------
// 3. MIDDLEWARES PRINCIPALES
// ---------------------------------------------
app.use(express.json()); // Permite recibir JSON
app.use(express.urlencoded({ extended: true })); // Permite recibir datos de formularios
app.use(express.static(path.join(__dirname, 'public'))); // Archivos estáticos (CSS, JS, Img)

// ---------------------------------------------
// 4. CONEXIÓN A BASE DE DATOS (MONGODB)
// ---------------------------------------------
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Conectado a MongoDB (YumiFeel)'))
  .catch(err => console.error('❌ Error crítico de conexión a MongoDB:', err));

// ---------------------------------------------
// 5. CONFIGURACIÓN DE SESIÓN Y COOKIES
// ---------------------------------------------
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI,
  collectionName: 'sessions',
  ttl: 14 * 24 * 60 * 60 // 14 días de vida para la sesión en BD
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'secreto_super_seguro_yumifeel',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: false, // IMPORTANTE: Dejar en false si no usas HTTPS localmente o Proxy
        httpOnly: true, // Protege contra ataques XSS
        maxAge: 1000 * 60 * 60 * 24 * 7 // Cookie válida por 7 días
    }
}));

// Inicialización de Passport (Auth)
app.use(passport.initialize());
app.use(passport.session());

// ---------------------------------------------
// 6. MODELOS DE DATOS (SCHEMAS)
// ---------------------------------------------

// --- MODELO: PAREJA ---
const coupleSchema = new mongoose.Schema({
    userIds: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    emotionalState: {
        type: String,
        default: 'Neutral'
    },
    emotionalSummary: String, // Resumen generado por la IA
}, { timestamps: true });

const Couple = mongoose.model('Couple', coupleSchema);

// --- MODELO: USUARIO ---
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    
    coupleId: { // Relación con la Pareja
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Couple',
        default: null
    },
    partnerId: { // Relación directa con el compañero
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    invitationCode: { // Código único para invitar
        type: String,
        unique: true,
        sparse: true
    }
}, { timestamps: true });

// Generar código de invitación automáticamente antes de guardar
userSchema.pre('save', function(next) {
    if (this.isNew && !this.invitationCode) {
        this.invitationCode = crypto.randomBytes(4).toString('hex').toUpperCase();
    }
    next();
});

const User = mongoose.model('User', userSchema);

// --- MODELO: MENSAJE ---
const messageSchema = new mongoose.Schema({
    senderId: { // Quién envió el mensaje (o para quién es, si es de la IA)
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    coupleId: { 
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Couple',
        required: true
    },
    text: { type: String, required: true },
    isFromAI: { type: Boolean, default: false }
}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

// ---------------------------------------------
// 7. ESTRATEGIA DE AUTENTICACIÓN (PASSPORT)
// ---------------------------------------------
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return done(null, false, { message: 'Este correo no está registrado.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return done(null, false, { message: 'La contraseña es incorrecta.' });
        }
        
        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

// Serialización de usuarios para la sesión
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

// ---------------------------------------------
// 8. MIDDLEWARES GLOBALES Y DE RUTAS
// ---------------------------------------------

// Variables globales para las vistas (EJS)
app.use((req, res, next) => {
    res.locals.currentUser = req.user;
    res.locals.baseUrl = process.env.BASE_URL;
    res.locals.path = req.path;
    // Mensajes flash (éxito/error)
    res.locals.error = req.session.error;
    res.locals.success = req.session.success;
    delete req.session.error;
    delete req.session.success;
    next();
});

// Protector de rutas (Requiere Login)
const requireAuth = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
};

// ---------------------------------------------
// 9. RUTAS DE AUTENTICACIÓN (LOGIN/REGISTER)
// ---------------------------------------------

// Login
app.get('/login', (req, res) => {
    if (req.isAuthenticated()) return res.redirect('/');
    res.render('login.html');
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: false 
}));

// Registro
app.get('/register', (req, res) => {
    if (req.isAuthenticated()) return res.redirect('/');
    res.render('register.html');
});

app.post('/register', async (req, res, next) => {
    try {
        const { name, email, password } = req.body;
        
        if (!name || !email || !password) {
            req.session.error = "Por favor, completa todos los campos.";
            return res.redirect('/register');
        }

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            req.session.error = "Este correo electrónico ya está registrado.";
            return res.redirect('/register');
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({
            name,
            email: email.toLowerCase(),
            password: hashedPassword
        });

        await newUser.save();

        // Auto-login tras registro exitoso
        req.login(newUser, (err) => {
            if (err) return next(err);
            req.session.success = "¡Bienvenido a YumiFeel!";
            return res.redirect('/');
        });

    } catch (err) {
        console.error("Error en registro:", err);
        req.session.error = "Ocurrió un error al crear tu cuenta.";
        res.redirect('/register');
    }
});

// Logout
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        req.session.destroy(() => {
            res.redirect('/login');
        });
    });
});

// ---------------------------------------------
// 10. RUTAS PRINCIPALES DE LA APP
// ---------------------------------------------

// HOME / CHAT
app.get('/', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        // A) USUARIO SIN PAREJA -> VISTA VINCULAR
        if (!user.coupleId || !user.partnerId) {
            return res.render('index.html', { 
                view: 'link-partner', 
                invitationCode: user.invitationCode,
                partner: null,
                messages: []
            });
        }

        // B) USUARIO CON PAREJA -> VISTA CHAT PRIVADO
        const partner = await User.findById(user.partnerId).select('name email');
        
        // --- FILTRO DE PRIVACIDAD ---
        // Buscamos SOLO los mensajes asociados al usuario actual (senderId = yo).
        // Esto traerá:
        // 1. Lo que yo escribí.
        // 2. Lo que la IA me respondió a mí.
        // NO traerá lo que escribió mi pareja.
        const messages = await Message.find({
            coupleId: user.coupleId,
            senderId: user._id 
        }).sort({ createdAt: 'asc' });

        res.render('index.html', {
            view: 'chat',
            partner: partner,
            messages: messages,
            invitationCode: user.invitationCode 
        });

    } catch (err) {
        console.error("Error cargando home:", err);
        req.session.error = "Error al cargar la aplicación.";
        res.redirect('/login');
    }
});

// SETTINGS / AJUSTES
app.get('/settings', requireAuth, async (req, res) => {
    let partner = null;
    if (req.user.partnerId) {
        partner = await User.findById(req.user.partnerId).select('name');
    }
    
    res.render('settings.html', {
        invitationCode: req.user.invitationCode,
        partner: partner
    });
});

// VINCULAR PAREJA (POST)
app.post('/link-partner', requireAuth, async (req, res) => {
    const { partnerCode } = req.body;
    const currentUser = await User.findById(req.user.id);

    try {
        if (!partnerCode) {
            req.session.error = "Debes ingresar un código.";
            return res.redirect('/');
        }
        
        if (partnerCode.toUpperCase() === currentUser.invitationCode) {
            req.session.error = "No puedes vincularte con tu propio código.";
            return res.redirect('/');
        }

        const partner = await User.findOne({ invitationCode: partnerCode.toUpperCase() });

        if (!partner) {
            req.session.error = "El código no existe. Verifícalo.";
            return res.redirect('/');
        }

        if (currentUser.coupleId || partner.coupleId) {
            req.session.error = "Uno de los usuarios ya tiene pareja.";
            return res.redirect('/');
        }

        // Crear nueva pareja
        const newCouple = new Couple({
            userIds: [currentUser._id, partner._id]
        });
        await newCouple.save();

        // Actualizar usuario actual
        currentUser.coupleId = newCouple._id;
        currentUser.partnerId = partner._id;
        await currentUser.save();

        // Actualizar pareja
        partner.coupleId = newCouple._id;
        partner.partnerId = currentUser._id;
        await partner.save();

        req.session.success = `¡Conectado exitosamente con ${partner.name}!`;
        res.redirect('/');

    } catch (err) {
        console.error("Error al vincular:", err);
        req.session.error = "Error interno al vincular.";
        res.redirect('/');
    }
});

// ---------------------------------------------
// 11. MOTOR DE IA (DEEPSEEK / OPENAI)
// ---------------------------------------------
async function callDeepSeek(history, currentUserName, partnerName) {
    try {
        // --- PROMPT DE MEDIACIÓN PRIVADA ---
        // Este prompt es clave: Instruye a la IA a leer TODO pero responder SOLO al usuario.
        const systemPrompt = {
            role: "system",
            content: `Eres Yumi, una IA mediadora de parejas experta en inteligencia emocional.
            
            DINÁMICA DE LA CONVERSACIÓN:
            1. Estás en un chat privado con ${currentUserName}.
            2. Tienes acceso al contexto de lo que ha dicho su pareja (${partnerName}), pero ${currentUserName} NO puede leer esos mensajes.
            3. Tu trabajo es ser un puente. Explica cómo se siente ${partnerName} basándote en sus mensajes, pero tradúcelo a un lenguaje constructivo y empático.
            
            REGLAS:
            - Nunca copies y pegues textualmente lo que dijo ${partnerName} si es hiriente.
            - Ayuda a ${currentUserName} a validar sus propios sentimientos.
            - Sé breve, cálida y usa emojis ocasionalmente.
            - Tu objetivo es reducir el conflicto y aumentar la conexión.`
        };

        const response = await axios.post(
            'https://api.deepseek.com/chat/completions',
            {
                model: 'deepseek-chat', 
                messages: [systemPrompt, ...history],
                temperature: 0.7, 
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
            return "Hmm, me quedé pensando... ¿podrías repetírmelo?";
        }

    } catch (error) {
        console.error("Error IA:", error.response ? error.response.data : error.message);
        return "Lo siento, mi conexión con el universo está fallando un poco. Intenta de nuevo en unos segundos. 🌟";
    }
}

// ---------------------------------------------
// 12. SERVIDOR REALTIME (SOCKET.IO)
// ---------------------------------------------

// Almacenamiento en memoria para estados (se reinicia si el server cae)
// Estructura: { coupleId: { userId1: {mood...}, userId2: {mood...} } }
const userStatuses = {}; 

io.on('connection', (socket) => {
    console.log('🔌 Nuevo cliente conectado:', socket.id);

    // UNIRSE A LA SALA DE LA PAREJA
    socket.on('join room', (coupleId) => {
        if (coupleId) {
            socket.join(coupleId);
            console.log(`Socket ${socket.id} unido a sala ${coupleId}`);
        }
    });

    // --- MANEJO DE MENSAJES DE CHAT (Lógica Privada) ---
    socket.on('chat message', async (data) => {
        const { text: msg, coupleId, userId: senderId } = data;

        try {
            // 1. Guardar mensaje del usuario en BD
            const userMessage = new Message({
                senderId: senderId,
                coupleId: coupleId,
                text: msg,
                isFromAI: false
            });
            await userMessage.save();

            // 2. EMITIR SOLO AL REMITENTE (Feedback inmediato)
            // NO usamos io.to(coupleId) para no mostrar el texto a la pareja.
            socket.emit('chat message', {
                text: userMessage.text,
                userId: userMessage.senderId.toString(),
                isFromAI: false,
                createdAt: userMessage.createdAt
            });

            // 3. OBTENER CONTEXTO PARA LA IA
            const couple = await Couple.findById(coupleId);
            const partnerId = couple.userIds.find(id => id.toString() !== senderId);

            const currentUser = await User.findById(senderId).select('name');
            const partnerUser = await User.findById(partnerId).select('name');
            
            const currentUserName = currentUser ? currentUser.name : 'Tu';
            const partnerName = partnerUser ? partnerUser.name : 'Tu Pareja';

            // 4. CONSTRUIR HISTORIAL COMPLETO (Usuario + Pareja)
            // La IA necesita leer ambos lados para mediar.
            const history = await Message.find({ coupleId: coupleId }).sort({ createdAt: -1 }).limit(20);
            
            const formattedHistory = history.map(m => {
                if (m.isFromAI) return { role: 'assistant', content: m.text };
                
                // Etiquetamos claramente quién habla para la IA
                const speakerName = (m.senderId.toString() === senderId) ? currentUserName : partnerName;
                return {
                    role: 'user',
                    content: `[${speakerName} dice]: ${m.text}`
                };
            });

            // Prompt específico para este turno
            const mediationPrompt = [
                ...formattedHistory.reverse(),
                {
                    role: "user",
                    content: `Soy ${currentUserName}. Acabo de decir: "${msg}". Respóndeme a mí.`
                }
            ];

            // 5. LLAMADA A LA IA
            const aiResponseText = await callDeepSeek(mediationPrompt, currentUserName, partnerName);
            
            // 6. GUARDAR RESPUESTA IA
            const aiMediationMessage = new Message({
                senderId: senderId, // Se guarda "a nombre" del usuario actual para que aparezca en SU chat
                coupleId: coupleId,
                text: aiResponseText,
                isFromAI: true
            });
            await aiMediationMessage.save();

            // 7. ENVIAR RESPUESTA IA SOLO AL USUARIO
            socket.emit('chat message', {
                text: aiMediationMessage.text,
                userId: 'AI',
                isFromAI: true,
                createdAt: aiMediationMessage.createdAt
            });

        } catch (err) {
            console.error("Error procesando mensaje:", err);
        }
    });

    // --- EVENTO: TE EXTRAÑO (Sí se comparte) ---
    socket.on('miss you', (data) => {
        // Envia señal a la otra persona en la sala
        socket.to(data.coupleId).emit('partner missed you');
        console.log(`❤️ Latido enviado en sala ${data.coupleId}`);
    });

    // --- EVENTO: ACTUALIZAR ESTADO (Sí se comparte) ---
    socket.on('status update', (data) => {
        const { coupleId, userId, mood, energy, happiness, share } = data;
        
        // Guardar en memoria
        if (!userStatuses[coupleId]) userStatuses[coupleId] = {};
        userStatuses[coupleId][userId] = { mood, energy, happiness, share };

        // Avisar a la pareja en tiempo real
        socket.to(coupleId).emit('partner status update', { mood, energy, happiness, share });
    });

    // --- EVENTO: RECUPERAR ESTADO AL CONECTAR ---
    socket.on('get status', (coupleId) => {
        if (userStatuses[coupleId]) {
            const states = userStatuses[coupleId];
            // Enviamos los estados disponibles
            for (const uid in states) {
                socket.emit('partner status update', states[uid]);
            }
        }
    });

    // Desconexión
    socket.on('disconnect', () => {
        console.log('🔌 Cliente desconectado');
    });
});

// ---------------------------------------------
// 13. INICIO DEL SERVIDOR
// ---------------------------------------------
server.listen(PORT, () => {
    console.log(`
    🚀 SERVIDOR YUMIFEEL INICIADO 🚀
    --------------------------------
    Puerto: ${PORT}
    URL Base: ${process.env.BASE_URL || 'http://localhost:' + PORT}
    MongoDB: Conectado
    Modo: ${process.env.NODE_ENV || 'Development'}
    --------------------------------
    `);
});