require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { validateBaseEnv, parseAllowedOrigins } = require('./scripts/env-utils');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 12;
const CLINIC_LOCATION = "Piata Alexandru Lahovari nr. 1, Sector 1, Bucuresti";
const LOGIN_LOCKOUT_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LOCKOUT_AFTER_ATTEMPTS = 5;
const LOGIN_LOCKOUT_DURATION_MS = 15 * 60 * 1000;
const MAX_DIAGNOSTIC_FILE_SIZE_BYTES = 5 * 1024 * 1024;
const ALLOWED_DIAGNOSTIC_MIME_TYPES = new Set(['application/pdf', 'image/jpeg', 'image/png']);
const ENABLE_DIAGNOSTIC_UPLOAD = process.env.ENABLE_DIAGNOSTIC_UPLOAD === 'true';

const baseEnvValidation = validateBaseEnv(process.env);
if (!baseEnvValidation.ok) {
    console.error('Startup environment validation failed:');
    for (const error of baseEnvValidation.errors) {
        console.error(`- ${error}`);
    }
    process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
const ALLOWED_ORIGINS = parseAllowedOrigins(process.env.ALLOWED_ORIGINS);
const loginAttempts = new Map();

// =====================
//  SCHEMAS
// =====================

// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
    phone: { type: String, unique: true, sparse: true, trim: true },
    password: String,
    googleId: String,
    displayName: String,
    role: { type: String, enum: ['user', 'admin', 'superadmin'], default: 'user' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Appointment Schema
const appointmentSchema = new mongoose.Schema({
    name: String,
    phone: String,
    type: String,
    date: String,
    time: String,
    notes: { type: String, default: '' },
    email: String,
    emailSent: { type: Boolean, default: false },
    hasDiagnosis: { type: Boolean, default: false },
    diagnosticFileMeta: {
        key: { type: String, default: null },
        mime: { type: String, default: null },
        size: { type: Number, default: null },
        uploadedAt: { type: Date, default: null }
    },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    createdAt: { type: Date, default: Date.now }
});
appointmentSchema.index({ date: 1, time: 1 }, { unique: true });

const Appointment = mongoose.model('Appointment', appointmentSchema);

const auditLogSchema = new mongoose.Schema({
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    action: { type: String, required: true },
    appointmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Appointment', default: null },
    ip: { type: String, default: '' },
    timestamp: { type: Date, default: Date.now }
});

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

mongoose.connect(MONGODB_URI)
    .then(async () => {
        await Appointment.syncIndexes();
        console.log('Connected to MongoDB');
    })
    .catch(err => console.error('MongoDB connection error:', err));

// =====================
//  MIDDLEWARE
// =====================

app.set('trust proxy', 1);

app.use(helmet({
    frameguard: { action: 'deny' },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", 'https://cdn.tailwindcss.com'],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
            imgSrc: ["'self'", 'data:', 'blob:'],
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
        }
    }
}));

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) {
            return callback(null, true);
        }

        if (ALLOWED_ORIGINS.includes(origin)) {
            return callback(null, true);
        }

        return callback(new Error('Origin not allowed by CORS.'));
    }
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static('public'));

// =====================
//  VALIDATION HELPERS
// =====================

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^(\+?40|0)7\d{8}$/;

function validateEmail(email) {
    return EMAIL_REGEX.test(email);
}

function validatePhone(phone) {
    const cleaned = phone.replace(/[\s\-]/g, '');
    return PHONE_REGEX.test(cleaned);
}

function cleanPhone(phone) {
    return phone.replace(/[\s\-]/g, '');
}

function isEmail(identifier) {
    return identifier.includes('@');
}

function generateToken(user) {
    return jwt.sign(
        { id: user._id, email: user.email, displayName: user.displayName, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
}

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return String(forwarded).split(',')[0].trim();
    }
    return req.ip || req.socket?.remoteAddress || 'unknown';
}

function getAttemptKey(req, identifier = '') {
    return `${getClientIp(req)}:${String(identifier).toLowerCase().trim()}`;
}

function getLoginAttemptState(key) {
    const now = Date.now();
    const existing = loginAttempts.get(key);

    if (!existing) {
        return { count: 0, firstAttemptAt: now, lockUntil: 0 };
    }

    if (existing.firstAttemptAt + LOGIN_LOCKOUT_WINDOW_MS < now) {
        loginAttempts.delete(key);
        return { count: 0, firstAttemptAt: now, lockUntil: 0 };
    }

    return existing;
}

function registerFailedLoginAttempt(req, identifier = '') {
    const key = getAttemptKey(req, identifier);
    const now = Date.now();
    const state = getLoginAttemptState(key);
    const count = state.count + 1;
    const lockUntil = count >= LOGIN_LOCKOUT_AFTER_ATTEMPTS ? now + LOGIN_LOCKOUT_DURATION_MS : state.lockUntil;

    loginAttempts.set(key, { count, firstAttemptAt: state.firstAttemptAt || now, lockUntil });
    return { count, lockUntil };
}

function clearFailedLoginAttempt(req, identifier = '') {
    loginAttempts.delete(getAttemptKey(req, identifier));
}

function getLoginLock(req, identifier = '') {
    const state = getLoginAttemptState(getAttemptKey(req, identifier));
    if (state.lockUntil && state.lockUntil > Date.now()) {
        return state.lockUntil;
    }
    return 0;
}

function sanitizeAppointmentForAdminList(appointment) {
    return {
        _id: appointment._id,
        name: appointment.name,
        phone: appointment.phone,
        email: appointment.email || '',
        date: appointment.date,
        time: appointment.time,
        type: appointment.type,
        notes: appointment.notes || '',
        hasDiagnosis: !!appointment.hasDiagnosis,
        diagnosticFileMeta: appointment.diagnosticFileMeta || null,
        emailSent: !!appointment.emailSent,
        createdAt: appointment.createdAt
    };
}

async function writeAuditLog(req, action, appointmentId = null) {
    try {
        await AuditLog.create({
            adminId: req.user._id,
            action,
            appointmentId,
            ip: getClientIp(req)
        });
    } catch (error) {
        console.error('Audit log write failed:', error.message);
    }
}

function validateDiagnosticFileMeta(meta) {
    if (!meta || typeof meta !== 'object') return false;

    const key = String(meta.key || '').trim();
    const mime = String(meta.mime || '').trim();
    const size = Number(meta.size);

    if (!key || !mime || Number.isNaN(size)) return false;
    if (!ALLOWED_DIAGNOSTIC_MIME_TYPES.has(mime)) return false;
    if (size <= 0 || size > MAX_DIAGNOSTIC_FILE_SIZE_BYTES) return false;
    return true;
}

const strictAuthLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 8,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Prea multe Ã®ncercÄƒri. ReÃ®ncercaÈ›i Ã®n cÃ¢teva minute.' }
});

const bookingLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Prea multe programÄƒri trimise de la acest IP. ÃŽncercaÈ›i mai tÃ¢rziu.' }
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Prea multe cereri administrative de la acest IP.' }
});

async function executeEmailScript(base64Data) {
    const smtpHost = process.env.EMAIL_SMTP_HOST || 'smtp.gmail.com';
    const smtpPort = Number(process.env.EMAIL_SMTP_PORT || 587);
    const smtpSecure = process.env.EMAIL_SMTP_SECURE === 'true';
    const senderEmail = process.env.EMAIL_USER;
    const senderPass = process.env.EMAIL_PASS;
    const senderName = process.env.EMAIL_FROM_NAME || 'Prof. Dr. Florian Balta';

    if (!senderEmail || !senderPass) {
        throw new Error('EMAIL_USER and EMAIL_PASS are required.');
    }

    const appointmentData = JSON.parse(Buffer.from(base64Data, 'base64').toString('utf8'));
    const { name, email, type, time, location } = appointmentData;
    if (!name || !email || !type || !time || !location) {
        throw new Error('Incomplete email payload.');
    }

    const [datePart, timePart] = time.split(' ');
    if (!datePart || !timePart) {
        throw new Error(`Invalid appointment time: ${time}`);
    }
    const [year, month, day] = datePart.split('-').map(Number);
    const [hour, minute] = timePart.split(':').map(Number);
    if ([year, month, day, hour, minute].some(Number.isNaN)) {
        throw new Error(`Invalid date/time values: ${time}`);
    }

    const pad2 = (n) => String(n).padStart(2, '0');
    const addMinutes = (y, mo, d, h, mi, delta) => {
        const dt = new Date(Date.UTC(y, mo - 1, d, h, mi + delta, 0));
        return {
            year: dt.getUTCFullYear(),
            month: dt.getUTCMonth() + 1,
            day: dt.getUTCDate(),
            hour: dt.getUTCHours(),
            minute: dt.getUTCMinutes()
        };
    };
    const toIcsLocal = ({ year: y, month: mo, day: d, hour: h, minute: mi }) =>
        `${y}${pad2(mo)}${pad2(d)}T${pad2(h)}${pad2(mi)}00`;
    const nowUtcStamp = () => {
        const now = new Date();
        return `${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}${pad2(now.getUTCDate())}T${pad2(now.getUTCHours())}${pad2(now.getUTCMinutes())}${pad2(now.getUTCSeconds())}Z`;
    };
    const escapeIcs = (value) =>
        String(value || '')
            .replace(/\\/g, '\\\\')
            .replace(/\n/g, '\\n')
            .replace(/;/g, '\\;')
            .replace(/,/g, '\\,');

    const start = { year, month, day, hour, minute };
    const end = addMinutes(year, month, day, hour, minute, 30);
    const uid = `${Date.now()}-${Math.random().toString(36).slice(2)}@antigravity`;
    const dtStart = toIcsLocal(start);
    const dtEnd = toIcsLocal(end);
    const dtStamp = nowUtcStamp();
    const dateRo = `${pad2(day)}.${pad2(month)}.${year}`;
    const timeRo = `${pad2(hour)}:${pad2(minute)}`;
    const summary = `Programare Prof. Dr. Balta Florian - [${type}]`;

    const icsContent = [
        'BEGIN:VCALENDAR',
        'PRODID:-//Antigravity Appointments//RO',
        'VERSION:2.0',
        'CALSCALE:GREGORIAN',
        'METHOD:REQUEST',
        'BEGIN:VTIMEZONE',
        'TZID:Europe/Bucharest',
        'BEGIN:STANDARD',
        'TZOFFSETFROM:+0300',
        'TZOFFSETTO:+0200',
        'TZNAME:EET',
        'DTSTART:19701025T040000',
        'RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU',
        'END:STANDARD',
        'BEGIN:DAYLIGHT',
        'TZOFFSETFROM:+0200',
        'TZOFFSETTO:+0300',
        'TZNAME:EEST',
        'DTSTART:19700329T030000',
        'RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU',
        'END:DAYLIGHT',
        'END:VTIMEZONE',
        'BEGIN:VEVENT',
        `UID:${uid}`,
        `DTSTAMP:${dtStamp}`,
        `DTSTART;TZID=Europe/Bucharest:${dtStart}`,
        `DTEND;TZID=Europe/Bucharest:${dtEnd}`,
        `SUMMARY:${escapeIcs(summary)}`,
        `DESCRIPTION:${escapeIcs(`Pacient: ${name}\nTip: ${type}`)}`,
        `LOCATION:${escapeIcs(location)}`,
        'STATUS:CONFIRMED',
        'BEGIN:VALARM',
        'ACTION:DISPLAY',
        'DESCRIPTION:Reminder',
        'TRIGGER:-PT60M',
        'END:VALARM',
        'END:VEVENT',
        'END:VCALENDAR'
    ].join('\r\n');

    const transporter = nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpSecure,
        auth: {
            user: senderEmail,
            pass: senderPass
        }
    });

    const htmlBody = `
        <div style="font-family: Arial, sans-serif;">
            <h2>Buna ziua, ${name}!</h2>
            <p>Programarea dumneavoastra a fost confirmata cu succes.</p>
            <ul>
                <li><strong>Tip:</strong> ${type}</li>
                <li><strong>Data si ora:</strong> ${dateRo} ${timeRo}</li>
                <li><strong>Locatie:</strong> ${location}</li>
            </ul>
            <p>Gasiti atasata invitatia de calendar (.ics).</p>
            <p>Multumim,<br/>Echipa ${senderName}</p>
        </div>
    `;

    const info = await transporter.sendMail({
        from: `"${senderName}" <${senderEmail}>`,
        to: email,
        subject: `Confirmare programare: ${summary}`,
        html: htmlBody,
        attachments: [
            {
                filename: 'invite.ics',
                content: icsContent,
                contentType: 'text/calendar; charset=UTF-8; method=REQUEST'
            }
        ]
    });

    return { messageId: info.messageId, envelope: info.envelope };
}

// Optional auth middleware
function optionalAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
        } catch (err) {
            // Token invalid
        }
    }
    next();
}

// Required Admin middleware
async function requireAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Autentificare necesarÄƒ.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);

        if (user && (user.role === 'admin' || user.role === 'superadmin')) {
            req.user = user;
            next();
        } else {
            res.status(403).json({ error: 'Acces interzis. Drepturi de administrator necesare.' });
        }
    } catch (err) {
        res.status(401).json({ error: 'Sesiune invalidÄƒ sau expiratÄƒ.' });
    }
}

// Required Super Admin middleware
async function requireSuperAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Autentificare necesarÄƒ.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);

        if (user && user.role === 'superadmin') {
            req.user = user;
            next();
        } else {
            res.status(403).json({ error: 'Acces interzis. Doar Super Admin are acces aici.' });
        }
    } catch (err) {
        res.status(401).json({ error: 'Sesiune invalidÄƒ sau expiratÄƒ.' });
    }
}

// =====================
//  AUTH API
// =====================

app.use('/api/auth/login', strictAuthLimiter);
app.use('/api/auth/signup', strictAuthLimiter);
app.use('/api/book', bookingLimiter);
app.use('/api/admin', adminLimiter);

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, phone, password, displayName } = req.body;

        if (!email || !phone || !password) {
            return res.status(400).json({ error: 'Email, telefon È™i parola sunt obligatorii.' });
        }

        if (!displayName || displayName.trim().length < 2) {
            return res.status(400).json({ error: 'Numele trebuie sÄƒ aibÄƒ cel puÈ›in 2 caractere.' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Format email invalid.' });
        }

        if (!validatePhone(phone)) {
            return res.status(400).json({ error: 'Format telefon invalid. FolosiÈ›i formatul 07xx xxx xxx.' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Parola trebuie sÄƒ aibÄƒ minim 6 caractere.' });
        }

        const cleanedPhone = cleanPhone(phone);

        const existingEmail = await User.findOne({ email: email.toLowerCase() });
        if (existingEmail) {
            return res.status(409).json({ error: 'Acest email este deja Ã®nregistrat.' });
        }

        const existingPhone = await User.findOne({ phone: cleanedPhone });
        if (existingPhone) {
            return res.status(409).json({ error: 'Acest numÄƒr de telefon este deja Ã®nregistrat.' });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        const user = new User({
            email: email.toLowerCase(),
            phone: cleanedPhone,
            password: hashedPassword,
            displayName: displayName.trim(),
            role: 'user'
        });

        await user.save();
        const token = generateToken(user);

        res.status(201).json({
            success: true,
            message: 'Cont creat cu succes!',
            token,
            user: {
                id: user._id,
                email: user.email,
                phone: user.phone,
                displayName: user.displayName,
                role: user.role
            }
        });

    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ error: 'Eroare la Ã®nregistrare.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;

        if (!identifier || !password) {
            return res.status(400).json({ error: 'Introduce?i email/telefon ?i parola.' });
        }

        const lockUntil = getLoginLock(req, identifier);
        if (lockUntil) {
            const waitSeconds = Math.ceil((lockUntil - Date.now()) / 1000);
            return res.status(429).json({ error: `Prea multe încercari e?uate. Încerca?i din nou în ${waitSeconds} secunde.` });
        }

        let user;
        if (isEmail(identifier)) {
            user = await User.findOne({ email: identifier.toLowerCase().trim() });
        } else {
            const cleanedPhone = cleanPhone(identifier);
            user = await User.findOne({ phone: cleanedPhone });
        }

        if (!user) {
            const failedAttempt = registerFailedLoginAttempt(req, identifier);
            if (failedAttempt.count > 1) {
                await new Promise((resolve) => setTimeout(resolve, Math.min(200 * failedAttempt.count, 2000)));
            }
            return res.status(401).json({ error: 'Email/telefon sau parola incorecta.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            const failedAttempt = registerFailedLoginAttempt(req, identifier);
            if (failedAttempt.count > 1) {
                await new Promise((resolve) => setTimeout(resolve, Math.min(200 * failedAttempt.count, 2000)));
            }
            return res.status(401).json({ error: 'Email/telefon sau parola incorecta.' });
        }

        clearFailedLoginAttempt(req, identifier);
        const token = generateToken(user);

        res.json({
            success: true,
            message: 'Autentificare reu?ita!',
            token,
            user: {
                id: user._id,
                email: user.email,
                phone: user.phone,
                displayName: user.displayName,
                role: user.role
            }
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Eroare la autentificare.' });
    }
});

app.get('/api/auth/me', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token lipsÄƒ.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'Utilizator negÄƒsit.' });
        }

        // Return a fresh token too, in case role changed
        const newToken = generateToken(user);

        res.json({
            token: newToken,
            user: {
                id: user._id,
                email: user.email,
                phone: user.phone,
                displayName: user.displayName,
                role: user.role,
                createdAt: user.createdAt
            }
        });

    } catch (err) {
        return res.status(401).json({ error: 'Sesiune invalidÄƒ.' });
    }
});


// =====================
//  SLOTS API
// =====================

const generateSlots = () => {
    const slots = [];
    let start = 9 * 60;
    const end = 14 * 60;
    while (start < end) {
        const hours = Math.floor(start / 60);
        const mins = start % 60;
        const timeStr = `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}`;
        slots.push(timeStr);
        start += 20;
    }
    return slots;
};

app.get('/api/slots', async (req, res) => {
    const { date } = req.query;
    if (!date) return res.status(400).json({ error: 'Date is required' });
    const day = new Date(date).getDay();
    if (day !== 3) return res.status(400).json({ error: 'Appointments are only available on Wednesdays.' });
    const allSlots = generateSlots();
    try {
        const existingAppointments = await Appointment.find({ date });
        const bookedTimes = existingAppointments.map(a => a.time);
        const availableSlots = allSlots.map(time => ({
            time,
            available: !bookedTimes.includes(time)
        }));
        res.json(availableSlots);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/book', optionalAuth, async (req, res) => {
    const { name, phone, email, type, date, time } = req.body;
    if (!name || !phone || !email || !type || !date || !time) {
        return res.status(400).json({ error: 'Toate câmpurile obligatorii trebuie completate.' });
    }

    if (!validateEmail(email)) {
        return res.status(400).json({ error: 'Format email invalid.' });
    }

    if (!validatePhone(phone)) {
        return res.status(400).json({ error: 'Format telefon invalid.' });
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^\d{2}:\d{2}$/.test(time)) {
        return res.status(400).json({ error: 'Data sau ora sunt invalide.' });
    }

    const dateDay = new Date(date).getDay();
    if (dateDay !== 3) {
        return res.status(400).json({ error: 'Programările sunt disponibile doar miercurea.' });
    }

    try {
        const { hasDiagnosis, diagnosticFile, diagnosticFileMeta } = req.body;
        if (diagnosticFile) {
            return res.status(400).json({ error: 'Încărcarea directă de fișiere este dezactivată. Folosiți stocare externă securizată.' });
        }

        let safeDiagnosticFileMeta = null;
        if (hasDiagnosis) {
            if (!ENABLE_DIAGNOSTIC_UPLOAD && diagnosticFileMeta) {
                return res.status(400).json({ error: 'Încărcarea documentelor este dezactivată momentan.' });
            }

            if (ENABLE_DIAGNOSTIC_UPLOAD && diagnosticFileMeta) {
                if (!validateDiagnosticFileMeta(diagnosticFileMeta)) {
                    return res.status(400).json({
                        error: `Metadatele fișierului sunt invalide. Tipuri permise: ${Array.from(ALLOWED_DIAGNOSTIC_MIME_TYPES).join(', ')}; mărime maximă ${MAX_DIAGNOSTIC_FILE_SIZE_BYTES} bytes.`
                    });
                }
                safeDiagnosticFileMeta = {
                    key: diagnosticFileMeta.key,
                    mime: diagnosticFileMeta.mime,
                    size: Number(diagnosticFileMeta.size),
                    uploadedAt: new Date()
                };
            }
        }

        const newAppointment = new Appointment({
            name,
            phone: cleanPhone(phone),
            email: email.toLowerCase().trim(),
            type,
            date,
            time,
            hasDiagnosis: !!hasDiagnosis,
            diagnosticFileMeta: safeDiagnosticFileMeta,
            userId: req.user ? req.user.id : null
        });
        await newAppointment.save();

        // Send Email Invitation (Async)
        const appointmentData = {
            name,
            email,
            type,
            time: `${date} ${time}`,
            location: "PiaÈ›a Alexandru Lahovari nr. 1, Sector 1, BucureÈ™ti"
        };

        const base64Data = Buffer.from(JSON.stringify(appointmentData)).toString('base64');

        console.log(`[EMAIL] Dispatching invitation for ${email}...`);

        executeEmailScript(base64Data).then(async ({ stdout, stderr, pythonCmd }) => {
            if (stdout) console.log(`[EMAIL STDOUT]: ${stdout}`);
            if (stderr) console.error(`[EMAIL STDERR]: ${stderr}`);
            console.log(`[EMAIL] Sent using interpreter: ${pythonCmd}`);

            try {
                await Appointment.findByIdAndUpdate(newAppointment._id, { emailSent: true });
                console.log(`[EMAIL SUCCESS] Status updated for ${email}`);
            } catch (updateErr) {
                console.error('[EMAIL DB UPDATE ERROR]:', updateErr);
            }
        }).catch(error => {
            console.error(`[EMAIL FAILURE] Process error for ${email}:`, error?.stderr || error.message);
        });

        res.json({ success: true, message: 'Programare confirmată! Verificați e-mail-ul pentru invitație.' });
    } catch (err) {
        if (err?.code === 11000) {
            return res.status(409).json({ error: 'Interval deja rezervat.' });
        }
        res.status(500).json({ error: 'Eroare la salvare.' });
    }
});


// =====================
//  ADMIN API
// =====================

// List appointments - Use JWT auth now
app.get('/api/admin/appointments', requireAdmin, async (req, res) => {
    try {
        const appointments = await Appointment.find().sort({ date: 1, time: 1 }).lean();
        await writeAuditLog(req, 'appointments_list');
        res.json(appointments.map(sanitizeAppointmentForAdminList));
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/appointments/:id', requireAdmin, async (req, res) => {
    try {
        const appointment = await Appointment.findById(req.params.id).lean();
        if (!appointment) {
            return res.status(404).json({ error: 'Programare negăsită.' });
        }

        await writeAuditLog(req, 'appointment_details_read', appointment._id);
        res.json(sanitizeAppointmentForAdminList(appointment));
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/appointments/:id/file-url', requireAdmin, async (req, res) => {
    try {
        const appointment = await Appointment.findById(req.params.id).lean();
        if (!appointment) {
            return res.status(404).json({ error: 'Programare negăsită.' });
        }

        await writeAuditLog(req, 'appointment_file_download_requested', appointment._id);

        if (!ENABLE_DIAGNOSTIC_UPLOAD || !appointment.diagnosticFileMeta?.key) {
            return res.status(404).json({ error: 'Documentul nu este disponibil pentru descărcare.' });
        }

        return res.status(501).json({ error: 'Generarea URL-urilor semnate nu este configurată în acest mediu.' });
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/admin/resend-email/:id', requireAdmin, async (req, res) => {
    try {
        const appointment = await Appointment.findById(req.params.id);
        if (!appointment) return res.status(404).json({ error: 'Programare negÄƒsitÄƒ.' });
        if (!appointment.email) return res.status(400).json({ error: 'Clientul nu are e-mail.' });

        const { name, email, type, date, time } = appointment;
        const appointmentData = {
            name,
            email,
            type,
            time: `${date} ${time}`,
            location: "PiaÈ›a Alexandru Lahovari nr. 1, Sector 1, BucureÈ™ti"
        };

        const base64Data = Buffer.from(JSON.stringify(appointmentData)).toString('base64');
        console.log(`[MANUAL EMAIL] Executing manual invitation for ${email}...`);

        try {
            const { stdout, stderr, pythonCmd } = await executeEmailScript(base64Data);
            if (stdout) console.log(`[MANUAL EMAIL STDOUT]: ${stdout}`);
            if (stderr) console.error(`[MANUAL EMAIL STDERR]: ${stderr}`);
            console.log(`[MANUAL EMAIL] Sent using interpreter: ${pythonCmd}`);
            await Appointment.findByIdAndUpdate(appointment._id, { emailSent: true });
            res.json({ success: true, message: 'Email trimis cu succes!' });
        } catch (err) {
            console.error(`[MANUAL EMAIL CRITICAL] Execution failed:`, err?.stderr || err.message || err);
            res.status(500).json({
                error: 'Trimiterea a eÈ™uat.',
                details: err?.stderr || err.message || 'Eroare necunoscutÄƒ'
            });
        }
    } catch (err) {
        res.status(500).json({ error: 'Eroare de sistem.' });
    }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try {
        const stats = await mongoose.connection.db.command({ dbStats: 1 });
        const usedSize = stats.storageSize || stats.dataSize;
        res.json({
            usedSizeMB: (usedSize / (1024 * 1024)).toFixed(3),
            totalSizeMB: 512,
            percentUsed: ((usedSize / (512 * 1024 * 1024)) * 100).toFixed(2)
        });
    } catch (err) {
        res.status(500).json({ error: 'Could not fetch stats' });
    }
});

app.post('/api/admin/reset', requireAdmin, async (req, res) => {
    try {
        await Appointment.deleteMany({});
        res.json({ success: true, message: 'Baza de date a fost resetatÄƒ.' });
    } catch (err) {
        res.status(500).json({ error: 'Eroare la resetarea bazei de date.' });
    }
});

app.delete('/api/admin/appointment/:id', requireAdmin, async (req, res) => {
    try {
        const deleted = await Appointment.findByIdAndDelete(req.params.id);
        if (!deleted) {
            return res.status(404).json({ error: 'Programare negÄƒsitÄƒ.' });
        }
        res.json({ success: true, message: 'Programarea pacientului a fost anulatÄƒ.' });
    } catch (err) {
        res.status(500).json({ error: 'Eroare la anularea programÄƒrii.' });
    }
});

app.delete('/api/admin/appointments/by-date', requireAdmin, async (req, res) => {
    try {
        const { date } = req.body || {};
        if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
            return res.status(400).json({ error: 'Data este invalidÄƒ. FolosiÈ›i formatul YYYY-MM-DD.' });
        }

        const result = await Appointment.deleteMany({ date });
        res.json({
            success: true,
            deletedCount: result.deletedCount || 0,
            message: `Au fost anulate ${result.deletedCount || 0} programÄƒri pentru data ${date}.`
        });
    } catch (err) {
        res.status(500).json({ error: 'Eroare la anularea programÄƒrilor pe zi.' });
    }
});

app.get('/api/admin/export', requireAdmin, async (req, res) => {
    try {
        const appointments = await Appointment.find().sort({ date: 1, time: 1 }).lean();
        const data = appointments.map(a => ({
            Data: a.date, Ora: a.time, Nume: a.name, Email: a.email || '', Telefon: a.phone, Tip: a.type,
            Email_Trimis: a.emailSent ? 'DA' : 'NU',
            Creat: a.createdAt ? a.createdAt.toISOString().split('T')[0] : ''
        }));
        const wb = xlsx.utils.book_new();
        const ws = xlsx.utils.json_to_sheet(data);
        xlsx.utils.book_append_sheet(wb, ws, "Programari");
        const buf = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });
        res.setHeader('Content-Disposition', 'attachment; filename="programari.xlsx"');
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.send(buf);
    } catch (err) {
        res.status(500).send('Eroare la generarea Excel.');
    }
});

// =====================
//  USER MANAGEMENT (SUPER ADMIN)
// =====================

// List all users
app.get('/api/admin/users', requireSuperAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

// Toggle Admin role
app.post('/api/admin/users/role', requireSuperAdmin, async (req, res) => {
    try {
        const { userId, role } = req.body;

        if (!userId || !role) {
            return res.status(400).json({ error: 'UserId È™i Rolul sunt necesare.' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'Utilizator negÄƒsit.' });
        }

        // Prevent changing superadmin role via this endpoint
        if (user.role === 'superadmin') {
            return res.status(403).json({ error: 'Rolul de Super Admin nu poate fi schimbat.' });
        }

        if (!['user', 'admin'].includes(role)) {
            return res.status(400).json({ error: 'Rol invalid.' });
        }

        user.role = role;
        await user.save();

        res.json({ success: true, message: `Rolul utilizatorului ${user.displayName} a fost actualizat la ${role}.` });
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.use((err, req, res, next) => {
    if (err && String(err.message || '').includes('CORS')) {
        return res.status(403).json({ error: 'Origin not allowed.' });
    }
    return next(err);
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT} (MongoDB + Auth + RBAC Enabled)`);
});


