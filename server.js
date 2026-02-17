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
const crypto = require('crypto');
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

const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
const ALLOWED_ORIGINS = parseAllowedOrigins(process.env.ALLOWED_ORIGINS);
const ACCESS_TOKEN_TTL_MINUTES = Number(process.env.ACCESS_TOKEN_TTL_MINUTES || 15);
const REFRESH_TOKEN_TTL_DAYS = Number(process.env.REFRESH_TOKEN_TTL_DAYS || 30);
const ACCESS_COOKIE_NAME = '__Host-access';
const REFRESH_COOKIE_NAME = '__Host-refresh';
const CSRF_COOKIE_NAME = '__Host-csrf';
const AUTH_COOKIE_BASE_OPTIONS = Object.freeze({
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/'
});
const CSRF_COOKIE_OPTIONS = Object.freeze({
    httpOnly: false,
    secure: true,
    sameSite: 'strict',
    path: '/'
});
const loginAttempts = new Map();
const refreshAttempts = new Map();

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
    },
    credentials: false
}));
app.use(bodyParser.json({ limit: '10mb' }));

app.use((req, res, next) => {
    req._parsedCookies = parseCookies(req);
    next();
});

app.use((req, res, next) => {
    const csrfCookie = getCookie(req, CSRF_COOKIE_NAME);
    if (!csrfCookie) {
        const token = setCsrfCookie(res);
        req._parsedCookies[CSRF_COOKIE_NAME] = token;
    }
    next();
});

app.use((req, res, next) => {
    if (!shouldRequireCsrf(req)) {
        return next();
    }

    const csrfCookie = getCookie(req, CSRF_COOKIE_NAME);
    const csrfHeader = String(req.get('X-CSRF-Token') || '').trim();

    if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
        return res.status(403).json({ error: 'CSRF token invalid or missing.' });
    }
    return next();
});

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

function toPositiveInt(value, fallback) {
    const parsed = Number.parseInt(String(value), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        return fallback;
    }
    return parsed;
}

const ACCESS_TOKEN_TTL_MINUTES_SAFE = toPositiveInt(ACCESS_TOKEN_TTL_MINUTES, 15);
const REFRESH_TOKEN_TTL_DAYS_SAFE = toPositiveInt(REFRESH_TOKEN_TTL_DAYS, 30);

function generateAccessToken(user) {
    return jwt.sign(
        { sub: String(user._id), tokenType: 'access' },
        JWT_ACCESS_SECRET,
        { expiresIn: `${ACCESS_TOKEN_TTL_MINUTES_SAFE}m` }
    );
}

function generateRefreshToken(user) {
    return jwt.sign(
        { sub: String(user._id), tokenType: 'refresh' },
        JWT_REFRESH_SECRET,
        { expiresIn: `${REFRESH_TOKEN_TTL_DAYS_SAFE}d` }
    );
}

function verifyAccessToken(token) {
    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    if (!payload || payload.tokenType !== 'access' || !payload.sub) {
        throw new Error('Invalid access token payload.');
    }
    return payload;
}

function verifyRefreshToken(token) {
    const payload = jwt.verify(token, JWT_REFRESH_SECRET);
    if (!payload || payload.tokenType !== 'refresh' || !payload.sub) {
        throw new Error('Invalid refresh token payload.');
    }
    return payload;
}

function buildUserPayload(user) {
    return {
        id: user._id,
        email: user.email,
        phone: user.phone,
        displayName: user.displayName,
        role: user.role,
        createdAt: user.createdAt
    };
}

function buildSessionUser(user) {
    return {
        id: user._id,
        email: user.email,
        role: user.role,
        displayName: user.displayName
    };
}

function parseCookies(req) {
    const cookieHeader = req.headers.cookie || '';
    if (!cookieHeader) return {};

    const parsed = {};
    const entries = cookieHeader.split(';');
    for (const entry of entries) {
        const index = entry.indexOf('=');
        if (index <= 0) continue;

        const key = entry.slice(0, index).trim();
        const rawValue = entry.slice(index + 1).trim();
        try {
            parsed[key] = decodeURIComponent(rawValue);
        } catch (_) {
            parsed[key] = rawValue;
        }
    }
    return parsed;
}

function getCookie(req, key) {
    if (!req._parsedCookies) {
        req._parsedCookies = parseCookies(req);
    }
    return req._parsedCookies[key];
}

function generateCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}

function setCsrfCookie(res, token = generateCsrfToken()) {
    res.cookie(CSRF_COOKIE_NAME, token, CSRF_COOKIE_OPTIONS);
    return token;
}

function setSessionCookies(res, user, { rotateRefresh = true, rotateCsrf = true } = {}) {
    const accessToken = generateAccessToken(user);
    res.cookie(ACCESS_COOKIE_NAME, accessToken, {
        ...AUTH_COOKIE_BASE_OPTIONS,
        maxAge: ACCESS_TOKEN_TTL_MINUTES_SAFE * 60 * 1000
    });

    if (rotateRefresh) {
        const refreshToken = generateRefreshToken(user);
        res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
            ...AUTH_COOKIE_BASE_OPTIONS,
            maxAge: REFRESH_TOKEN_TTL_DAYS_SAFE * 24 * 60 * 60 * 1000
        });
    }

    if (rotateCsrf) {
        setCsrfCookie(res);
    }
}

function clearSessionCookies(res) {
    const authClearOpts = {
        ...AUTH_COOKIE_BASE_OPTIONS,
        maxAge: 0
    };
    const csrfClearOpts = {
        ...CSRF_COOKIE_OPTIONS,
        maxAge: 0
    };

    res.clearCookie(ACCESS_COOKIE_NAME, authClearOpts);
    res.clearCookie(REFRESH_COOKIE_NAME, authClearOpts);
    res.clearCookie(CSRF_COOKIE_NAME, csrfClearOpts);
}

function setAuthNoStore(res) {
    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');
}

function shouldRequireCsrf(req) {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        return false;
    }
    if (req.path === '/api/auth/login') {
        return false;
    }
    return true;
}

function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
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

function getRefreshAttemptState(key) {
    const now = Date.now();
    const existing = refreshAttempts.get(key);

    if (!existing) {
        return { count: 0, firstAttemptAt: now };
    }

    if (existing.firstAttemptAt + LOGIN_LOCKOUT_WINDOW_MS < now) {
        refreshAttempts.delete(key);
        return { count: 0, firstAttemptAt: now };
    }

    return existing;
}

function registerFailedRefreshAttempt(req) {
    const key = getClientIp(req);
    const now = Date.now();
    const state = getRefreshAttemptState(key);
    const count = state.count + 1;
    refreshAttempts.set(key, { count, firstAttemptAt: state.firstAttemptAt || now });
    return { count };
}

function clearFailedRefreshAttempt(req) {
    refreshAttempts.delete(getClientIp(req));
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
    message: { error: 'Prea multe ÃƒÂ®ncercÃ„Æ’ri. ReÃƒÂ®ncercaÃˆâ€ºi ÃƒÂ®n cÃƒÂ¢teva minute.' }
});

const refreshLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Prea multe cereri de refresh. Reincercati in cateva minute.' }
});

const bookingLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Prea multe programÃ„Æ’ri trimise de la acest IP. ÃƒÅ½ncercaÃˆâ€ºi mai tÃƒÂ¢rziu.' }
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

async function getAuthenticatedUser(req) {
    const accessToken = getCookie(req, ACCESS_COOKIE_NAME);
    if (!accessToken) return null;

    const payload = verifyAccessToken(accessToken);
    const user = await User.findById(payload.sub);
    return user || null;
}

// Optional auth middleware
async function optionalAuth(req, res, next) {
    try {
        req.user = await getAuthenticatedUser(req);
    } catch (_) {
        req.user = null;
    }
    next();
}

// Required Admin middleware
async function requireAdmin(req, res, next) {
    try {
        const user = await getAuthenticatedUser(req);
        if (!user) {
            return res.status(401).json({ error: 'Autentificare necesara.' });
        }

        if (user.role === 'admin' || user.role === 'superadmin') {
            req.user = user;
            return next();
        }
        return res.status(403).json({ error: 'Acces interzis. Drepturi de administrator necesare.' });
    } catch (_) {
        return res.status(401).json({ error: 'Sesiune invalida sau expirata.' });
    }
}

// Required Super Admin middleware
async function requireSuperAdmin(req, res, next) {
    try {
        const user = await getAuthenticatedUser(req);
        if (!user) {
            return res.status(401).json({ error: 'Autentificare necesara.' });
        }

        if (user.role === 'superadmin') {
            req.user = user;
            return next();
        }
        return res.status(403).json({ error: 'Acces interzis. Doar Super Admin are acces aici.' });
    } catch (_) {
        return res.status(401).json({ error: 'Sesiune invalida sau expirata.' });
    }
}

// =====================
//  AUTH API
// =====================

app.use('/api/auth/login', strictAuthLimiter);
app.use('/api/auth/signup', strictAuthLimiter);
app.use('/api/auth/refresh', refreshLimiter);
app.use('/api/book', bookingLimiter);
app.use('/api/admin', adminLimiter);

app.post('/api/auth/signup', async (req, res) => {
    setAuthNoStore(res);

    try {
        const { email, phone, password, displayName } = req.body || {};

        if (!email || !phone || !password) {
            return res.status(400).json({ error: 'Email, telefon si parola sunt obligatorii.' });
        }

        if (!displayName || displayName.trim().length < 2) {
            return res.status(400).json({ error: 'Numele trebuie sa aiba cel putin 2 caractere.' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Format email invalid.' });
        }

        if (!validatePhone(phone)) {
            return res.status(400).json({ error: 'Format telefon invalid. Folositi formatul 07xx xxx xxx.' });
        }

        if (String(password).length < 6) {
            return res.status(400).json({ error: 'Parola trebuie sa aiba minim 6 caractere.' });
        }

        const cleanedPhone = cleanPhone(phone);

        const existingEmail = await User.findOne({ email: String(email).toLowerCase() });
        if (existingEmail) {
            return res.status(409).json({ error: 'Acest email este deja inregistrat.' });
        }

        const existingPhone = await User.findOne({ phone: cleanedPhone });
        if (existingPhone) {
            return res.status(409).json({ error: 'Acest numar de telefon este deja inregistrat.' });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        const user = new User({
            email: String(email).toLowerCase(),
            phone: cleanedPhone,
            password: hashedPassword,
            displayName: String(displayName).trim(),
            role: 'user'
        });

        await user.save();
        setSessionCookies(res, user, { rotateRefresh: true, rotateCsrf: true });

        return res.status(201).json({
            ok: true,
            user: buildSessionUser(user)
        });

    } catch (err) {
        console.error('Signup error:', err.message);
        return res.status(500).json({ error: 'Eroare la inregistrare.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    setAuthNoStore(res);

    try {
        const identifier = typeof req.body?.identifier === 'string' ? req.body.identifier.trim() : '';
        const password = typeof req.body?.password === 'string' ? req.body.password : '';

        if (!identifier || !password || identifier.length > 254 || password.length > 1024) {
            return res.status(400).json({ error: 'Date de autentificare invalide.' });
        }

        const lockUntil = getLoginLock(req, identifier);
        if (lockUntil) {
            const waitSeconds = Math.ceil((lockUntil - Date.now()) / 1000);
            return res.status(429).json({ error: `Prea multe incercari esuate. Incercati din nou in ${waitSeconds} secunde.` });
        }

        let user;
        if (isEmail(identifier)) {
            user = await User.findOne({ email: identifier.toLowerCase() });
        } else {
            const cleanedPhone = cleanPhone(identifier);
            user = await User.findOne({ phone: cleanedPhone });
        }

        if (!user) {
            const failedAttempt = registerFailedLoginAttempt(req, identifier);
            if (failedAttempt.count > 1) {
                await delay(Math.min(200 * failedAttempt.count, 2000));
            }
            return res.status(401).json({ error: 'Credentiale invalide.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            const failedAttempt = registerFailedLoginAttempt(req, identifier);
            if (failedAttempt.count > 1) {
                await delay(Math.min(200 * failedAttempt.count, 2000));
            }
            return res.status(401).json({ error: 'Credentiale invalide.' });
        }

        clearFailedLoginAttempt(req, identifier);
        setSessionCookies(res, user, { rotateRefresh: true, rotateCsrf: true });

        return res.json({
            ok: true,
            user: buildSessionUser(user)
        });

    } catch (err) {
        console.error('Login error:', err.message);
        return res.status(500).json({ error: 'Eroare la autentificare.' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    setAuthNoStore(res);
    clearSessionCookies(res);
    return res.json({ ok: true });
});

app.post('/api/auth/refresh', async (req, res) => {
    setAuthNoStore(res);

    const refreshToken = getCookie(req, REFRESH_COOKIE_NAME);
    if (!refreshToken) {
        const failedAttempt = registerFailedRefreshAttempt(req);
        if (failedAttempt.count > 1) {
            await delay(Math.min(150 * failedAttempt.count, 1500));
        }
        clearSessionCookies(res);
        return res.status(401).json({ error: 'Sesiune invalida.' });
    }

    try {
        const payload = verifyRefreshToken(refreshToken);
        const user = await User.findById(payload.sub);

        if (!user) {
            throw new Error('User not found for refresh token.');
        }

        clearFailedRefreshAttempt(req);
        setSessionCookies(res, user, { rotateRefresh: true, rotateCsrf: true });
        return res.json({ ok: true });

    } catch (_) {
        const failedAttempt = registerFailedRefreshAttempt(req);
        if (failedAttempt.count > 1) {
            await delay(Math.min(150 * failedAttempt.count, 1500));
        }
        clearSessionCookies(res);
        return res.status(401).json({ error: 'Sesiune invalida.' });
    }
});

app.get('/api/auth/me', async (req, res) => {
    setAuthNoStore(res);

    const accessToken = getCookie(req, ACCESS_COOKIE_NAME);
    if (!accessToken) {
        return res.status(401).json({ error: 'Sesiune absenta.' });
    }

    try {
        const payload = verifyAccessToken(accessToken);
        const user = await User.findById(payload.sub).select('-password');
        if (!user) {
            return res.status(401).json({ error: 'Sesiune invalida.' });
        }

        return res.json({
            ok: true,
            user: buildUserPayload(user)
        });

    } catch (_) {
        return res.status(401).json({ error: 'Sesiune invalida sau expirata.' });
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
        return res.status(400).json({ error: 'Toate cÃ¢mpurile obligatorii trebuie completate.' });
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
        return res.status(400).json({ error: 'ProgramÄƒrile sunt disponibile doar miercurea.' });
    }

    try {
        const { hasDiagnosis, diagnosticFile, diagnosticFileMeta } = req.body;
        if (diagnosticFile) {
            return res.status(400).json({ error: 'ÃŽncÄƒrcarea directÄƒ de fiÈ™iere este dezactivatÄƒ. FolosiÈ›i stocare externÄƒ securizatÄƒ.' });
        }

        let safeDiagnosticFileMeta = null;
        if (hasDiagnosis) {
            if (!ENABLE_DIAGNOSTIC_UPLOAD && diagnosticFileMeta) {
                return res.status(400).json({ error: 'ÃŽncÄƒrcarea documentelor este dezactivatÄƒ momentan.' });
            }

            if (ENABLE_DIAGNOSTIC_UPLOAD && diagnosticFileMeta) {
                if (!validateDiagnosticFileMeta(diagnosticFileMeta)) {
                    return res.status(400).json({
                        error: `Metadatele fiÈ™ierului sunt invalide. Tipuri permise: ${Array.from(ALLOWED_DIAGNOSTIC_MIME_TYPES).join(', ')}; mÄƒrime maximÄƒ ${MAX_DIAGNOSTIC_FILE_SIZE_BYTES} bytes.`
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
            location: "PiaÃˆâ€ºa Alexandru Lahovari nr. 1, Sector 1, BucureÃˆâ„¢ti"
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

        res.json({ success: true, message: 'Programare confirmatÄƒ! VerificaÈ›i e-mail-ul pentru invitaÈ›ie.' });
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
            return res.status(404).json({ error: 'Programare negÄƒsitÄƒ.' });
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
            return res.status(404).json({ error: 'Programare negÄƒsitÄƒ.' });
        }

        await writeAuditLog(req, 'appointment_file_download_requested', appointment._id);

        if (!ENABLE_DIAGNOSTIC_UPLOAD || !appointment.diagnosticFileMeta?.key) {
            return res.status(404).json({ error: 'Documentul nu este disponibil pentru descÄƒrcare.' });
        }

        return res.status(501).json({ error: 'Generarea URL-urilor semnate nu este configuratÄƒ Ã®n acest mediu.' });
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/admin/resend-email/:id', requireAdmin, async (req, res) => {
    try {
        const appointment = await Appointment.findById(req.params.id);
        if (!appointment) return res.status(404).json({ error: 'Programare negÃ„Æ’sitÃ„Æ’.' });
        if (!appointment.email) return res.status(400).json({ error: 'Clientul nu are e-mail.' });

        const { name, email, type, date, time } = appointment;
        const appointmentData = {
            name,
            email,
            type,
            time: `${date} ${time}`,
            location: "PiaÃˆâ€ºa Alexandru Lahovari nr. 1, Sector 1, BucureÃˆâ„¢ti"
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
                error: 'Trimiterea a eÃˆâ„¢uat.',
                details: err?.stderr || err.message || 'Eroare necunoscutÃ„Æ’'
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
        res.json({ success: true, message: 'Baza de date a fost resetatÃ„Æ’.' });
    } catch (err) {
        res.status(500).json({ error: 'Eroare la resetarea bazei de date.' });
    }
});

app.delete('/api/admin/appointment/:id', requireAdmin, async (req, res) => {
    try {
        const deleted = await Appointment.findByIdAndDelete(req.params.id);
        if (!deleted) {
            return res.status(404).json({ error: 'Programare negÃ„Æ’sitÃ„Æ’.' });
        }
        res.json({ success: true, message: 'Programarea pacientului a fost anulatÃ„Æ’.' });
    } catch (err) {
        res.status(500).json({ error: 'Eroare la anularea programÃ„Æ’rii.' });
    }
});

app.delete('/api/admin/appointments/by-date', requireAdmin, async (req, res) => {
    try {
        const { date } = req.body || {};
        if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
            return res.status(400).json({ error: 'Data este invalidÃ„Æ’. FolosiÃˆâ€ºi formatul YYYY-MM-DD.' });
        }

        const result = await Appointment.deleteMany({ date });
        res.json({
            success: true,
            deletedCount: result.deletedCount || 0,
            message: `Au fost anulate ${result.deletedCount || 0} programÃ„Æ’ri pentru data ${date}.`
        });
    } catch (err) {
        res.status(500).json({ error: 'Eroare la anularea programÃ„Æ’rilor pe zi.' });
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
            return res.status(400).json({ error: 'UserId Ãˆâ„¢i Rolul sunt necesare.' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'Utilizator negÃ„Æ’sit.' });
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




