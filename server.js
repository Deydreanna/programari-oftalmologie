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
const JWT_STEPUP_SECRET = process.env.JWT_STEPUP_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
const ALLOWED_ORIGINS = parseAllowedOrigins(process.env.ALLOWED_ORIGINS);
const ACCESS_TOKEN_TTL_MINUTES = Number(process.env.ACCESS_TOKEN_TTL_MINUTES || 15);
const REFRESH_TOKEN_TTL_DAYS = Number(process.env.REFRESH_TOKEN_TTL_DAYS || 30);
const STEP_UP_TOKEN_TTL_MINUTES = Number(process.env.STEP_UP_TOKEN_TTL_MINUTES || 5);
const ACCESS_COOKIE_NAME = '__Host-access';
const REFRESH_COOKIE_NAME = '__Host-refresh';
const CSRF_COOKIE_NAME = '__Host-csrf';
const ROLE = Object.freeze({
    VIEWER: 'viewer',
    SCHEDULER: 'scheduler',
    SUPERADMIN: 'superadmin'
});
const VALID_ROLES = new Set(Object.values(ROLE));
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
    role: { type: String, enum: [ROLE.VIEWER, ROLE.SCHEDULER, ROLE.SUPERADMIN], default: ROLE.VIEWER },
    createdAt: { type: Date, default: Date.now }
}, { strict: 'throw' });

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
}, { strict: 'throw' });
appointmentSchema.index({ date: 1, time: 1 }, { unique: true });

const Appointment = mongoose.model('Appointment', appointmentSchema);

const auditLogSchema = new mongoose.Schema({
    actorUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    actorRole: { type: String, default: 'anonymous' },
    action: { type: String, required: true },
    targetType: { type: String, default: '' },
    targetId: { type: String, default: '' },
    result: { type: String, enum: ['success', 'failure', 'denied'], required: true },
    ip: { type: String, default: '' },
    userAgent: { type: String, default: '' },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
    timestamp: { type: Date, default: Date.now }
}, { strict: 'throw' });
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });

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
            scriptSrc: ["'self'", 'https://cdn.tailwindcss.com', "'unsafe-inline'"],
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
app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');
    return next();
});

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
const MONGODB_OBJECT_ID_REGEX = /^[a-fA-F0-9]{24}$/;

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

function isValidISODateString(value) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;

    const [yearStr, monthStr, dayStr] = value.split('-');
    const year = Number(yearStr);
    const month = Number(monthStr);
    const day = Number(dayStr);
    if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) return false;

    const date = new Date(Date.UTC(year, month - 1, day));
    return date.getUTCFullYear() === year &&
        date.getUTCMonth() + 1 === month &&
        date.getUTCDate() === day;
}

function trimString(value) {
    return typeof value === 'string' ? value.trim() : value;
}

function createSchema(parser) {
    return {
        safeParse(input) {
            try {
                return { success: true, data: parser(input) };
            } catch (error) {
                return {
                    success: false,
                    error: { issues: [{ message: error?.message || 'Invalid request payload.' }] }
                };
            }
        }
    };
}

function ensureObjectStrict(input, allowedKeys = []) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new Error('Invalid request payload.');
    }

    const keySet = new Set(allowedKeys);
    for (const key of Object.keys(input)) {
        if (!keySet.has(key)) {
            throw new Error(`Unexpected field: ${key}`);
        }
    }
    return input;
}

function parseStringField(value, fieldName, { min = 0, max = 1024, pattern = null, trim = true } = {}) {
    if (typeof value !== 'string') {
        throw new Error(`${fieldName} must be a string.`);
    }
    const normalized = trim ? value.trim() : value;
    if (normalized.length < min || normalized.length > max) {
        throw new Error(`${fieldName} length is invalid.`);
    }
    if (pattern && !pattern.test(normalized)) {
        throw new Error(`${fieldName} format is invalid.`);
    }
    return normalized;
}

function parseBooleanField(value, fieldName, { optional = false } = {}) {
    if (value === undefined && optional) return undefined;
    if (typeof value !== 'boolean') {
        throw new Error(`${fieldName} must be a boolean.`);
    }
    return value;
}

function parseISODateField(value, fieldName) {
    const dateValue = parseStringField(value, fieldName, { min: 10, max: 10, pattern: /^\d{4}-\d{2}-\d{2}$/ });
    if (!isValidISODateString(dateValue)) {
        throw new Error(`${fieldName} is invalid.`);
    }
    return dateValue;
}

function parseTimeField(value, fieldName) {
    return parseStringField(value, fieldName, { min: 5, max: 5, pattern: /^\d{2}:\d{2}$/ });
}

function parseDiagnosticFileMeta(value) {
    if (value === undefined) return undefined;
    const input = ensureObjectStrict(value, ['key', 'mime', 'size']);
    const key = parseStringField(input.key, 'diagnosticFileMeta.key', { min: 1, max: 512 });
    const mime = parseStringField(input.mime, 'diagnosticFileMeta.mime', { min: 1, max: 128 });
    const size = Number(input.size);
    if (!Number.isInteger(size) || size <= 0 || size > MAX_DIAGNOSTIC_FILE_SIZE_BYTES) {
        throw new Error('diagnosticFileMeta.size is invalid.');
    }
    return { key, mime, size };
}

const loginBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['identifier', 'password']);
    return {
        identifier: parseStringField(payload.identifier, 'identifier', { min: 3, max: 254 }),
        password: parseStringField(payload.password, 'password', { min: 1, max: 1024, trim: false })
    };
});

const signupBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['email', 'phone', 'password', 'displayName']);
    const email = parseStringField(payload.email, 'email', { min: 3, max: 254 });
    if (!validateEmail(email)) throw new Error('email format is invalid.');
    return {
        email,
        phone: parseStringField(payload.phone, 'phone', { min: 10, max: 20 }),
        password: parseStringField(payload.password, 'password', { min: 6, max: 128, trim: false }),
        displayName: parseStringField(payload.displayName, 'displayName', { min: 2, max: 120 })
    };
});

const slotsQuerySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['date']);
    return {
        date: parseISODateField(payload.date, 'date')
    };
});

const bookBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['name', 'phone', 'email', 'type', 'date', 'time', 'hasDiagnosis', 'diagnosticFileMeta', 'diagnosticFile']);
    const email = parseStringField(payload.email, 'email', { min: 3, max: 254 });
    if (!validateEmail(email)) throw new Error('email format is invalid.');
    return {
        name: parseStringField(payload.name, 'name', { min: 2, max: 120 }),
        phone: parseStringField(payload.phone, 'phone', { min: 10, max: 20 }),
        email,
        type: parseStringField(payload.type, 'type', { min: 2, max: 64 }),
        date: parseISODateField(payload.date, 'date'),
        time: parseTimeField(payload.time, 'time'),
        hasDiagnosis: parseBooleanField(payload.hasDiagnosis, 'hasDiagnosis', { optional: true }),
        diagnosticFileMeta: parseDiagnosticFileMeta(payload.diagnosticFileMeta),
        diagnosticFile: payload.diagnosticFile
    };
});

const roleUpdateBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['userId', 'role']);
    const userId = parseStringField(payload.userId, 'userId', { min: 24, max: 24 });
    if (!MONGODB_OBJECT_ID_REGEX.test(userId)) throw new Error('Invalid userId.');
    const role = parseStringField(payload.role, 'role', { min: 6, max: 10 });
    if (![ROLE.VIEWER, ROLE.SCHEDULER].includes(role)) throw new Error('Invalid role.');
    return { userId, role };
});

const dateOnlyBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['date']);
    return {
        date: parseISODateField(payload.date, 'date')
    };
});

const stepUpBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['password', 'action']);
    return {
        password: parseStringField(payload.password, 'password', { min: 6, max: 1024, trim: false }),
        action: parseStringField(payload.action, 'action', { min: 3, max: 64 })
    };
});

function formatZodError(error) {
    const firstIssue = error?.issues?.[0];
    return firstIssue?.message || 'Invalid request payload.';
}

function validateBody(schema) {
    return (req, res, next) => {
        const parsed = schema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ error: formatZodError(parsed.error) });
        }
        req.validatedBody = parsed.data;
        return next();
    };
}

function validateQuery(schema) {
    return (req, res, next) => {
        const parsed = schema.safeParse(req.query);
        if (!parsed.success) {
            return res.status(400).json({ error: formatZodError(parsed.error) });
        }
        req.validatedQuery = parsed.data;
        return next();
    };
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

function generateStepUpToken(user, action) {
    return jwt.sign(
        {
            sub: String(user._id),
            role: user.role,
            tokenType: 'stepup',
            action: String(action || '').trim()
        },
        JWT_STEPUP_SECRET,
        { expiresIn: `${toPositiveInt(STEP_UP_TOKEN_TTL_MINUTES, 5)}m` }
    );
}

function verifyStepUpToken(token) {
    const payload = jwt.verify(token, JWT_STEPUP_SECRET);
    if (!payload || payload.tokenType !== 'stepup' || !payload.sub || !payload.action) {
        throw new Error('Invalid step-up token payload.');
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

function normalizeRoleValue(rawRole) {
    if (VALID_ROLES.has(rawRole)) {
        return rawRole;
    }
    if (rawRole === 'admin') {
        return ROLE.SCHEDULER;
    }
    if (rawRole === 'user') {
        return ROLE.VIEWER;
    }
    return ROLE.VIEWER;
}

async function ensureNormalizedRole(user) {
    if (!user) return null;
    const normalizedRole = normalizeRoleValue(user.role);
    if (normalizedRole !== user.role) {
        user.role = normalizedRole;
        await user.save();
    }
    return user;
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

function getUserAgent(req) {
    return String(req.headers['user-agent'] || '').slice(0, 512);
}

function hashIdentifier(identifier) {
    return crypto.createHash('sha256').update(String(identifier || '').toLowerCase().trim()).digest('hex');
}

async function writeAuditLog(req, {
    action,
    result = 'success',
    targetType = '',
    targetId = '',
    actorUser = req.user || null,
    metadata = {}
} = {}) {
    try {
        await AuditLog.create({
            actorUserId: actorUser?._id || null,
            actorRole: actorUser?.role || 'anonymous',
            action: String(action || 'unknown_action'),
            targetType: String(targetType || ''),
            targetId: String(targetId || ''),
            result,
            ip: getClientIp(req),
            userAgent: getUserAgent(req),
            metadata: metadata && typeof metadata === 'object' ? metadata : {}
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
    message: { error: 'Prea multe ÃƒÆ’Ã‚Â®ncercÃƒâ€žÃ†â€™ri. ReÃƒÆ’Ã‚Â®ncercaÃƒË†Ã¢â‚¬Âºi ÃƒÆ’Ã‚Â®n cÃƒÆ’Ã‚Â¢teva minute.' }
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
    message: { error: 'Prea multe programÃƒâ€žÃ†â€™ri trimise de la acest IP. ÃƒÆ’Ã…Â½ncercaÃƒË†Ã¢â‚¬Âºi mai tÃƒÆ’Ã‚Â¢rziu.' }
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
    return ensureNormalizedRole(user || null);
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

async function requireAuthenticated(req, res, next) {
    try {
        const user = await getAuthenticatedUser(req);
        if (!user) {
            return res.status(401).json({ error: 'Autentificare necesara.' });
        }
        req.user = user;
        return next();
    } catch (_) {
        return res.status(401).json({ error: 'Sesiune invalida sau expirata.' });
    }
}

function requireRoles(allowedRoles = []) {
    return async (req, res, next) => {
        try {
            const user = await getAuthenticatedUser(req);
            if (!user) {
                return res.status(401).json({ error: 'Autentificare necesara.' });
            }

            if (!allowedRoles.includes(user.role)) {
                await writeAuditLog(req, {
                    action: 'authorization_denied',
                    result: 'denied',
                    targetType: 'endpoint',
                    targetId: req.path,
                    actorUser: user,
                    metadata: { method: req.method, requiredRoles: allowedRoles }
                });
                return res.status(403).json({ error: 'Acces interzis.' });
            }

            req.user = user;
            return next();
        } catch (_) {
            return res.status(401).json({ error: 'Sesiune invalida sau expirata.' });
        }
    };
}

function requireStepUp(action) {
    return async (req, res, next) => {
        try {
            const token = String(req.get('X-Step-Up-Token') || '').trim();
            if (!token) {
                await writeAuditLog(req, {
                    action: 'step_up_required_but_missing',
                    result: 'denied',
                    targetType: 'action',
                    targetId: action,
                    actorUser: req.user || null
                });
                return res.status(403).json({ error: 'Step-up authentication required.' });
            }

            const payload = verifyStepUpToken(token);
            if (!req.user || String(req.user._id) !== String(payload.sub)) {
                await writeAuditLog(req, {
                    action: 'step_up_token_user_mismatch',
                    result: 'denied',
                    targetType: 'action',
                    targetId: action,
                    actorUser: req.user || null
                });
                return res.status(403).json({ error: 'Step-up token does not match current user.' });
            }

            if (String(payload.action) !== String(action)) {
                await writeAuditLog(req, {
                    action: 'step_up_token_action_mismatch',
                    result: 'denied',
                    targetType: 'action',
                    targetId: action,
                    actorUser: req.user || null
                });
                return res.status(403).json({ error: 'Step-up token action mismatch.' });
            }

            return next();
        } catch (_) {
            await writeAuditLog(req, {
                action: 'step_up_token_invalid',
                result: 'denied',
                targetType: 'action',
                targetId: action,
                actorUser: req.user || null
            });
            return res.status(403).json({ error: 'Invalid or expired step-up token.' });
        }
    };
}

const requireViewerSchedulerOrSuperadmin = requireRoles([ROLE.VIEWER, ROLE.SCHEDULER, ROLE.SUPERADMIN]);
const requireSchedulerOrSuperadmin = requireRoles([ROLE.SCHEDULER, ROLE.SUPERADMIN]);
const requireSuperadminOnly = requireRoles([ROLE.SUPERADMIN]);

// =====================
//  AUTH API
// =====================

app.use('/api/auth/login', strictAuthLimiter);
app.use('/api/auth/signup', strictAuthLimiter);
app.use('/api/auth/refresh', refreshLimiter);
app.use('/api/book', bookingLimiter);
app.use('/api/admin', adminLimiter);

app.post('/api/auth/signup', validateBody(signupBodySchema), async (req, res) => {
    setAuthNoStore(res);

    try {
        const { email, phone, password, displayName } = req.validatedBody;

        if (!validatePhone(phone)) {
            return res.status(400).json({ error: 'Format telefon invalid. Folositi formatul 07xx xxx xxx.' });
        }

        const cleanedPhone = cleanPhone(phone);
        const normalizedEmail = String(email).toLowerCase();

        const existingEmail = await User.findOne({ email: normalizedEmail });
        if (existingEmail) {
            return res.status(409).json({ error: 'Acest email este deja inregistrat.' });
        }

        const existingPhone = await User.findOne({ phone: cleanedPhone });
        if (existingPhone) {
            return res.status(409).json({ error: 'Acest numar de telefon este deja inregistrat.' });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        const user = new User({
            email: normalizedEmail,
            phone: cleanedPhone,
            password: hashedPassword,
            displayName: displayName.trim(),
            role: ROLE.VIEWER
        });

        await user.save();
        setSessionCookies(res, user, { rotateRefresh: true, rotateCsrf: true });
        await writeAuditLog(req, {
            action: 'auth_signup_success',
            result: 'success',
            targetType: 'user',
            targetId: String(user._id),
            actorUser: user
        });

        return res.status(201).json({
            ok: true,
            user: buildSessionUser(user)
        });

    } catch (err) {
        console.error('Signup error:', err.message);
        return res.status(500).json({ error: 'Eroare la inregistrare.' });
    }
});

app.post('/api/auth/login', validateBody(loginBodySchema), async (req, res) => {
    setAuthNoStore(res);

    try {
        const identifier = trimString(req.validatedBody.identifier);
        const password = req.validatedBody.password;

        const lockUntil = getLoginLock(req, identifier);
        if (lockUntil) {
            const waitSeconds = Math.ceil((lockUntil - Date.now()) / 1000);
            await writeAuditLog(req, {
                action: 'auth_login_failed',
                result: 'failure',
                targetType: 'auth',
                targetId: 'login',
                metadata: {
                    reason: 'lockout',
                    identifierHash: hashIdentifier(identifier)
                }
            });
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
            await writeAuditLog(req, {
                action: 'auth_login_failed',
                result: 'failure',
                targetType: 'auth',
                targetId: 'login',
                metadata: {
                    reason: 'unknown_user',
                    identifierHash: hashIdentifier(identifier)
                }
            });
            return res.status(401).json({ error: 'Credentiale invalide.' });
        }

        user = await ensureNormalizedRole(user);

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            const failedAttempt = registerFailedLoginAttempt(req, identifier);
            if (failedAttempt.count > 1) {
                await delay(Math.min(200 * failedAttempt.count, 2000));
            }
            await writeAuditLog(req, {
                action: 'auth_login_failed',
                result: 'failure',
                targetType: 'user',
                targetId: String(user._id),
                actorUser: user,
                metadata: { reason: 'password_mismatch' }
            });
            return res.status(401).json({ error: 'Credentiale invalide.' });
        }

        clearFailedLoginAttempt(req, identifier);
        setSessionCookies(res, user, { rotateRefresh: true, rotateCsrf: true });
        await writeAuditLog(req, {
            action: 'auth_login_success',
            result: 'success',
            targetType: 'user',
            targetId: String(user._id),
            actorUser: user
        });

        return res.json({
            ok: true,
            user: buildSessionUser(user)
        });

    } catch (err) {
        console.error('Login error:', err.message);
        return res.status(500).json({ error: 'Eroare la autentificare.' });
    }
});

app.post('/api/auth/logout', async (req, res) => {
    setAuthNoStore(res);
    const user = await getAuthenticatedUser(req).catch(() => null);
    clearSessionCookies(res);

    await writeAuditLog(req, {
        action: 'auth_logout',
        result: 'success',
        targetType: 'session',
        targetId: String(user?._id || ''),
        actorUser: user
    });

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
        const user = await ensureNormalizedRole(await User.findById(payload.sub));
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

app.post('/api/auth/step-up', requireAuthenticated, validateBody(stepUpBodySchema), async (req, res) => {
    setAuthNoStore(res);

    const { password, action } = req.validatedBody;

    try {
        const user = req.user;
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            await writeAuditLog(req, {
                action: 'step_up_failed',
                result: 'failure',
                targetType: 'action',
                targetId: action,
                actorUser: user
            });
            return res.status(401).json({ error: 'Confirmarea parolei a esuat.' });
        }

        const stepUpToken = generateStepUpToken(user, action);
        await writeAuditLog(req, {
            action: 'step_up_success',
            result: 'success',
            targetType: 'action',
            targetId: action,
            actorUser: user
        });

        return res.json({
            ok: true,
            stepUpToken,
            expiresInSeconds: toPositiveInt(STEP_UP_TOKEN_TTL_MINUTES, 5) * 60
        });

    } catch (error) {
        console.error('Step-up error:', error.message);
        return res.status(500).json({ error: 'Eroare la confirmarea pasului suplimentar.' });
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

app.get('/api/slots', validateQuery(slotsQuerySchema), async (req, res) => {
    const { date } = req.validatedQuery;
    const day = new Date(`${date}T00:00:00Z`).getUTCDay();
    if (day !== 3) {
        return res.status(400).json({ error: 'Appointments are only available on Wednesdays.' });
    }

    const allSlots = generateSlots();
    try {
        const existingAppointments = await Appointment.find({ date });
        const bookedTimes = existingAppointments.map((a) => a.time);
        const availableSlots = allSlots.map((time) => ({
            time,
            available: !bookedTimes.includes(time)
        }));
        return res.json(availableSlots);
    } catch (_) {
        return res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/book', optionalAuth, validateBody(bookBodySchema), async (req, res) => {
    const { name, phone, email, type, date, time, hasDiagnosis, diagnosticFile, diagnosticFileMeta } = req.validatedBody;

    if (!validatePhone(phone)) {
        return res.status(400).json({ error: 'Format telefon invalid.' });
    }

    const [hours, minutes] = String(time).split(':').map(Number);
    const minutesOfDay = (hours * 60) + minutes;
    if (Number.isNaN(minutesOfDay) || minutesOfDay < 9 * 60 || minutesOfDay > 13 * 60 + 40 || minutes % 20 !== 0) {
        return res.status(400).json({ error: 'Ora selectata este invalida.' });
    }

    const dateDay = new Date(`${date}T00:00:00Z`).getUTCDay();
    if (dateDay !== 3) {
        return res.status(400).json({ error: 'Programarile sunt disponibile doar miercurea.' });
    }

    try {
        if (diagnosticFile) {
            return res.status(400).json({ error: 'Incarcarea directa de fisiere este dezactivata. Folositi stocare externa securizata.' });
        }

        let safeDiagnosticFileMeta = null;
        if (hasDiagnosis) {
            if (!ENABLE_DIAGNOSTIC_UPLOAD && diagnosticFileMeta) {
                return res.status(400).json({ error: 'Incarcarea documentelor este dezactivata momentan.' });
            }

            if (ENABLE_DIAGNOSTIC_UPLOAD && diagnosticFileMeta) {
                if (!validateDiagnosticFileMeta(diagnosticFileMeta)) {
                    return res.status(400).json({
                        error: `Metadatele fisierului sunt invalide. Tipuri permise: ${Array.from(ALLOWED_DIAGNOSTIC_MIME_TYPES).join(', ')}; marime maxima ${MAX_DIAGNOSTIC_FILE_SIZE_BYTES} bytes.`
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
            userId: req.user ? req.user._id : null
        });
        await newAppointment.save();

        const appointmentData = {
            name,
            email,
            type,
            time: `${date} ${time}`,
            location: CLINIC_LOCATION
        };

        const base64Data = Buffer.from(JSON.stringify(appointmentData)).toString('base64');

        executeEmailScript(base64Data).then(async ({ stdout, stderr }) => {
            if (stdout) console.log(`[EMAIL STDOUT]: ${stdout}`);
            if (stderr) console.error(`[EMAIL STDERR]: ${stderr}`);

            try {
                await Appointment.findByIdAndUpdate(newAppointment._id, { emailSent: true });
            } catch (updateErr) {
                console.error('[EMAIL DB UPDATE ERROR]:', updateErr.message);
            }
        }).catch((error) => {
            console.error(`[EMAIL FAILURE]:`, error?.stderr || error.message);
        });

        return res.json({ success: true, message: 'Programare confirmata! Verificati e-mail-ul pentru invitatie.' });
    } catch (err) {
        if (err?.code === 11000) {
            return res.status(409).json({ error: 'Interval deja rezervat.' });
        }
        return res.status(500).json({ error: 'Eroare la salvare.' });
    }
});


// =====================
//  ADMIN API
// =====================

// List appointments
app.get('/api/admin/appointments', requireViewerSchedulerOrSuperadmin, async (req, res) => {
    setAuthNoStore(res);

    try {
        const appointments = await Appointment.find().sort({ date: 1, time: 1 }).lean();
        await writeAuditLog(req, {
            action: 'appointments_list_view',
            result: 'success',
            targetType: 'appointment_collection',
            actorUser: req.user,
            metadata: { count: appointments.length }
        });
        return res.json(appointments.map(sanitizeAppointmentForAdminList));
    } catch (_) {
        return res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/appointments/:id', requireViewerSchedulerOrSuperadmin, async (req, res) => {
    setAuthNoStore(res);

    const appointmentId = String(req.params.id || '').trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const appointment = await Appointment.findById(appointmentId).lean();
        if (!appointment) {
            return res.status(404).json({ error: 'Programare negasita.' });
        }

        await writeAuditLog(req, {
            action: 'appointment_view',
            result: 'success',
            targetType: 'appointment',
            targetId: appointmentId,
            actorUser: req.user
        });
        return res.json(sanitizeAppointmentForAdminList(appointment));
    } catch (_) {
        return res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/appointments/:id/file-url', requireSchedulerOrSuperadmin, async (req, res) => {
    setAuthNoStore(res);

    const appointmentId = String(req.params.id || '').trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const appointment = await Appointment.findById(appointmentId).lean();
        if (!appointment) {
            return res.status(404).json({ error: 'Programare negasita.' });
        }

        await writeAuditLog(req, {
            action: 'appointment_file_download_requested',
            result: 'success',
            targetType: 'appointment',
            targetId: appointmentId,
            actorUser: req.user
        });

        if (!ENABLE_DIAGNOSTIC_UPLOAD || !appointment.diagnosticFileMeta?.key) {
            return res.status(404).json({ error: 'Documentul nu este disponibil pentru descarcare.' });
        }

        return res.status(501).json({ error: 'Generarea URL-urilor semnate nu este configurata in acest mediu.' });
    } catch (_) {
        return res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/admin/resend-email/:id', requireSchedulerOrSuperadmin, async (req, res) => {
    setAuthNoStore(res);

    const appointmentId = String(req.params.id || '').trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const appointment = await Appointment.findById(appointmentId);
        if (!appointment) return res.status(404).json({ error: 'Programare negasita.' });
        if (!appointment.email) return res.status(400).json({ error: 'Clientul nu are e-mail.' });

        const { name, email, type, date, time } = appointment;
        const appointmentData = {
            name,
            email,
            type,
            time: `${date} ${time}`,
            location: CLINIC_LOCATION
        };

        const base64Data = Buffer.from(JSON.stringify(appointmentData)).toString('base64');

        try {
            await executeEmailScript(base64Data);
            await Appointment.findByIdAndUpdate(appointment._id, { emailSent: true });
            await writeAuditLog(req, {
                action: 'appointment_resend_email',
                result: 'success',
                targetType: 'appointment',
                targetId: appointmentId,
                actorUser: req.user
            });
            return res.json({ success: true, message: 'Email trimis cu succes!' });
        } catch (err) {
            await writeAuditLog(req, {
                action: 'appointment_resend_email',
                result: 'failure',
                targetType: 'appointment',
                targetId: appointmentId,
                actorUser: req.user,
                metadata: { reason: err?.message || 'send_failed' }
            });
            return res.status(500).json({
                error: 'Trimiterea a esuat.',
                details: err?.stderr || err.message || 'Eroare necunoscuta'
            });
        }
    } catch (_) {
        return res.status(500).json({ error: 'Eroare de sistem.' });
    }
});

app.get('/api/admin/stats', requireViewerSchedulerOrSuperadmin, async (req, res) => {
    setAuthNoStore(res);

    try {
        const stats = await mongoose.connection.db.command({ dbStats: 1 });
        const usedSize = stats.storageSize || stats.dataSize;
        await writeAuditLog(req, {
            action: 'admin_stats_view',
            result: 'success',
            targetType: 'system',
            targetId: 'db_stats',
            actorUser: req.user
        });
        return res.json({
            usedSizeMB: (usedSize / (1024 * 1024)).toFixed(3),
            totalSizeMB: 512,
            percentUsed: ((usedSize / (512 * 1024 * 1024)) * 100).toFixed(2)
        });
    } catch (_) {
        return res.status(500).json({ error: 'Could not fetch stats' });
    }
});

app.post('/api/admin/reset', requireSuperadminOnly, requireStepUp('appointments_reset'), async (req, res) => {
    setAuthNoStore(res);

    try {
        const result = await Appointment.deleteMany({});
        await writeAuditLog(req, {
            action: 'appointments_reset',
            result: 'success',
            targetType: 'appointment_collection',
            actorUser: req.user,
            metadata: { deletedCount: result.deletedCount || 0 }
        });
        return res.json({ success: true, message: 'Baza de date a fost resetata.' });
    } catch (_) {
        await writeAuditLog(req, {
            action: 'appointments_reset',
            result: 'failure',
            targetType: 'appointment_collection',
            actorUser: req.user
        });
        return res.status(500).json({ error: 'Eroare la resetarea bazei de date.' });
    }
});

app.delete('/api/admin/appointment/:id', requireSuperadminOnly, requireStepUp('appointment_delete'), async (req, res) => {
    setAuthNoStore(res);

    const appointmentId = String(req.params.id || '').trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const deleted = await Appointment.findByIdAndDelete(appointmentId);
        if (!deleted) {
            return res.status(404).json({ error: 'Programare negasita.' });
        }
        await writeAuditLog(req, {
            action: 'appointment_delete',
            result: 'success',
            targetType: 'appointment',
            targetId: appointmentId,
            actorUser: req.user
        });
        return res.json({ success: true, message: 'Programarea pacientului a fost anulata.' });
    } catch (_) {
        await writeAuditLog(req, {
            action: 'appointment_delete',
            result: 'failure',
            targetType: 'appointment',
            targetId: appointmentId,
            actorUser: req.user
        });
        return res.status(500).json({ error: 'Eroare la anularea programarii.' });
    }
});

app.delete('/api/admin/appointments/by-date', requireSuperadminOnly, requireStepUp('appointments_delete_by_date'), validateBody(dateOnlyBodySchema), async (req, res) => {
    setAuthNoStore(res);

    try {
        const { date } = req.validatedBody;
        const result = await Appointment.deleteMany({ date });
        await writeAuditLog(req, {
            action: 'appointments_delete_by_date',
            result: 'success',
            targetType: 'appointment_collection',
            targetId: date,
            actorUser: req.user,
            metadata: { deletedCount: result.deletedCount || 0 }
        });
        return res.json({
            success: true,
            deletedCount: result.deletedCount || 0,
            message: `Au fost anulate ${result.deletedCount || 0} programari pentru data ${date}.`
        });
    } catch (_) {
        await writeAuditLog(req, {
            action: 'appointments_delete_by_date',
            result: 'failure',
            targetType: 'appointment_collection',
            actorUser: req.user
        });
        return res.status(500).json({ error: 'Eroare la anularea programarilor pe zi.' });
    }
});

app.get('/api/admin/export', requireSuperadminOnly, requireStepUp('appointments_export'), async (req, res) => {
    setAuthNoStore(res);

    try {
        const appointments = await Appointment.find().sort({ date: 1, time: 1 }).lean();

        const metadataRows = [{
            NOTICE: 'CONFIDENTIAL - authorized superadmin use only',
            GeneratedAt: new Date().toISOString(),
            GeneratedBy: req.user?.email || 'unknown',
            Records: appointments.length
        }];

        const data = appointments.map((a) => ({
            Data: a.date,
            Ora: a.time,
            Tip: a.type,
            Email_Trimis: a.emailSent ? 'DA' : 'NU',
            Creat: a.createdAt ? new Date(a.createdAt).toISOString().split('T')[0] : ''
        }));

        const wb = xlsx.utils.book_new();
        wb.Props = {
            Title: 'Programari Export',
            Subject: 'Confidential',
            Author: req.user?.email || 'system',
            CreatedDate: new Date()
        };

        const wsMeta = xlsx.utils.json_to_sheet(metadataRows);
        const wsData = xlsx.utils.json_to_sheet(data);
        xlsx.utils.book_append_sheet(wb, wsMeta, 'METADATA');
        xlsx.utils.book_append_sheet(wb, wsData, 'Programari');

        const buf = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });
        await writeAuditLog(req, {
            action: 'appointments_export',
            result: 'success',
            targetType: 'appointment_collection',
            actorUser: req.user,
            metadata: { count: appointments.length }
        });

        res.setHeader('Content-Disposition', 'attachment; filename="programari.xlsx"');
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        return res.send(buf);
    } catch (_) {
        await writeAuditLog(req, {
            action: 'appointments_export',
            result: 'failure',
            targetType: 'appointment_collection',
            actorUser: req.user
        });
        return res.status(500).send('Eroare la generarea Excel.');
    }
});

// =====================
//  USER MANAGEMENT (SUPER ADMIN)
// =====================

app.get('/api/admin/users', requireSuperadminOnly, async (req, res) => {
    setAuthNoStore(res);

    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 }).lean();
        const normalizedUsers = users.map((user) => ({
            ...user,
            role: normalizeRoleValue(user.role)
        }));
        await writeAuditLog(req, {
            action: 'users_list_view',
            result: 'success',
            targetType: 'user_collection',
            actorUser: req.user,
            metadata: { count: normalizedUsers.length }
        });
        return res.json(normalizedUsers);
    } catch (_) {
        return res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/admin/users/role', requireSuperadminOnly, requireStepUp('user_role_change'), validateBody(roleUpdateBodySchema), async (req, res) => {
    setAuthNoStore(res);

    try {
        const { userId, role } = req.validatedBody;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'Utilizator negasit.' });
        }

        if (user.role === ROLE.SUPERADMIN) {
            return res.status(403).json({ error: 'Rolul de Super Admin nu poate fi schimbat.' });
        }

        const previousRole = user.role;
        user.role = role;
        await user.save();

        await writeAuditLog(req, {
            action: 'user_role_change',
            result: 'success',
            targetType: 'user',
            targetId: String(user._id),
            actorUser: req.user,
            metadata: { previousRole, newRole: role }
        });

        return res.json({ success: true, message: `Rolul utilizatorului ${user.displayName} a fost actualizat la ${role}.` });
    } catch (_) {
        await writeAuditLog(req, {
            action: 'user_role_change',
            result: 'failure',
            targetType: 'user',
            actorUser: req.user
        });
        return res.status(500).json({ error: 'Database error' });
    }
});
app.use((err, req, res, next) => {
    if (err && String(err.message || '').includes('CORS')) {
        return res.status(403).json({ error: 'Origin not allowed.' });
    }
    console.error('Unhandled error:', err?.message || err);
    if (res.headersSent) {
        return next(err);
    }

    const isProduction = process.env.NODE_ENV === 'production';
    if (isProduction) {
        return res.status(500).json({ error: 'Internal server error.' });
    }
    return res.status(500).json({ error: 'Internal server error.', details: err?.message || 'Unknown error' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT} (MongoDB + Auth + RBAC Enabled)`);
});
