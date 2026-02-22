require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
const { validateBaseEnv } = require('./scripts/env-utils');
const { runPostgresHealthCheck, getPostgresPool, redactPostgresUrlInText } = require('./db/postgres');
const pgUsers = require('./db/users-postgres');
const pgDoctors = require('./db/doctors-postgres');
const pgAppointments = require('./db/appointments-postgres');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 12;
const CLINIC_DISPLAY_NAME = 'INSTITUTUL CLINIC DE URGENTE OFTALMOLOGICE "PROF. DR. MIRCEA OLTEANU"';
const CLINIC_LOCATION = "Piata Alexandru Lahovari nr. 1, Sector 1, Bucuresti";
const LOGIN_LOCKOUT_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LOCKOUT_AFTER_ATTEMPTS = 5;
const LOGIN_LOCKOUT_DURATION_MS = 15 * 60 * 1000;
const MAX_DIAGNOSTIC_FILE_SIZE_BYTES = 5 * 1024 * 1024;
const ALLOWED_DIAGNOSTIC_MIME_TYPES = new Set(['application/pdf', 'image/jpeg', 'image/png']);
const ENABLE_DIAGNOSTIC_UPLOAD = process.env.ENABLE_DIAGNOSTIC_UPLOAD === 'true';
const ENABLE_DEBUG_CHARSET_ENDPOINT = process.env.ENABLE_DEBUG_CHARSET_ENDPOINT === 'true';
const TIME_HHMM_REGEX = /^([01]\d|2[0-3]):([0-5]\d)$/;
const DEFAULT_DOCTOR_SLUG = 'prof-dr-balta-florian';
const DEFAULT_DOCTOR_DISPLAY_NAME = CLINIC_DISPLAY_NAME;
const DEFAULT_DOCTOR_SPECIALTY = 'Oftalmologie';
const DEFAULT_BOOKING_SETTINGS = Object.freeze({
    consultationDurationMinutes: 20,
    workdayStart: '09:00',
    workdayEnd: '14:00',
    monthsToShow: 3,
    timezone: 'Europe/Bucharest'
});
const DEFAULT_AVAILABILITY_WEEKDAYS = Object.freeze([3]);

const baseEnvValidation = validateBaseEnv(process.env);
const startupValidationErrors = [...baseEnvValidation.errors];
if (startupValidationErrors.length) {
    console.error('Startup environment validation failed:');
    for (const error of startupValidationErrors) {
        console.error(`- ${error}`);
    }
    process.exit(1);
}

const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const JWT_STEPUP_SECRET = process.env.JWT_STEPUP_SECRET;
const ALLOWED_ORIGINS = baseEnvValidation.parsed.allowedOrigins || [];
const ACCESS_TOKEN_TTL_MINUTES = Number(process.env.ACCESS_TOKEN_TTL_MINUTES || 15);
const REFRESH_TOKEN_TTL_DAYS = Number(process.env.REFRESH_TOKEN_TTL_DAYS || 30);
const STEP_UP_TOKEN_TTL_MINUTES = Number(process.env.STEP_UP_TOKEN_TTL_MINUTES || 5);
const ACCESS_COOKIE_NAME = '__Host-access';
const REFRESH_COOKIE_NAME = '__Host-refresh';
const CSRF_COOKIE_NAME = '__Host-csrf';
const DEBUG_CHARSET_SAMPLE_TEXT = '\u0218\u021b\u0103\u00ee\u00e2\u0103 \u2013 test \u{1F600}';
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

function parseHHMMToMinutes(value) {
    if (typeof value !== 'string') return NaN;
    const match = value.match(TIME_HHMM_REGEX);
    if (!match) return NaN;
    const hours = Number(match[1]);
    const minutes = Number(match[2]);
    return (hours * 60) + minutes;
}

function isValidHHMM(value) {
    return TIME_HHMM_REGEX.test(String(value || ''));
}

function isValidWeekdayList(value) {
    if (!Array.isArray(value) || value.length === 0) return false;
    const normalized = new Set();
    for (const weekday of value) {
        if (!Number.isInteger(weekday) || weekday < 0 || weekday > 6) return false;
        normalized.add(weekday);
    }
    return normalized.size > 0;
}

function sanitizeInlineString(value) {
    return String(value || '').replace(/\0/g, '').trim();
}

async function ensureDefaultDoctorAndBackfill() {
    let defaultDoctor = await pgDoctors.findDoctorByIdentifier(DEFAULT_DOCTOR_SLUG, { requireActive: false });
    if (!defaultDoctor) {
        defaultDoctor = await pgDoctors.createDoctor({
            slug: DEFAULT_DOCTOR_SLUG,
            displayName: DEFAULT_DOCTOR_DISPLAY_NAME,
            specialty: DEFAULT_DOCTOR_SPECIALTY,
            isActive: true,
            bookingSettings: DEFAULT_BOOKING_SETTINGS,
            availabilityRules: { weekdays: DEFAULT_AVAILABILITY_WEEKDAYS },
            blockedDates: []
        });
    }

    return {
        defaultDoctorId: String(defaultDoctor._id),
        appointmentsBackfilled: 0,
        snapshotsBackfilled: 0,
        appointmentsMigratedToPostgres: 0,
        usersBackfilled: 0
    };
}

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
app.use(express.json({
    limit: '10mb',
    strict: true,
    type: ['application/json', 'application/*+json']
}));
app.use(express.urlencoded({ extended: false, limit: '10mb' }));
app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');
    return next();
});
app.use(['/api', '/debug'], (req, res, next) => {
    res.set('Content-Type', 'application/json; charset=utf-8');
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

app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, filePath) => {
        const lowerPath = String(filePath || '').toLowerCase();
        if (lowerPath.endsWith('.html')) {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
        } else if (lowerPath.endsWith('.js')) {
            res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
        } else if (lowerPath.endsWith('.css')) {
            res.setHeader('Content-Type', 'text/css; charset=utf-8');
        } else if (lowerPath.endsWith('.json')) {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
        }
    }
}));

app.get('/adminpanel', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.set('Content-Type', 'text/html; charset=utf-8');
    return res.sendFile(path.join(__dirname, 'public', 'adminpanel.html'));
});

// =====================
//  VALIDATION HELPERS
// =====================

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^(\+?40|0)7\d{8}$/;
const LEGACY_OBJECT_ID_REGEX = /^[a-fA-F0-9]{24}$/;
const POSTGRES_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DOCTOR_SLUG_REGEX = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const STRONG_PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{10,128}$/;

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

function validateStrongPassword(password) {
    return STRONG_PASSWORD_REGEX.test(String(password || ''));
}

function isEmail(identifier) {
    return identifier.includes('@');
}

function resolveBootstrapSuperadminEmail() {
    const candidate = String(
        process.env.SUPERADMIN_EMAIL
        || process.env.SUPERADMIN_IDENTIFIER
        || ''
    ).trim().toLowerCase();
    return candidate;
}

async function ensureBootstrapSuperadmin() {
    const email = resolveBootstrapSuperadminEmail();
    const password = typeof process.env.SUPERADMIN_PASSWORD === 'string'
        ? process.env.SUPERADMIN_PASSWORD
        : '';

    if (!email && !password) {
        return { skipped: true, reason: 'SUPERADMIN_EMAIL/SUPERADMIN_IDENTIFIER and SUPERADMIN_PASSWORD not set' };
    }

    if (!email || !password) {
        throw new Error(
            'SUPERADMIN_EMAIL (or SUPERADMIN_IDENTIFIER) and SUPERADMIN_PASSWORD must both be set to bootstrap superadmin.'
        );
    }

    if (!validateEmail(email)) {
        throw new Error('SUPERADMIN_EMAIL (or SUPERADMIN_IDENTIFIER) must be a valid email address.');
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pgUsers.withTransaction(async (client) => {
        const existing = await pgUsers.findUserByEmail(email, client);
        if (existing) {
            const updated = await pgUsers.updateUserByPublicId(existing._id, {
                passwordHash: hashedPassword,
                role: ROLE.SUPERADMIN,
                displayName: existing.displayName || 'Super Admin'
            }, client);
            return { action: 'updated', email: updated.email };
        }

        const created = await pgUsers.createUser({
            email,
            phone: null,
            passwordHash: hashedPassword,
            displayName: 'Super Admin',
            role: ROLE.SUPERADMIN,
            managedDoctorIds: []
        }, client);
        return { action: 'created', email: created.email };
    });

    console.log(`[AUTH] Superadmin bootstrap ${result.action}: ${result.email}`);
    return result;
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
    return parseStringField(value, fieldName, { min: 5, max: 5, pattern: TIME_HHMM_REGEX });
}

function parseObjectIdField(value, fieldName) {
    const idValue = parseStringField(value, fieldName, { min: 24, max: 24 });
    if (!LEGACY_OBJECT_ID_REGEX.test(idValue)) {
        throw new Error(`${fieldName} is invalid.`);
    }
    return idValue;
}

function isValidUserIdentifier(value) {
    const normalized = String(value || '').trim();
    return LEGACY_OBJECT_ID_REGEX.test(normalized) || POSTGRES_UUID_REGEX.test(normalized);
}

function parseUserIdField(value, fieldName) {
    const idValue = parseStringField(value, fieldName, { min: 24, max: 64 });
    if (!isValidUserIdentifier(idValue)) {
        throw new Error(`${fieldName} is invalid.`);
    }
    return idValue;
}

function parseObjectIdArrayField(value, fieldName, { optional = false, maxLength = 20 } = {}) {
    if (value === undefined && optional) return undefined;
    if (!Array.isArray(value)) {
        throw new Error(`${fieldName} must be an array.`);
    }
    if (value.length > maxLength) {
        throw new Error(`${fieldName} exceeds max length.`);
    }
    const seen = new Set();
    const normalized = [];
    for (const item of value) {
        const id = parseObjectIdField(item, fieldName);
        if (seen.has(id)) continue;
        seen.add(id);
        normalized.push(id);
    }
    return normalized;
}

function parseWeekdaysField(value, fieldName, { optional = false } = {}) {
    if (value === undefined && optional) return undefined;
    if (!Array.isArray(value) || value.length === 0) {
        throw new Error(`${fieldName} must contain at least one weekday.`);
    }
    const unique = new Set();
    const result = [];
    for (const item of value) {
        const numeric = Number(item);
        if (!Number.isInteger(numeric) || numeric < 0 || numeric > 6) {
            throw new Error(`${fieldName} contains an invalid weekday.`);
        }
        if (unique.has(numeric)) continue;
        unique.add(numeric);
        result.push(numeric);
    }
    return result;
}

function parseDoctorSlugField(value, fieldName = 'slug') {
    return parseStringField(value, fieldName, {
        min: 3,
        max: 80,
        pattern: DOCTOR_SLUG_REGEX
    }).toLowerCase();
}

function parseConsultationDurationField(value, fieldName) {
    const minutes = Number(value);
    if (!Number.isInteger(minutes) || minutes < 5 || minutes > 120) {
        throw new Error(`${fieldName} is invalid.`);
    }
    return minutes;
}

function parseMonthsToShowField(value, fieldName) {
    const months = Number(value);
    if (!Number.isInteger(months) || months < 1 || months > 12) {
        throw new Error(`${fieldName} is invalid.`);
    }
    return months;
}

function assertValidScheduleInterval(startTime, endTime, consultationDurationMinutes, contextFieldName, { requirePerfectDivision = false } = {}) {
    const startMinutes = parseHHMMToMinutes(startTime);
    const endMinutes = parseHHMMToMinutes(endTime);
    if (!Number.isFinite(startMinutes) || !Number.isFinite(endMinutes) || endMinutes <= startMinutes) {
        throw new Error(`${contextFieldName} interval is invalid.`);
    }
    const intervalMinutes = endMinutes - startMinutes;
    if (intervalMinutes < consultationDurationMinutes) {
        throw new Error(`${contextFieldName} interval is shorter than consultation duration.`);
    }
    if (requirePerfectDivision && (intervalMinutes % consultationDurationMinutes !== 0)) {
        throw new Error(`${contextFieldName} interval must be divisible by consultation duration.`);
    }
}

function parseWeekdayField(value, fieldName) {
    const weekday = Number(value);
    if (!Number.isInteger(weekday) || weekday < 0 || weekday > 6) {
        throw new Error(`${fieldName} is invalid.`);
    }
    return weekday;
}

function parseDayConfigsField(value, fieldName, { optional = false } = {}) {
    if (value === undefined && optional) return undefined;
    if (!Array.isArray(value) || value.length === 0) {
        throw new Error(`${fieldName} must contain at least one day config.`);
    }

    const uniqueWeekdays = new Set();
    const normalized = [];
    for (let index = 0; index < value.length; index += 1) {
        const itemField = `${fieldName}[${index}]`;
        const payload = ensureObjectStrict(value[index], ['weekday', 'startTime', 'endTime', 'consultationDurationMinutes']);
        const weekday = parseWeekdayField(payload.weekday, `${itemField}.weekday`);
        if (uniqueWeekdays.has(weekday)) {
            throw new Error(`${itemField}.weekday is duplicated.`);
        }
        uniqueWeekdays.add(weekday);

        const startTime = parseTimeField(payload.startTime, `${itemField}.startTime`);
        const endTime = parseTimeField(payload.endTime, `${itemField}.endTime`);
        const consultationDurationMinutes = parseConsultationDurationField(
            payload.consultationDurationMinutes,
            `${itemField}.consultationDurationMinutes`
        );
        assertValidScheduleInterval(startTime, endTime, consultationDurationMinutes, itemField, { requirePerfectDivision: true });

        normalized.push({
            weekday,
            startTime,
            endTime,
            consultationDurationMinutes
        });
    }

    return normalized.sort((a, b) => a.weekday - b.weekday);
}

function parseDoctorBookingSettings(value, { optional = false } = {}) {
    if (value === undefined && optional) return undefined;
    const payload = ensureObjectStrict(value, ['consultationDurationMinutes', 'workdayStart', 'workdayEnd', 'monthsToShow', 'timezone']);
    const consultationDurationMinutes = parseConsultationDurationField(payload.consultationDurationMinutes, 'bookingSettings.consultationDurationMinutes');
    const workdayStart = parseTimeField(payload.workdayStart, 'bookingSettings.workdayStart');
    const workdayEnd = parseTimeField(payload.workdayEnd, 'bookingSettings.workdayEnd');
    const monthsToShow = parseMonthsToShowField(payload.monthsToShow, 'bookingSettings.monthsToShow');
    const timezone = parseStringField(payload.timezone, 'bookingSettings.timezone', { min: 3, max: 64 });

    assertValidScheduleInterval(
        workdayStart,
        workdayEnd,
        consultationDurationMinutes,
        'bookingSettings',
        { requirePerfectDivision: false }
    );

    return {
        consultationDurationMinutes,
        workdayStart,
        workdayEnd,
        monthsToShow,
        timezone
    };
}

function parseDoctorAvailabilityRules(value, { optional = false } = {}) {
    if (value === undefined && optional) return undefined;
    const payload = ensureObjectStrict(value, ['weekdays', 'dayConfigs']);
    const dayConfigs = payload.dayConfigs !== undefined
        ? parseDayConfigsField(payload.dayConfigs, 'availabilityRules.dayConfigs')
        : undefined;
    const weekdays = dayConfigs
        ? dayConfigs.map((config) => config.weekday)
        : parseWeekdaysField(payload.weekdays, 'availabilityRules.weekdays');
    return {
        weekdays,
        ...(dayConfigs ? { dayConfigs } : {})
    };
}

function parseDoctorBlockedDates(value, { optional = false } = {}) {
    if (value === undefined && optional) return undefined;
    if (!Array.isArray(value)) {
        throw new Error('blockedDates must be an array.');
    }
    const unique = new Set();
    const normalized = [];
    for (const rawDate of value) {
        const dateValue = parseISODateField(rawDate, 'blockedDates');
        if (unique.has(dateValue)) continue;
        unique.add(dateValue);
        normalized.push(dateValue);
    }
    return normalized;
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

const adminCreateUserBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['email', 'phone', 'password', 'displayName', 'role', 'managedDoctorIds']);
    const email = parseStringField(payload.email, 'email', { min: 3, max: 254 });
    if (!validateEmail(email)) throw new Error('email format is invalid.');

    const rawRole = parseStringField(payload.role, 'role', { min: 4, max: 16 }).toLowerCase();
    const normalizedRole = normalizeRoleValue(rawRole);
    if (![ROLE.VIEWER, ROLE.SCHEDULER].includes(normalizedRole)) {
        throw new Error('Invalid role.');
    }

    const password = parseStringField(payload.password, 'password', { min: 10, max: 128, trim: false });
    if (!validateStrongPassword(password)) {
        throw new Error('Password must contain lower/upper letters and digits, minimum 10 chars.');
    }

    const managedDoctorIds = parseObjectIdArrayField(payload.managedDoctorIds || [], 'managedDoctorIds', { optional: true });

    return {
        email,
        phone: parseStringField(payload.phone, 'phone', { min: 10, max: 20 }),
        password,
        displayName: parseStringField(payload.displayName, 'displayName', { min: 2, max: 120 }),
        role: normalizedRole,
        managedDoctorIds
    };
});

const adminUpdateUserBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['email', 'phone', 'password', 'displayName', 'role', 'managedDoctorIds']);
    const output = {};

    if (payload.email !== undefined) {
        const email = parseStringField(payload.email, 'email', { min: 3, max: 254 });
        if (!validateEmail(email)) throw new Error('email format is invalid.');
        output.email = email;
    }

    if (payload.phone !== undefined) {
        output.phone = parseStringField(payload.phone, 'phone', { min: 10, max: 20 });
    }

    if (payload.password !== undefined) {
        const password = parseStringField(payload.password, 'password', { min: 10, max: 128, trim: false });
        if (!validateStrongPassword(password)) {
            throw new Error('Password must contain lower/upper letters and digits, minimum 10 chars.');
        }
        output.password = password;
    }

    if (payload.displayName !== undefined) {
        output.displayName = parseStringField(payload.displayName, 'displayName', { min: 2, max: 120 });
    }

    if (payload.role !== undefined) {
        const rawRole = parseStringField(payload.role, 'role', { min: 4, max: 16 }).toLowerCase();
        const normalizedRole = normalizeRoleValue(rawRole);
        if (![ROLE.VIEWER, ROLE.SCHEDULER, ROLE.SUPERADMIN].includes(normalizedRole)) {
            throw new Error('Invalid role.');
        }
        output.role = normalizedRole;
    }

    if (payload.managedDoctorIds !== undefined) {
        output.managedDoctorIds = parseObjectIdArrayField(payload.managedDoctorIds, 'managedDoctorIds');
    }

    if (Object.keys(output).length === 0) {
        throw new Error('At least one field is required for update.');
    }

    return output;
});

const doctorCreateBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['slug', 'displayName', 'specialty', 'isActive', 'bookingSettings', 'availabilityRules', 'blockedDates']);
    const bookingSettingsInput = payload.bookingSettings || DEFAULT_BOOKING_SETTINGS;
    const availabilityRulesInput = payload.availabilityRules || { weekdays: DEFAULT_AVAILABILITY_WEEKDAYS };
    return {
        slug: parseDoctorSlugField(payload.slug, 'slug'),
        displayName: parseStringField(payload.displayName, 'displayName', { min: 2, max: 120 }),
        specialty: parseStringField(payload.specialty || DEFAULT_DOCTOR_SPECIALTY, 'specialty', { min: 2, max: 120 }),
        isActive: parseBooleanField(payload.isActive, 'isActive', { optional: true }) ?? true,
        bookingSettings: parseDoctorBookingSettings(bookingSettingsInput),
        availabilityRules: parseDoctorAvailabilityRules(availabilityRulesInput),
        blockedDates: parseDoctorBlockedDates(payload.blockedDates || [])
    };
});

const doctorPatchBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['slug', 'displayName', 'specialty', 'isActive', 'bookingSettings', 'availabilityRules', 'blockedDates']);
    const out = {};
    if (payload.slug !== undefined) out.slug = parseDoctorSlugField(payload.slug, 'slug');
    if (payload.displayName !== undefined) out.displayName = parseStringField(payload.displayName, 'displayName', { min: 2, max: 120 });
    if (payload.specialty !== undefined) out.specialty = parseStringField(payload.specialty, 'specialty', { min: 2, max: 120 });
    if (payload.isActive !== undefined) out.isActive = parseBooleanField(payload.isActive, 'isActive');
    if (payload.bookingSettings !== undefined) out.bookingSettings = parseDoctorBookingSettings(payload.bookingSettings);
    if (payload.availabilityRules !== undefined) out.availabilityRules = parseDoctorAvailabilityRules(payload.availabilityRules);
    if (payload.blockedDates !== undefined) out.blockedDates = parseDoctorBlockedDates(payload.blockedDates);
    if (Object.keys(out).length === 0) {
        throw new Error('No updatable doctor fields provided.');
    }
    return out;
});

const doctorBlockDateBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['date']);
    return {
        date: parseISODateField(payload.date, 'date')
    };
});

const doctorDayScheduleBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['status', 'clearOverride', 'startTime', 'endTime', 'consultationDurationMinutes']);
    const out = {};

    if (payload.status !== undefined) {
        const status = parseStringField(payload.status, 'status', { min: 5, max: 12 }).toLowerCase();
        if (!['active', 'blocked'].includes(status)) {
            throw new Error('status is invalid.');
        }
        out.status = status;
    }
    if (payload.clearOverride !== undefined) {
        out.clearOverride = parseBooleanField(payload.clearOverride, 'clearOverride');
    }
    if (payload.startTime !== undefined) {
        out.startTime = parseTimeField(payload.startTime, 'startTime');
    }
    if (payload.endTime !== undefined) {
        out.endTime = parseTimeField(payload.endTime, 'endTime');
    }
    if (payload.consultationDurationMinutes !== undefined) {
        out.consultationDurationMinutes = parseConsultationDurationField(
            payload.consultationDurationMinutes,
            'consultationDurationMinutes'
        );
    }

    if (Object.keys(out).length === 0) {
        throw new Error('No day schedule fields provided.');
    }

    const status = out.status || 'active';
    if (status === 'blocked') {
        return {
            status: 'blocked',
            clearOverride: out.clearOverride !== false
        };
    }

    if (out.clearOverride === true) {
        return {
            status: 'active',
            clearOverride: true
        };
    }

    if (out.startTime === undefined || out.endTime === undefined || out.consultationDurationMinutes === undefined) {
        throw new Error('startTime, endTime and consultationDurationMinutes are required unless clearOverride=true.');
    }

    assertValidScheduleInterval(
        out.startTime,
        out.endTime,
        out.consultationDurationMinutes,
        'daySchedule',
        { requirePerfectDivision: true }
    );

    return {
        status: 'active',
        clearOverride: false,
        startTime: out.startTime,
        endTime: out.endTime,
        consultationDurationMinutes: out.consultationDurationMinutes
    };
});

const slotsQuerySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['date', 'doctor']);
    const doctor = parseStringField(payload.doctor, 'doctor', { min: 2, max: 120 });
    return {
        date: parseISODateField(payload.date, 'date'),
        doctor
    };
});

const bookBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['name', 'phone', 'email', 'type', 'date', 'time', 'hasDiagnosis', 'diagnosticFileMeta', 'diagnosticFile', 'doctorId', 'doctorSlug']);
    if (payload.doctorId === undefined && payload.doctorSlug === undefined) {
        throw new Error('doctorId or doctorSlug is required.');
    }
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
        diagnosticFile: payload.diagnosticFile,
        doctorId: payload.doctorId !== undefined ? parseObjectIdField(payload.doctorId, 'doctorId') : undefined,
        doctorSlug: payload.doctorSlug !== undefined ? parseDoctorSlugField(payload.doctorSlug, 'doctorSlug') : undefined
    };
});

const roleUpdateBodySchema = createSchema((input) => {
    const payload = ensureObjectStrict(input, ['userId', 'role']);
    const userId = parseUserIdField(payload.userId, 'userId');
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

function normalizeManagedDoctorIds(value) {
    if (!Array.isArray(value)) {
        return [];
    }
    const seen = new Set();
    const normalized = [];
    for (const item of value) {
        const id = String(item || '');
        if (!LEGACY_OBJECT_ID_REGEX.test(id)) continue;
        if (seen.has(id)) continue;
        seen.add(id);
        normalized.push(id);
    }
    return normalized;
}

function buildUserPayload(user) {
    return {
        id: user._id,
        email: user.email,
        phone: user.phone,
        displayName: user.displayName,
        role: user.role,
        createdAt: user.createdAt,
        managedDoctorIds: normalizeManagedDoctorIds(user.managedDoctorIds)
    };
}

function buildSessionUser(user) {
    return {
        id: user._id,
        email: user.email,
        role: user.role,
        displayName: user.displayName,
        managedDoctorIds: normalizeManagedDoctorIds(user.managedDoctorIds)
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

function getUserPublicId(user) {
    const candidates = [
        user?.legacyPublicId,
        user?._id,
        user?.id
    ];
    for (const candidate of candidates) {
        const value = String(candidate || '').trim();
        if (LEGACY_OBJECT_ID_REGEX.test(value)) {
            return value;
        }
    }
    return null;
}

async function findUserById(userId) {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) return null;
    return pgUsers.findUserByPublicId(normalizedUserId);
}

async function findUserByEmail(email) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!normalizedEmail) return null;
    return pgUsers.findUserByEmail(normalizedEmail);
}

async function findUserByPhone(phone) {
    const normalizedPhone = String(phone || '').trim();
    if (!normalizedPhone) return null;
    return pgUsers.findUserByPhone(normalizedPhone);
}

async function persistUser(user, { managedDoctorIdsChanged = false } = {}) {
    if (!user) return null;
    return pgUsers.updateUserByPublicId(user._id, {
        email: user.email ?? null,
        phone: user.phone ?? null,
        passwordHash: user.password,
        googleId: user.googleId ?? null,
        displayName: user.displayName,
        role: normalizeRoleValue(user.role),
        ...(managedDoctorIdsChanged ? { managedDoctorIds: normalizeManagedDoctorIds(user.managedDoctorIds || []) } : {})
    });
}

async function ensureNormalizedRole(user) {
    if (!user) return null;
    let shouldSave = false;
    const normalizedRole = normalizeRoleValue(user.role);
    if (normalizedRole !== user.role) {
        user.role = normalizedRole;
        shouldSave = true;
    }
    if (!Array.isArray(user.managedDoctorIds)) {
        user.managedDoctorIds = [];
        shouldSave = true;
    }
    if (shouldSave) {
        return persistUser(user, { managedDoctorIdsChanged: true });
    }
    return user;
}

function isSuperadminUser(user) {
    return normalizeRoleValue(user?.role) === ROLE.SUPERADMIN;
}

function getUserManagedDoctorIds(user) {
    return normalizeManagedDoctorIds(user?.managedDoctorIds || []);
}

function canUserAccessDoctor(user, doctorId) {
    if (!doctorId) return false;
    if (isSuperadminUser(user)) return true;
    const wanted = String(doctorId);
    return getUserManagedDoctorIds(user).includes(wanted);
}

function toISODateUTC(date) {
    const y = date.getUTCFullYear();
    const m = String(date.getUTCMonth() + 1).padStart(2, '0');
    const d = String(date.getUTCDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
}

function getUtcDateFromISO(dateStr) {
    const [year, month, day] = String(dateStr).split('-').map(Number);
    return new Date(Date.UTC(year, month - 1, day));
}

function isDateInDoctorRange(dateStr, monthsToShow) {
    if (!isValidISODateString(dateStr)) return false;
    const target = getUtcDateFromISO(dateStr);
    const today = new Date();
    const todayUtc = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
    if (target < todayUtc) return false;

    const maxDate = new Date(todayUtc);
    maxDate.setUTCMonth(maxDate.getUTCMonth() + Number(monthsToShow || 1));
    return target <= maxDate;
}

function generateDoctorSlots(doctor) {
    const settings = doctor?.bookingSettings || DEFAULT_BOOKING_SETTINGS;
    return generateSlotsForWindow(
        settings.workdayStart,
        settings.workdayEnd,
        settings.consultationDurationMinutes
    );
}

function generateSlotsForWindow(workdayStart, workdayEnd, consultationDurationMinutes) {
    const start = parseHHMMToMinutes(workdayStart);
    const end = parseHHMMToMinutes(workdayEnd);
    const duration = Number(consultationDurationMinutes);
    if (!Number.isFinite(start) || !Number.isFinite(end) || !Number.isInteger(duration) || duration <= 0 || end <= start) {
        return [];
    }

    const slots = [];
    for (let minute = start; minute + duration <= end; minute += duration) {
        const hour = Math.floor(minute / 60);
        const min = minute % 60;
        slots.push(`${String(hour).padStart(2, '0')}:${String(min).padStart(2, '0')}`);
    }
    return slots;
}

function sanitizeDoctorForPublic(doctor) {
    const dayConfigs = Array.isArray(doctor.availabilityRules?.dayConfigs)
        ? doctor.availabilityRules.dayConfigs
            .map((config) => ({
                weekday: Number(config?.weekday),
                startTime: String(config?.startTime || ''),
                endTime: String(config?.endTime || ''),
                consultationDurationMinutes: Number(config?.consultationDurationMinutes)
            }))
            .filter((config) => Number.isInteger(config.weekday) && config.weekday >= 0 && config.weekday <= 6)
        : [];
    return {
        _id: doctor._id,
        slug: doctor.slug,
        displayName: doctor.displayName,
        specialty: doctor.specialty || DEFAULT_DOCTOR_SPECIALTY,
        bookingSettings: {
            consultationDurationMinutes: doctor.bookingSettings?.consultationDurationMinutes,
            workdayStart: doctor.bookingSettings?.workdayStart,
            workdayEnd: doctor.bookingSettings?.workdayEnd,
            monthsToShow: doctor.bookingSettings?.monthsToShow,
            timezone: doctor.bookingSettings?.timezone
        },
        availabilityRules: {
            weekdays: dayConfigs.length
                ? dayConfigs.map((config) => config.weekday)
                : (Array.isArray(doctor.availabilityRules?.weekdays) ? doctor.availabilityRules.weekdays : []),
            dayConfigs
        }
    };
}

function sanitizeDoctorForAdmin(doctor, { includeAudit = false } = {}) {
    const dayConfigs = Array.isArray(doctor.availabilityRules?.dayConfigs)
        ? doctor.availabilityRules.dayConfigs
            .map((config) => ({
                weekday: Number(config?.weekday),
                startTime: String(config?.startTime || ''),
                endTime: String(config?.endTime || ''),
                consultationDurationMinutes: Number(config?.consultationDurationMinutes)
            }))
            .filter((config) => Number.isInteger(config.weekday) && config.weekday >= 0 && config.weekday <= 6)
        : [];
    const payload = {
        _id: doctor._id,
        slug: doctor.slug,
        displayName: doctor.displayName,
        specialty: doctor.specialty || DEFAULT_DOCTOR_SPECIALTY,
        isActive: !!doctor.isActive,
        bookingSettings: {
            consultationDurationMinutes: doctor.bookingSettings?.consultationDurationMinutes,
            workdayStart: doctor.bookingSettings?.workdayStart,
            workdayEnd: doctor.bookingSettings?.workdayEnd,
            monthsToShow: doctor.bookingSettings?.monthsToShow,
            timezone: doctor.bookingSettings?.timezone
        },
        availabilityRules: {
            weekdays: dayConfigs.length
                ? dayConfigs.map((config) => config.weekday)
                : (Array.isArray(doctor.availabilityRules?.weekdays) ? doctor.availabilityRules.weekdays : []),
            dayConfigs
        },
        blockedDates: Array.isArray(doctor.blockedDates) ? doctor.blockedDates : [],
        createdAt: doctor.createdAt,
        updatedAt: doctor.updatedAt
    };

    if (includeAudit) {
        payload.createdByUserId = doctor.createdByUserId || null;
        payload.updatedByUserId = doctor.updatedByUserId || null;
    }

    return payload;
}

async function resolveDoctorByIdentifier(rawIdentifier, { requireActive = true } = {}) {
    const normalized = sanitizeInlineString(rawIdentifier).toLowerCase();
    if (!normalized) return null;
    return pgDoctors.findDoctorByIdentifier(normalized, { requireActive });
}

async function validateDoctorIdsExist(ids = []) {
    if (!Array.isArray(ids) || ids.length === 0) {
        return true;
    }

    const normalizedLegacyIds = normalizeManagedDoctorIds(ids.map((id) => String(id)));
    if (!normalizedLegacyIds.length) {
        return false;
    }

    const count = await pgDoctors.countDoctorsByLegacyIds(normalizedLegacyIds);
    return count === normalizedLegacyIds.length;
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
        doctorId: appointment.doctorId || null,
        doctorSnapshotName: appointment.doctorSnapshotName || '',
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
        const actorUserId = getUserPublicId(actorUser) || String(actorUser?._id || actorUser?.id || '').trim() || null;
        await pgAppointments.createAuditLog({
            action: String(action || 'unknown_action'),
            result: String(result || 'success'),
            targetType: String(targetType || ''),
            targetId: String(targetId || ''),
            actorUserPublicId: actorUserId,
            actorRole: actorUser?.role || 'anonymous',
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
    message: { error: 'Prea multe incercari. Reincercati in cateva minute.' }
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
    message: { error: 'Prea multe programari trimise de la acest IP. Incercati mai tarziu.' }
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
    const senderName = process.env.EMAIL_FROM_NAME || CLINIC_DISPLAY_NAME;

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
    const summary = `Programare ${CLINIC_DISPLAY_NAME} - [${type}]`;

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
    const user = await findUserById(payload.sub);
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
app.use('/api/appointments', bookingLimiter);
app.use('/api/admin', adminLimiter);

app.get('/debug/charset', requireSuperadminOnly, async (req, res) => {
    if (!ENABLE_DEBUG_CHARSET_ENDPOINT) {
        return res.status(404).json({ error: 'Not found.' });
    }
    setAuthNoStore(res);
    res.set('Content-Type', 'application/json; charset=utf-8');

    const responseContentType = String(res.getHeader('Content-Type') || '');

    return res.status(200).json({
        ok: true,
        sample: DEBUG_CHARSET_SAMPLE_TEXT,
        responseContentType
    });
});

app.post('/debug/charset', requireSuperadminOnly, async (req, res) => {
    if (!ENABLE_DEBUG_CHARSET_ENDPOINT) {
        return res.status(404).json({ error: 'Not found.' });
    }
    setAuthNoStore(res);
    res.set('Content-Type', 'application/json; charset=utf-8');

    const incomingText = typeof req.body?.text === 'string' ? req.body.text : DEBUG_CHARSET_SAMPLE_TEXT;

    try {
        const pool = getPostgresPool();
        const result = await pool.query('SELECT $1::text AS text', [incomingText]);
        const loadedText = String(result.rows?.[0]?.text || '');
        const responseContentType = String(res.getHeader('Content-Type') || '');

        return res.status(200).json({
            ok: true,
            incomingText,
            writtenText: incomingText,
            readText: loadedText,
            dbRoundtripMatches: incomingText === loadedText,
            responseContentType
        });
    } catch (error) {
        console.error('[DEBUG CHARSET] POST failed:', error?.message || error);
        return res.status(500).json({
            ok: false,
            error: 'Debug charset DB write/read failed.'
        });
    }
});

app.post('/api/auth/signup', async (req, res) => {
    setAuthNoStore(res);
    try {
        await writeAuditLog(req, {
            action: 'auth_signup_blocked',
            result: 'denied',
            targetType: 'endpoint',
            targetId: '/api/auth/signup',
            actorUser: null
        });
    } catch (_) {
        // no-op: signup is disabled even if audit logging fails
    }
    return res.status(403).json({ error: 'Inregistrarea publica este dezactivata. Solicitati cont unui superadmin.' });
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
            user = await findUserByEmail(identifier.toLowerCase());
        } else {
            const cleanedPhone = cleanPhone(identifier);
            user = await findUserByPhone(cleanedPhone);
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
        const user = await findUserById(payload.sub);

        if (!user) {
            throw new Error('User not found for refresh token.');
        }

        clearFailedRefreshAttempt(req);
        setSessionCookies(res, await ensureNormalizedRole(user), { rotateRefresh: true, rotateCsrf: true });
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
        const user = await ensureNormalizedRole(await findUserById(payload.sub));
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

app.get('/api/public/doctors', async (req, res) => {
    try {
        const doctors = await pgDoctors.listDoctors({ isActive: true });
        return res.json({
            doctors: doctors.map(sanitizeDoctorForPublic)
        });
    } catch (error) {
        console.error('Public doctors list error:', error?.message || error);
        return res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/slots', validateQuery(slotsQuerySchema), async (req, res) => {
    const { date, doctor: doctorIdentifier } = req.validatedQuery;
    try {
        const doctor = await resolveDoctorByIdentifier(doctorIdentifier, { requireActive: true });
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found.' });
        }
        const slotMatrix = await pgAppointments.getSlotMatrixForDoctorDate(doctor._id, date);
        if (!slotMatrix.found) {
            return res.status(404).json({ error: 'Doctor not found.' });
        }
        if (slotMatrix.inRange === false) {
            return res.status(400).json({ error: 'Data selectata este in afara intervalului permis pentru acest medic.' });
        }
        if (slotMatrix.hasAvailability === false) {
            return res.status(400).json({ error: 'Medicul selectat nu are disponibilitate in aceasta zi.' });
        }

        return res.json({
            doctor: sanitizeDoctorForPublic(doctor),
            date,
            blocked: !!slotMatrix.blocked,
            slots: slotMatrix.slots
        });
    } catch (_) {
        return res.status(500).json({ error: 'Database error' });
    }
});

async function handleAppointmentBooking(req, res) {
    const { name, phone, email, type, date, time, hasDiagnosis, diagnosticFile, diagnosticFileMeta, doctorId, doctorSlug } = req.validatedBody;

    if (!validatePhone(phone)) {
        return res.status(400).json({ error: 'Format telefon invalid.' });
    }

    try {
        const doctorLookup = doctorId || doctorSlug;
        const doctor = await resolveDoctorByIdentifier(doctorLookup, { requireActive: true });
        if (!doctor) {
            return res.status(404).json({ error: 'Medicul selectat nu exista sau nu este activ.' });
        }

        if (!isDateInDoctorRange(date, doctor.bookingSettings?.monthsToShow)) {
            return res.status(400).json({ error: 'Data selectata este in afara intervalului permis pentru acest medic.' });
        }

        if (diagnosticFile) {
            return res.status(400).json({ error: 'Incarcarea directa de fisiere este dezactivata. Folositi stocare externa securizata.' });
        }

        let safeDiagnosticFileMeta;
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

        const newAppointment = await pgAppointments.createAppointmentTransactional({
            doctorIdentifier: doctor._id,
            name,
            phone: cleanPhone(phone),
            email: email.toLowerCase().trim(),
            type,
            date,
            time,
            notes: '',
            hasDiagnosis: !!hasDiagnosis,
            diagnosticFileMeta: safeDiagnosticFileMeta || null,
            userPublicId: getUserPublicId(req.user) || req.user?._id || null,
            auditContext: {
                action: 'appointment_book',
                result: 'success',
                targetType: 'appointment',
                actorUserPublicId: getUserPublicId(req.user) || req.user?._id || null,
                actorRole: req.user?.role || 'anonymous',
                ip: getClientIp(req),
                userAgent: getUserAgent(req),
                metadata: {
                    doctorId: doctor._id,
                    date,
                    time
                }
            }
        });

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
                await pgAppointments.setAppointmentEmailSentByPublicId(newAppointment._id, true);
            } catch (updateErr) {
                console.error('[EMAIL DB UPDATE ERROR]:', updateErr.message);
            }
        }).catch((error) => {
            console.error(`[EMAIL FAILURE]:`, error?.stderr || error.message);
        });

        return res.json({ success: true, message: 'Programare confirmata! Verificati e-mail-ul pentru invitatie.' });
    } catch (err) {
        if (err instanceof pgAppointments.BookingValidationError) {
            return res.status(err.status || 400).json({ error: err.message || 'Eroare la salvare.' });
        }
        console.error('Booking save failed:', err?.message || err, err?.code || '');
        if (pgAppointments.isUniqueViolation(err)) {
            return res.status(409).json({ error: 'Interval deja rezervat.' });
        }
        return res.status(500).json({ error: 'Eroare la salvare.' });
    }
}

app.post('/api/book', optionalAuth, validateBody(bookBodySchema), handleAppointmentBooking);
app.post('/api/appointments', optionalAuth, validateBody(bookBodySchema), handleAppointmentBooking);

function sanitizeUserForAdmin(userDoc, doctorMap = new Map()) {
    const managedDoctorIds = normalizeManagedDoctorIds(userDoc.managedDoctorIds);
    return {
        _id: userDoc._id,
        email: userDoc.email,
        phone: userDoc.phone,
        displayName: userDoc.displayName,
        role: normalizeRoleValue(userDoc.role),
        managedDoctorIds,
        managedDoctors: managedDoctorIds
            .map((id) => doctorMap.get(id))
            .filter(Boolean),
        createdAt: userDoc.createdAt
    };
}

async function assertManagedDoctorsExist(managedDoctorIds) {
    return validateDoctorIdsExist((managedDoctorIds || []).map((id) => String(id)));
}

async function loadDoctorsMapByIds(rawIds = []) {
    const ids = normalizeManagedDoctorIds(rawIds);
    if (ids.length === 0) {
        return new Map();
    }

    const doctors = await pgDoctors.listDoctors({ legacyIds: ids, isActive: null });

    const map = new Map();
    for (const doctor of doctors) {
        map.set(String(doctor._id), { _id: doctor._id, slug: doctor.slug, displayName: doctor.displayName });
    }
    return map;
}


// =====================
//  ADMIN API
// =====================

// List appointments
app.get('/api/admin/appointments', requireViewerSchedulerOrSuperadmin, async (req, res) => {
    setAuthNoStore(res);

    try {
        let appointments;
        if (isSuperadminUser(req.user)) {
            appointments = await pgAppointments.listAppointments();
        } else {
            const scopedDoctorIds = getUserManagedDoctorIds(req.user);
            if (scopedDoctorIds.length === 0) {
                return res.status(403).json({ error: 'Nu aveti niciun medic asignat.' });
            }
            appointments = await pgAppointments.listAppointments({ doctorLegacyIds: scopedDoctorIds });
        }

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
    if (!LEGACY_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const appointment = await pgAppointments.findAppointmentByPublicId(appointmentId);
        if (!appointment) {
            return res.status(404).json({ error: 'Programare negasita.' });
        }
        if (!canUserAccessDoctor(req.user, appointment.doctorId)) {
            return res.status(403).json({ error: 'Acces interzis pentru acest medic.' });
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
    if (!LEGACY_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const appointment = await pgAppointments.findAppointmentByPublicId(appointmentId);
        if (!appointment) {
            return res.status(404).json({ error: 'Programare negasita.' });
        }
        if (!canUserAccessDoctor(req.user, appointment.doctorId)) {
            return res.status(403).json({ error: 'Acces interzis pentru acest medic.' });
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
    if (!LEGACY_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const appointment = await pgAppointments.findAppointmentByPublicId(appointmentId);
        if (!appointment) return res.status(404).json({ error: 'Programare negasita.' });
        if (!canUserAccessDoctor(req.user, appointment.doctorId)) {
            return res.status(403).json({ error: 'Acces interzis pentru acest medic.' });
        }
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
            await pgAppointments.setAppointmentEmailSentByPublicId(appointment._id, true);
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

app.get('/api/admin/stats', requireSuperadminOnly, async (req, res) => {
    setAuthNoStore(res);

    try {
        const stats = await pgAppointments.getAppointmentStorageStats();
        const usedSize = Number(stats.appointmentsBytes || 0);
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
        const deletedCount = await pgAppointments.withTransaction(async (client) => {
            const count = await pgAppointments.deleteAllAppointments(client);
            await pgAppointments.createAuditLog({
                action: 'appointments_reset',
                result: 'success',
                targetType: 'appointment_collection',
                actorUserPublicId: getUserPublicId(req.user) || req.user?._id || null,
                actorRole: req.user?.role || 'anonymous',
                ip: getClientIp(req),
                userAgent: getUserAgent(req),
                metadata: { deletedCount: count }
            }, client);
            return count;
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
    if (!LEGACY_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const deleted = await pgAppointments.withTransaction(async (client) => {
            const removed = await pgAppointments.deleteAppointmentByPublicId(appointmentId, client);
            if (!removed) {
                return null;
            }
            await pgAppointments.createAuditLog({
                action: 'appointment_delete',
                result: 'success',
                targetType: 'appointment',
                targetId: appointmentId,
                actorUserPublicId: getUserPublicId(req.user) || req.user?._id || null,
                actorRole: req.user?.role || 'anonymous',
                ip: getClientIp(req),
                userAgent: getUserAgent(req),
                metadata: {
                    doctorId: removed.doctorId || null,
                    date: removed.date || null,
                    time: removed.time || null
                }
            }, client);
            return removed;
        });
        if (!deleted) {
            return res.status(404).json({ error: 'Programare negasita.' });
        }
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
        const deletedCount = await pgAppointments.withTransaction(async (client) => {
            const count = await pgAppointments.deleteAppointmentsByDate(date, client);
            await pgAppointments.createAuditLog({
                action: 'appointments_delete_by_date',
                result: 'success',
                targetType: 'appointment_collection',
                targetId: date,
                actorUserPublicId: getUserPublicId(req.user) || req.user?._id || null,
                actorRole: req.user?.role || 'anonymous',
                ip: getClientIp(req),
                userAgent: getUserAgent(req),
                metadata: { deletedCount: count }
            }, client);
            return count;
        });
        return res.json({
            success: true,
            deletedCount,
            message: `Au fost anulate ${deletedCount} programari pentru data ${date}.`
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
        const appointments = await pgAppointments.listAppointments();

        const metadataRows = [{
            NOTICE: 'CONFIDENTIAL - authorized superadmin use only',
            GeneratedAt: new Date().toISOString(),
            GeneratedBy: req.user?.email || 'unknown',
            Records: appointments.length
        }];

        const data = appointments.map((a) => ({
            Medic: a.doctorSnapshotName || '',
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
        return res.status(500).json({ error: 'Eroare la generarea Excel.' });
    }
});

// =====================
//  DOCTOR MANAGEMENT
// =====================

app.get('/api/admin/doctors', requireViewerSchedulerOrSuperadmin, async (req, res) => {
    setAuthNoStore(res);

    try {
        let doctors;
        if (isSuperadminUser(req.user)) {
            doctors = await pgDoctors.listDoctors({ isActive: null });
        } else {
            const scopedDoctorIds = getUserManagedDoctorIds(req.user);
            if (scopedDoctorIds.length === 0) {
                return res.status(403).json({ error: 'Nu aveti niciun medic asignat.' });
            }
            doctors = await pgDoctors.listDoctors({ legacyIds: scopedDoctorIds, isActive: null });
        }

        await writeAuditLog(req, {
            action: 'doctor_list_view',
            result: 'success',
            targetType: 'doctor_collection',
            actorUser: req.user,
            metadata: { count: doctors.length }
        });
        return res.json(doctors.map((doctor) => sanitizeDoctorForAdmin(doctor, { includeAudit: isSuperadminUser(req.user) })));
    } catch (error) {
        console.error('Admin doctors list error:', error?.message || error);
        return res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/admin/doctors', requireSuperadminOnly, validateBody(doctorCreateBodySchema), async (req, res) => {
    setAuthNoStore(res);

    try {
        const payload = req.validatedBody;
        const doctor = await pgDoctors.createDoctor({
            slug: payload.slug,
            displayName: sanitizeInlineString(payload.displayName),
            specialty: sanitizeInlineString(payload.specialty),
            isActive: !!payload.isActive,
            bookingSettings: payload.bookingSettings,
            availabilityRules: payload.availabilityRules,
            blockedDates: payload.blockedDates,
            createdByUserPublicId: getUserPublicId(req.user) || req.user?._id || null,
            updatedByUserPublicId: getUserPublicId(req.user) || req.user?._id || null
        });

        await writeAuditLog(req, {
            action: 'doctor_create',
            result: 'success',
            targetType: 'doctor',
            targetId: String(doctor._id),
            actorUser: req.user,
            metadata: { slug: doctor.slug }
        });
        return res.status(201).json({ success: true, doctor: sanitizeDoctorForAdmin(doctor, { includeAudit: true }) });
    } catch (error) {
        await writeAuditLog(req, {
            action: 'doctor_create',
            result: 'failure',
            targetType: 'doctor',
            actorUser: req.user
        });
        if (pgDoctors.isUniqueViolation(error)) {
            return res.status(409).json({ error: 'Slug-ul medicului exista deja.' });
        }
        return res.status(500).json({ error: 'Eroare la crearea medicului.' });
    }
});

app.patch('/api/admin/doctors/:id', requireSchedulerOrSuperadmin, validateBody(doctorPatchBodySchema), async (req, res) => {
    setAuthNoStore(res);

    const doctorId = String(req.params.id || '').trim();
    if (!LEGACY_OBJECT_ID_REGEX.test(doctorId)) {
        return res.status(400).json({ error: 'Medic invalid.' });
    }
    if (!isSuperadminUser(req.user) && !canUserAccessDoctor(req.user, doctorId)) {
        return res.status(403).json({ error: 'Acces interzis pentru acest medic.' });
    }

    try {
        const updates = req.validatedBody;
        const updateDoc = {};
        if (updates.slug !== undefined) updateDoc.slug = updates.slug;
        if (updates.displayName !== undefined) updateDoc.displayName = sanitizeInlineString(updates.displayName);
        if (updates.specialty !== undefined) updateDoc.specialty = sanitizeInlineString(updates.specialty);
        if (updates.isActive !== undefined) updateDoc.isActive = updates.isActive;
        if (updates.bookingSettings !== undefined) updateDoc.bookingSettings = updates.bookingSettings;
        if (updates.availabilityRules !== undefined) updateDoc.availabilityRules = updates.availabilityRules;
        if (updates.blockedDates !== undefined) updateDoc.blockedDates = updates.blockedDates;
        updateDoc.updatedByUserPublicId = getUserPublicId(req.user) || req.user?._id || null;

        const doctor = await pgDoctors.updateDoctorByLegacyId(doctorId, updateDoc);
        if (!doctor) {
            return res.status(404).json({ error: 'Medic negasit.' });
        }

        await pgAppointments.updateDoctorSnapshotNameByDoctorLegacyId(doctor._id, doctor.displayName);

        await writeAuditLog(req, {
            action: 'doctor_update',
            result: 'success',
            targetType: 'doctor',
            targetId: doctorId,
            actorUser: req.user,
            metadata: { fields: Object.keys(updates || {}) }
        });
        return res.json({ success: true, doctor: sanitizeDoctorForAdmin(doctor, { includeAudit: true }) });
    } catch (error) {
        await writeAuditLog(req, {
            action: 'doctor_update',
            result: 'failure',
            targetType: 'doctor',
            targetId: doctorId,
            actorUser: req.user
        });
        if (pgDoctors.isUniqueViolation(error)) {
            return res.status(409).json({ error: 'Slug-ul medicului exista deja.' });
        }
        return res.status(500).json({ error: 'Eroare la actualizarea medicului.' });
    }
});

app.delete('/api/admin/doctors/:id', requireSuperadminOnly, requireStepUp('doctor_delete'), async (req, res) => {
    setAuthNoStore(res);

    const doctorId = String(req.params.id || '').trim();
    if (!LEGACY_OBJECT_ID_REGEX.test(doctorId)) {
        return res.status(400).json({ error: 'Medic invalid.' });
    }

    try {
        const deletedDoctor = await pgDoctors.deleteDoctorByLegacyId(
            doctorId,
            { actorUserPublicId: getUserPublicId(req.user) || req.user?._id || null }
        );
        if (!deletedDoctor) {
            return res.status(404).json({ error: 'Medic negasit.' });
        }

        await writeAuditLog(req, {
            action: 'doctor_delete_hard',
            result: 'success',
            targetType: 'doctor',
            targetId: doctorId,
            actorUser: req.user,
            metadata: {
                deletedAppointments: Number(deletedDoctor.deletedAppointments || 0)
            }
        });

        return res.json({
            success: true,
            message: 'Medicul a fost sters definitiv.',
            deletedDoctor: {
                _id: deletedDoctor._id,
                slug: deletedDoctor.slug,
                displayName: deletedDoctor.displayName
            },
            deletedAppointments: Number(deletedDoctor.deletedAppointments || 0)
        });
    } catch (_) {
        await writeAuditLog(req, {
            action: 'doctor_delete_hard',
            result: 'failure',
            targetType: 'doctor',
            targetId: doctorId,
            actorUser: req.user
        });
        return res.status(500).json({ error: 'Eroare la stergerea medicului.' });
    }
});

app.get('/api/admin/doctors/:id/day-schedule/:date', requireSchedulerOrSuperadmin, async (req, res) => {
    setAuthNoStore(res);

    const doctorId = String(req.params.id || '').trim();
    if (!LEGACY_OBJECT_ID_REGEX.test(doctorId)) {
        return res.status(400).json({ error: 'Medic invalid.' });
    }
    if (!isSuperadminUser(req.user) && !canUserAccessDoctor(req.user, doctorId)) {
        return res.status(403).json({ error: 'Acces interzis pentru acest medic.' });
    }

    const rawDate = String(req.params.date || '').trim();
    if (!isValidISODateString(rawDate)) {
        return res.status(400).json({ error: 'Data invalida.' });
    }

    try {
        const doctor = await resolveDoctorByIdentifier(doctorId, { requireActive: false });
        if (!doctor) {
            return res.status(404).json({ error: 'Medic negasit.' });
        }

        const daySchedule = await pgDoctors.getDoctorDayScheduleByLegacyId(doctorId, rawDate);
        if (!daySchedule) {
            return res.status(404).json({ error: 'Programul zilei nu a putut fi incarcat.' });
        }

        const bookedTimes = await pgAppointments.listBookedTimesByDoctorDate(doctorId, rawDate);
        const slots = daySchedule.rule
            ? generateSlotsForWindow(
                daySchedule.rule.startTime,
                daySchedule.rule.endTime,
                daySchedule.rule.consultationDurationMinutes
            )
            : [];

        return res.json({
            success: true,
            doctor: sanitizeDoctorForAdmin(doctor, { includeAudit: isSuperadminUser(req.user) }),
            date: rawDate,
            daySchedule: {
                weekday: daySchedule.weekday,
                blocked: !!daySchedule.blocked,
                hasAvailability: !!daySchedule.hasAvailability,
                rule: daySchedule.rule || null,
                overrideRule: daySchedule.overrideRule || null,
                defaultRule: daySchedule.defaultRule || null,
                slots,
                bookedTimes
            }
        });
    } catch (_) {
        return res.status(500).json({ error: 'Eroare la incarcarea programului zilei.' });
    }
});

app.patch('/api/admin/doctors/:id/day-schedule/:date', requireSchedulerOrSuperadmin, validateBody(doctorDayScheduleBodySchema), async (req, res) => {
    setAuthNoStore(res);

    const doctorId = String(req.params.id || '').trim();
    if (!LEGACY_OBJECT_ID_REGEX.test(doctorId)) {
        return res.status(400).json({ error: 'Medic invalid.' });
    }
    if (!isSuperadminUser(req.user) && !canUserAccessDoctor(req.user, doctorId)) {
        return res.status(403).json({ error: 'Acces interzis pentru acest medic.' });
    }

    const rawDate = String(req.params.date || '').trim();
    if (!isValidISODateString(rawDate)) {
        return res.status(400).json({ error: 'Data invalida.' });
    }

    try {
        const doctor = await resolveDoctorByIdentifier(doctorId, { requireActive: false });
        if (!doctor) {
            return res.status(404).json({ error: 'Medic negasit.' });
        }

        if (!isDateInDoctorRange(rawDate, doctor.bookingSettings?.monthsToShow)) {
            return res.status(400).json({ error: 'Data este in afara intervalului configurat pentru acest medic.' });
        }

        const payload = req.validatedBody;
        const actorUserPublicId = getUserPublicId(req.user) || req.user?._id || null;

        if (payload.status === 'blocked') {
            if (payload.clearOverride) {
                await pgDoctors.removeDoctorDayOverrideByLegacyId(
                    doctorId,
                    rawDate,
                    { actorUserPublicId }
                );
            }
            await pgDoctors.blockDoctorDateByLegacyId(
                doctorId,
                rawDate,
                { actorUserPublicId }
            );
        } else {
            if (payload.clearOverride) {
                const currentDaySchedule = await pgDoctors.getDoctorDayScheduleByLegacyId(doctorId, rawDate);
                const defaultRule = currentDaySchedule?.defaultRule;
                if (!defaultRule) {
                    return res.status(400).json({ error: 'Nu exista program standard pentru aceasta zi.' });
                }
                const bookedTimes = await pgAppointments.listBookedTimesByDoctorDate(doctorId, rawDate);
                const allowedSlots = generateSlotsForWindow(
                    defaultRule.startTime,
                    defaultRule.endTime,
                    defaultRule.consultationDurationMinutes
                );
                const invalidBookedTimes = bookedTimes.filter((time) => !allowedSlots.includes(time));
                if (invalidBookedTimes.length > 0) {
                    return res.status(409).json({
                        error: 'Revenirea la programul standard invalideaza programari existente.',
                        conflictTimes: invalidBookedTimes
                    });
                }

                await pgDoctors.removeDoctorDayOverrideByLegacyId(
                    doctorId,
                    rawDate,
                    { actorUserPublicId }
                );
            } else {
                const bookedTimes = await pgAppointments.listBookedTimesByDoctorDate(doctorId, rawDate);
                const allowedSlots = generateSlotsForWindow(
                    payload.startTime,
                    payload.endTime,
                    payload.consultationDurationMinutes
                );
                const invalidBookedTimes = bookedTimes.filter((time) => !allowedSlots.includes(time));
                if (invalidBookedTimes.length > 0) {
                    return res.status(409).json({
                        error: 'Modificarea invalideaza programari existente. Ajustati intervalul sau durata.',
                        conflictTimes: invalidBookedTimes
                    });
                }

                await pgDoctors.upsertDoctorDayOverrideByLegacyId(
                    doctorId,
                    rawDate,
                    {
                        startTime: payload.startTime,
                        endTime: payload.endTime,
                        consultationDurationMinutes: payload.consultationDurationMinutes,
                        actorUserPublicId
                    }
                );
            }

            await pgDoctors.unblockDoctorDateByLegacyId(
                doctorId,
                rawDate,
                { actorUserPublicId }
            );
        }

        const updatedDaySchedule = await pgDoctors.getDoctorDayScheduleByLegacyId(doctorId, rawDate);
        const refreshedDoctor = await resolveDoctorByIdentifier(doctorId, { requireActive: false });
        const bookedTimes = await pgAppointments.listBookedTimesByDoctorDate(doctorId, rawDate);
        const slots = updatedDaySchedule?.rule
            ? generateSlotsForWindow(
                updatedDaySchedule.rule.startTime,
                updatedDaySchedule.rule.endTime,
                updatedDaySchedule.rule.consultationDurationMinutes
            )
            : [];

        await writeAuditLog(req, {
            action: 'doctor_day_schedule_update',
            result: 'success',
            targetType: 'doctor',
            targetId: doctorId,
            actorUser: req.user,
            metadata: {
                date: rawDate,
                status: payload.status,
                clearOverride: !!payload.clearOverride
            }
        });

        return res.json({
            success: true,
            doctor: refreshedDoctor ? sanitizeDoctorForAdmin(refreshedDoctor, { includeAudit: isSuperadminUser(req.user) }) : null,
            date: rawDate,
            daySchedule: updatedDaySchedule
                ? {
                    weekday: updatedDaySchedule.weekday,
                    blocked: !!updatedDaySchedule.blocked,
                    hasAvailability: !!updatedDaySchedule.hasAvailability,
                    rule: updatedDaySchedule.rule || null,
                    overrideRule: updatedDaySchedule.overrideRule || null,
                    defaultRule: updatedDaySchedule.defaultRule || null,
                    slots,
                    bookedTimes
                }
                : null
        });
    } catch (error) {
        await writeAuditLog(req, {
            action: 'doctor_day_schedule_update',
            result: 'failure',
            targetType: 'doctor',
            targetId: doctorId,
            actorUser: req.user,
            metadata: { date: rawDate }
        });
        if (String(error?.message || '').includes('Invalid day override window')) {
            return res.status(400).json({ error: 'Intervalul zilei este invalid.' });
        }
        return res.status(500).json({ error: 'Eroare la actualizarea programului zilei.' });
    }
});

app.post('/api/admin/doctors/:id/block-date', requireSchedulerOrSuperadmin, validateBody(doctorBlockDateBodySchema), async (req, res) => {
    setAuthNoStore(res);

    const doctorId = String(req.params.id || '').trim();
    if (!LEGACY_OBJECT_ID_REGEX.test(doctorId)) {
        return res.status(400).json({ error: 'Medic invalid.' });
    }
    if (!isSuperadminUser(req.user) && !canUserAccessDoctor(req.user, doctorId)) {
        return res.status(403).json({ error: 'Acces interzis pentru acest medic.' });
    }

    try {
        const { date } = req.validatedBody;
        const doctor = await pgDoctors.blockDoctorDateByLegacyId(
            doctorId,
            date,
            { actorUserPublicId: getUserPublicId(req.user) || req.user?._id || null }
        );

        if (!doctor) {
            return res.status(404).json({ error: 'Medic negasit.' });
        }

        await writeAuditLog(req, {
            action: 'doctor_block_date',
            result: 'success',
            targetType: 'doctor',
            targetId: doctorId,
            actorUser: req.user,
            metadata: { date }
        });
        return res.json({ success: true, doctor: sanitizeDoctorForAdmin(doctor, { includeAudit: true }) });
    } catch (_) {
        return res.status(500).json({ error: 'Eroare la blocarea zilei.' });
    }
});

app.delete('/api/admin/doctors/:id/block-date/:date', requireSchedulerOrSuperadmin, async (req, res) => {
    setAuthNoStore(res);

    const doctorId = String(req.params.id || '').trim();
    if (!LEGACY_OBJECT_ID_REGEX.test(doctorId)) {
        return res.status(400).json({ error: 'Medic invalid.' });
    }
    if (!isSuperadminUser(req.user) && !canUserAccessDoctor(req.user, doctorId)) {
        return res.status(403).json({ error: 'Acces interzis pentru acest medic.' });
    }

    const rawDate = String(req.params.date || '').trim();
    if (!isValidISODateString(rawDate)) {
        return res.status(400).json({ error: 'Data invalida.' });
    }

    try {
        const doctor = await pgDoctors.unblockDoctorDateByLegacyId(
            doctorId,
            rawDate,
            { actorUserPublicId: getUserPublicId(req.user) || req.user?._id || null }
        );
        if (!doctor) {
            return res.status(404).json({ error: 'Medic negasit.' });
        }

        await writeAuditLog(req, {
            action: 'doctor_unblock_date',
            result: 'success',
            targetType: 'doctor',
            targetId: doctorId,
            actorUser: req.user,
            metadata: { date: rawDate }
        });

        return res.json({ success: true, doctor: sanitizeDoctorForAdmin(doctor, { includeAudit: true }) });
    } catch (_) {
        return res.status(500).json({ error: 'Eroare la reactivarea zilei.' });
    }
});

// =====================
//  USER MANAGEMENT (SUPER ADMIN)
// =====================

app.post('/api/admin/users', requireSuperadminOnly, validateBody(adminCreateUserBodySchema), async (req, res) => {
    setAuthNoStore(res);

    try {
        const { email, phone, password, displayName, role, managedDoctorIds } = req.validatedBody;

        if (!validatePhone(phone)) {
            return res.status(400).json({ error: 'Format telefon invalid. Folositi formatul 07xx xxx xxx.' });
        }

        const normalizedEmail = String(email).toLowerCase();
        const cleanedPhone = cleanPhone(phone);
        const normalizedDoctorIds = normalizeManagedDoctorIds(managedDoctorIds || []);
        const doctorIdsExist = await assertManagedDoctorsExist(normalizedDoctorIds);
        if (!doctorIdsExist) {
            return res.status(400).json({ error: 'Unul sau mai multi doctori asignati nu exista.' });
        }

        const existingEmail = await findUserByEmail(normalizedEmail);
        if (existingEmail) {
            return res.status(409).json({ error: 'Acest email este deja inregistrat.' });
        }

        const existingPhone = await findUserByPhone(cleanedPhone);
        if (existingPhone) {
            return res.status(409).json({ error: 'Acest numar de telefon este deja inregistrat.' });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const user = await pgUsers.withTransaction(async (client) => pgUsers.createUser({
            email: normalizedEmail,
            phone: cleanedPhone,
            passwordHash: hashedPassword,
            displayName: displayName.trim(),
            role,
            managedDoctorIds: normalizedDoctorIds
        }, client));

        const doctorsMap = await loadDoctorsMapByIds(normalizedDoctorIds);
        await writeAuditLog(req, {
            action: 'user_create',
            result: 'success',
            targetType: 'user',
            targetId: String(user._id),
            actorUser: req.user,
            metadata: { role, managedDoctorIds: normalizedDoctorIds }
        });

        return res.status(201).json({
            success: true,
            user: sanitizeUserForAdmin(user, doctorsMap)
        });
    } catch (error) {
        await writeAuditLog(req, {
            action: 'user_create',
            result: 'failure',
            targetType: 'user',
            actorUser: req.user
        });
        if (pgUsers.isUniqueViolation(error)) {
            return res.status(409).json({ error: 'Email sau telefon deja inregistrat.' });
        }
        return res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/users', requireSuperadminOnly, async (req, res) => {
    setAuthNoStore(res);

    try {
        const users = await pgUsers.listUsers();
        const allDoctorIds = users.flatMap((user) => normalizeManagedDoctorIds(user.managedDoctorIds));
        const doctorMap = await loadDoctorsMapByIds(allDoctorIds);
        const normalizedUsers = users.map((user) => sanitizeUserForAdmin(user, doctorMap));
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

        const user = await findUserById(userId);
        if (!user) {
            return res.status(404).json({ error: 'Utilizator negasit.' });
        }

        if (user.role === ROLE.SUPERADMIN) {
            return res.status(403).json({ error: 'Rolul de Super Admin nu poate fi schimbat.' });
        }

        const previousRole = user.role;
        user.role = role;
        await persistUser(user);

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

app.patch('/api/admin/users/:id', requireSuperadminOnly, requireStepUp('user_update'), validateBody(adminUpdateUserBodySchema), async (req, res) => {
    setAuthNoStore(res);

    const userId = String(req.params.id || '').trim();
    if (!isValidUserIdentifier(userId)) {
        return res.status(400).json({ error: 'Utilizator invalid.' });
    }

    try {
        const existingUser = await findUserById(userId);
        if (!existingUser) {
            return res.status(404).json({ error: 'Utilizator negasit.' });
        }

        const updates = req.validatedBody;
        const changedFields = [];

        if (updates.email !== undefined) {
            const normalizedEmail = updates.email.toLowerCase();
            const duplicate = await findUserByEmail(normalizedEmail);
            if (duplicate && String(duplicate._id) !== String(existingUser._id)) {
                return res.status(409).json({ error: 'Acest email este deja inregistrat.' });
            }
            existingUser.email = normalizedEmail;
            changedFields.push('email');
        }

        if (updates.phone !== undefined) {
            if (!validatePhone(updates.phone)) {
                return res.status(400).json({ error: 'Format telefon invalid.' });
            }
            const cleanedPhone = cleanPhone(updates.phone);
            const duplicatePhone = await findUserByPhone(cleanedPhone);
            if (duplicatePhone && String(duplicatePhone._id) !== String(existingUser._id)) {
                return res.status(409).json({ error: 'Acest numar de telefon este deja inregistrat.' });
            }
            existingUser.phone = cleanedPhone;
            changedFields.push('phone');
        }

        if (updates.displayName !== undefined) {
            existingUser.displayName = sanitizeInlineString(updates.displayName);
            changedFields.push('displayName');
        }

        if (updates.role !== undefined) {
            if (String(existingUser._id) === String(req.user._id) && updates.role !== ROLE.SUPERADMIN) {
                return res.status(403).json({ error: 'Nu va puteti schimba propriul rol din superadmin.' });
            }

            if (existingUser.role === ROLE.SUPERADMIN && updates.role !== ROLE.SUPERADMIN) {
                const superadminCount = await pgUsers.countUsersByRole(ROLE.SUPERADMIN);
                if (superadminCount <= 1) {
                    return res.status(403).json({ error: 'Nu puteti retrograda ultimul superadmin.' });
                }
            }

            existingUser.role = updates.role;
            changedFields.push('role');
        }

        if (updates.password !== undefined) {
            existingUser.password = await bcrypt.hash(updates.password, SALT_ROUNDS);
            changedFields.push('password');
        }

        if (updates.managedDoctorIds !== undefined) {
            const normalizedDoctorIds = normalizeManagedDoctorIds(updates.managedDoctorIds);
            const exists = await assertManagedDoctorsExist(normalizedDoctorIds);
            if (!exists) {
                return res.status(400).json({ error: 'Unul sau mai multi doctori asignati nu exista.' });
            }
            existingUser.managedDoctorIds = normalizedDoctorIds;
            changedFields.push('managedDoctorIds');
        }

        if (changedFields.length === 0) {
            return res.status(400).json({ error: 'Nicio schimbare valida.' });
        }

        const savedUser = await persistUser(existingUser, { managedDoctorIdsChanged: changedFields.includes('managedDoctorIds') });
        const doctorsMap = await loadDoctorsMapByIds(savedUser.managedDoctorIds);

        await writeAuditLog(req, {
            action: 'user_update',
            result: 'success',
            targetType: 'user',
            targetId: String(savedUser._id),
            actorUser: req.user,
            metadata: { changedFields }
        });

        return res.json({
            success: true,
            user: sanitizeUserForAdmin(savedUser, doctorsMap)
        });
    } catch (error) {
        await writeAuditLog(req, {
            action: 'user_update',
            result: 'failure',
            targetType: 'user',
            targetId: userId,
            actorUser: req.user
        });
        if (pgUsers.isUniqueViolation(error)) {
            return res.status(409).json({ error: 'Email sau telefon deja inregistrat.' });
        }
        return res.status(500).json({ error: 'Database error' });
    }
});

app.delete('/api/admin/users/:id', requireSuperadminOnly, requireStepUp('user_delete'), async (req, res) => {
    setAuthNoStore(res);

    const userId = String(req.params.id || '').trim();
    if (!isValidUserIdentifier(userId)) {
        return res.status(400).json({ error: 'Utilizator invalid.' });
    }

    if (String(userId) === String(req.user._id)) {
        return res.status(403).json({ error: 'Nu va puteti sterge propriul cont.' });
    }

    try {
        const target = await findUserById(userId);
        if (!target) {
            return res.status(404).json({ error: 'Utilizator negasit.' });
        }

        if (target.role === ROLE.SUPERADMIN) {
            const superadminCount = await pgUsers.countUsersByRole(ROLE.SUPERADMIN);
            if (superadminCount <= 1) {
                return res.status(403).json({ error: 'Nu puteti sterge ultimul superadmin.' });
            }
        }

        await pgUsers.deleteUserByPublicId(target._id);
        await writeAuditLog(req, {
            action: 'user_delete',
            result: 'success',
            targetType: 'user',
            targetId: String(target._id),
            actorUser: req.user
        });

        return res.json({ success: true, message: 'Utilizator sters.' });
    } catch (_) {
        await writeAuditLog(req, {
            action: 'user_delete',
            result: 'failure',
            targetType: 'user',
            targetId: userId,
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

async function validatePostgresStartupHealth() {
    const health = await runPostgresHealthCheck();

    console.log(
        `[POSTGRES] Startup health check OK `
        + `(target=${health.target}, latencyMs=${health.latencyMs}).`
    );
}

async function bootstrapServer() {
    try {
        await validatePostgresStartupHealth();
        const superadminBootstrap = await ensureBootstrapSuperadmin();
        if (superadminBootstrap?.skipped) {
            console.log(`[AUTH] Superadmin bootstrap skipped: ${superadminBootstrap.reason}.`);
        }
        const migrationSummary = await ensureDefaultDoctorAndBackfill();
        console.log('Startup migration summary:', migrationSummary);
    } catch (error) {
        console.error(`[BOOTSTRAP] Startup initialization failed: ${redactPostgresUrlInText(error?.message || String(error))}`);
        process.exit(1);
    }

    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT} (postgres-only mode)`);
    });
}

bootstrapServer().catch((error) => {
    console.error(`Server bootstrap failed: ${redactPostgresUrlInText(error?.message || String(error))}`);
    process.exit(1);
});
