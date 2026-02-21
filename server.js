require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
const { validateBaseEnv, normalizeDbProvider, isPostgresProvider } = require('./scripts/env-utils');
const { runPostgresHealthCheck, redactPostgresUrlInText } = require('./db/postgres');
const pgUsers = require('./db/users-postgres');
const pgDoctors = require('./db/doctors-postgres');
const pgAppointments = require('./db/appointments-postgres');
const {
    buildMongoTlsPolicy,
    buildMongoDriverTlsOptions,
    getSafeMongoErrorSummary,
    isLikelyTlsCompatibilityError,
    FALLBACK_MONGO_TLS_MIN_VERSION
} = require('./utils/mongo-tls-config');

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
const TIME_HHMM_REGEX = /^([01]\d|2[0-3]):([0-5]\d)$/;
const DEFAULT_DOCTOR_SLUG = 'prof-dr-balta-florian';
const DEFAULT_DOCTOR_DISPLAY_NAME = 'Prof. Dr. Balta Florian';
const DEFAULT_DOCTOR_SPECIALTY = 'Oftalmologie';
const DEFAULT_BOOKING_SETTINGS = Object.freeze({
    consultationDurationMinutes: 20,
    workdayStart: '09:00',
    workdayEnd: '14:00',
    monthsToShow: 3,
    timezone: 'Europe/Bucharest'
});
const DEFAULT_AVAILABILITY_WEEKDAYS = Object.freeze([3]);

const mongoTlsPolicy = buildMongoTlsPolicy(process.env);
const baseEnvValidation = validateBaseEnv(process.env);
const DB_PROVIDER = baseEnvValidation.parsed.dbProvider || normalizeDbProvider(process.env.DB_PROVIDER) || 'mongo';
const POSTGRES_ENABLED = isPostgresProvider(DB_PROVIDER);
const USERS_IN_POSTGRES = POSTGRES_ENABLED;
const DOCTORS_IN_POSTGRES = POSTGRES_ENABLED;
const APPOINTMENTS_IN_POSTGRES = POSTGRES_ENABLED;
const AUDIT_IN_POSTGRES = POSTGRES_ENABLED;
const DUAL_MONGO_USER_FALLBACK = DB_PROVIDER === 'dual';
const DUAL_MONGO_DOCTOR_FALLBACK = DB_PROVIDER === 'dual';
const DUAL_MONGO_APPOINTMENT_FALLBACK = DB_PROVIDER === 'dual';
const startupValidationErrors = Array.from(new Set([
    ...baseEnvValidation.errors,
    ...mongoTlsPolicy.validationErrors
]));
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
const MONGODB_URI = mongoTlsPolicy.mongodbUri;
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
let mongoBootstrapPromise = null;
let mongoBootstrapped = false;
const MONGOOSE_READY_STATE_LABELS = Object.freeze({
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
});
const mongoTlsRuntime = {
    fallbackToTls12Used: false,
    effectiveMinVersion: mongoTlsPolicy.configuredMinVersion,
    lastConnectionError: null
};

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
    managedDoctorIds: { type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' }], default: () => [] },
    createdAt: { type: Date, default: Date.now }
}, { strict: 'throw' });

const User = mongoose.model('User', userSchema);

const doctorSchema = new mongoose.Schema({
    slug: { type: String, required: true, unique: true, lowercase: true, trim: true },
    displayName: { type: String, required: true, trim: true },
    specialty: { type: String, default: DEFAULT_DOCTOR_SPECIALTY, trim: true },
    isActive: { type: Boolean, default: true },
    bookingSettings: {
        consultationDurationMinutes: { type: Number, default: DEFAULT_BOOKING_SETTINGS.consultationDurationMinutes },
        workdayStart: { type: String, default: DEFAULT_BOOKING_SETTINGS.workdayStart },
        workdayEnd: { type: String, default: DEFAULT_BOOKING_SETTINGS.workdayEnd },
        monthsToShow: { type: Number, default: DEFAULT_BOOKING_SETTINGS.monthsToShow },
        timezone: { type: String, default: DEFAULT_BOOKING_SETTINGS.timezone, trim: true }
    },
    availabilityRules: {
        weekdays: { type: [Number], default: () => [...DEFAULT_AVAILABILITY_WEEKDAYS] }
    },
    blockedDates: { type: [String], default: () => [] },
    createdByUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    updatedByUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }
}, { strict: 'throw', timestamps: true });

doctorSchema.path('slug').validate((value) => /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(String(value || '')), 'Doctor slug format is invalid.');
doctorSchema.path('bookingSettings.consultationDurationMinutes').validate((value) => Number.isInteger(value) && value >= 5 && value <= 120, 'Invalid consultation duration.');
doctorSchema.path('bookingSettings.workdayStart').validate((value) => isValidHHMM(value), 'Invalid workdayStart.');
doctorSchema.path('bookingSettings.workdayEnd').validate((value) => isValidHHMM(value), 'Invalid workdayEnd.');
doctorSchema.path('bookingSettings.monthsToShow').validate((value) => Number.isInteger(value) && value >= 1 && value <= 12, 'Invalid monthsToShow.');
doctorSchema.path('availabilityRules.weekdays').validate((value) => isValidWeekdayList(value), 'Invalid availability weekdays.');
doctorSchema.path('blockedDates').validate((value) => {
    if (!Array.isArray(value)) return false;
    const seen = new Set();
    for (const item of value) {
        if (typeof item !== 'string') return false;
        if (!/^\d{4}-\d{2}-\d{2}$/.test(item)) return false;
        if (seen.has(item)) return false;
        seen.add(item);
    }
    return true;
}, 'Invalid blockedDates.');
doctorSchema.pre('validate', function doctorValidate(next) {
    const start = parseHHMMToMinutes(this.bookingSettings?.workdayStart);
    const end = parseHHMMToMinutes(this.bookingSettings?.workdayEnd);
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
        return next(new Error('Doctor workday interval is invalid.'));
    }
    return next();
});

const Doctor = mongoose.model('Doctor', doctorSchema);

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
    doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true },
    doctorSnapshotName: { type: String, default: '' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    createdAt: { type: Date, default: Date.now }
}, { strict: 'throw' });
appointmentSchema.index({ doctorId: 1, date: 1, time: 1 }, { unique: true });

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

const charsetProbeSchema = new mongoose.Schema({
    text: { type: String, required: true, trim: false },
    createdAt: { type: Date, default: Date.now }
}, { strict: 'throw' });
charsetProbeSchema.index({ createdAt: -1 });

const CharsetProbe = mongoose.model('CharsetProbe', charsetProbeSchema);

async function ensureDefaultDoctorAndBackfill() {
    if (DOCTORS_IN_POSTGRES && DUAL_MONGO_DOCTOR_FALLBACK) {
        const mongoDoctors = await Doctor.find().lean();
        for (const mongoDoctor of mongoDoctors) {
            await migrateMongoDoctorToPostgres(mongoDoctor);
        }
    }

    let defaultDoctor;
    if (DOCTORS_IN_POSTGRES) {
        defaultDoctor = await pgDoctors.findDoctorByIdentifier(DEFAULT_DOCTOR_SLUG, { requireActive: false });
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
    } else {
        defaultDoctor = await Doctor.findOneAndUpdate(
            { slug: DEFAULT_DOCTOR_SLUG },
            {
                $setOnInsert: {
                    slug: DEFAULT_DOCTOR_SLUG,
                    displayName: DEFAULT_DOCTOR_DISPLAY_NAME,
                    specialty: DEFAULT_DOCTOR_SPECIALTY,
                    isActive: true,
                    bookingSettings: {
                        consultationDurationMinutes: DEFAULT_BOOKING_SETTINGS.consultationDurationMinutes,
                        workdayStart: DEFAULT_BOOKING_SETTINGS.workdayStart,
                        workdayEnd: DEFAULT_BOOKING_SETTINGS.workdayEnd,
                        monthsToShow: DEFAULT_BOOKING_SETTINGS.monthsToShow,
                        timezone: DEFAULT_BOOKING_SETTINGS.timezone
                    },
                    availabilityRules: { weekdays: DEFAULT_AVAILABILITY_WEEKDAYS },
                    blockedDates: [],
                    createdByUserId: null,
                    updatedByUserId: null
                }
            },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );
    }

    let appointmentsBackfillCount = 0;
    let snapshotsBackfillCount = 0;
    let appointmentsMigratedCount = 0;
    if (!APPOINTMENTS_IN_POSTGRES || DUAL_MONGO_APPOINTMENT_FALLBACK) {
        const appointmentsBackfill = await Appointment.updateMany(
            {
                $or: [
                    { doctorId: { $exists: false } },
                    { doctorId: null }
                ]
            },
            {
                $set: {
                    doctorId: defaultDoctor._id,
                    doctorSnapshotName: defaultDoctor.displayName
                }
            }
        );
        appointmentsBackfillCount = appointmentsBackfill.modifiedCount || 0;

        const snapshotBackfill = await Appointment.updateMany(
            { doctorSnapshotName: { $in: [null, ''] }, doctorId: { $exists: true, $ne: null } },
            { $set: { doctorSnapshotName: defaultDoctor.displayName } }
        );
        snapshotsBackfillCount = snapshotBackfill.modifiedCount || 0;
    }

    if (APPOINTMENTS_IN_POSTGRES && DUAL_MONGO_APPOINTMENT_FALLBACK) {
        const mongoAppointments = await Appointment.find().lean();
        for (const mongoAppointment of mongoAppointments) {
            const migrated = await migrateMongoAppointmentToPostgres(mongoAppointment, { defaultDoctorId: defaultDoctor._id });
            if (migrated) {
                appointmentsMigratedCount += 1;
            }
        }
    }

    let usersBackfillCount = 0;
    if (!USERS_IN_POSTGRES) {
        const usersBackfill = await User.updateMany(
            { managedDoctorIds: { $exists: false } },
            { $set: { managedDoctorIds: [] } }
        );
        usersBackfillCount = usersBackfill.modifiedCount || 0;
    }

    return {
        defaultDoctorId: String(defaultDoctor._id),
        appointmentsBackfilled: appointmentsBackfillCount,
        snapshotsBackfilled: snapshotsBackfillCount,
        appointmentsMigratedToPostgres: appointmentsMigratedCount,
        usersBackfilled: usersBackfillCount
    };
}

function getMongoConnectionStateLabel() {
    return MONGOOSE_READY_STATE_LABELS[mongoose.connection.readyState] || 'unknown';
}

function getMongoTlsDiagnosticsSnapshot() {
    return {
        connectionState: getMongoConnectionStateLabel(),
        tlsRequired: true,
        configuredMinVersion: mongoTlsPolicy.configuredMinVersion,
        effectiveMinVersion: mongoTlsRuntime.effectiveMinVersion,
        fallbackToTls12Used: mongoTlsRuntime.fallbackToTls12Used,
        allowFallbackToTls12: mongoTlsPolicy.allowFallbackTo12,
        uriScheme: mongoTlsPolicy.uriScheme,
        hostCount: mongoTlsPolicy.hostCount,
        redactedHosts: mongoTlsPolicy.redactedHosts,
        tlsCAFileConfigured: mongoTlsPolicy.tlsCAFileConfigured,
        tlsCertificateKeyFileConfigured: mongoTlsPolicy.tlsCertificateKeyFileConfigured,
        tlsCertificateKeyPasswordConfigured: mongoTlsPolicy.tlsCertificateKeyPasswordConfigured,
        lastConnectionError: mongoTlsRuntime.lastConnectionError,
        nodeVersion: process.version
    };
}

function formatSafeMongoError(error) {
    const summary = getSafeMongoErrorSummary(error);
    const codePart = summary.code ? ` code=${summary.code}` : '';
    return `${summary.name}${codePart}: ${summary.message}`;
}

async function connectMongoWithTlsPolicy() {
    const primaryMinVersion = mongoTlsPolicy.configuredMinVersion;
    const primaryOptions = buildMongoDriverTlsOptions(mongoTlsPolicy, primaryMinVersion);

    try {
        await mongoose.connect(MONGODB_URI, primaryOptions);
        mongoTlsRuntime.effectiveMinVersion = primaryMinVersion;
        mongoTlsRuntime.fallbackToTls12Used = false;
        mongoTlsRuntime.lastConnectionError = null;
        return;
    } catch (primaryError) {
        const tlsCompatibilityError = isLikelyTlsCompatibilityError(primaryError);
        const fallbackEnabled = mongoTlsPolicy.allowFallbackTo12;
        const canFallbackTo12 = primaryMinVersion !== FALLBACK_MONGO_TLS_MIN_VERSION;

        if (tlsCompatibilityError && !fallbackEnabled && canFallbackTo12) {
            const compatibilityError = new Error(
                `MongoDB TLS compatibility failure while enforcing ${primaryMinVersion}. `
                + 'Fallback to TLSv1.2 is disabled. Set MONGO_TLS_ALLOW_FALLBACK_TO_1_2=true '
                + 'to retry with TLSv1.2.'
            );
            compatibilityError.cause = primaryError;
            throw compatibilityError;
        }

        if (!(tlsCompatibilityError && fallbackEnabled && canFallbackTo12)) {
            throw primaryError;
        }

        console.warn(
            `[HIGH][MONGO_TLS] TLS compatibility issue detected. `
            + `Retrying once with ${FALLBACK_MONGO_TLS_MIN_VERSION} because `
            + 'MONGO_TLS_ALLOW_FALLBACK_TO_1_2=true.'
        );
        console.warn(`[HIGH][MONGO_TLS] Primary connection error: ${formatSafeMongoError(primaryError)}`);

        await mongoose.disconnect().catch(() => {});

        try {
            await mongoose.connect(
                MONGODB_URI,
                buildMongoDriverTlsOptions(mongoTlsPolicy, FALLBACK_MONGO_TLS_MIN_VERSION)
            );
            mongoTlsRuntime.fallbackToTls12Used = true;
            mongoTlsRuntime.effectiveMinVersion = FALLBACK_MONGO_TLS_MIN_VERSION;
            mongoTlsRuntime.lastConnectionError = null;
        } catch (fallbackError) {
            const fallbackSummary = formatSafeMongoError(fallbackError);
            const fallbackFailure = new Error(
                `MongoDB connection failed after fallback to ${FALLBACK_MONGO_TLS_MIN_VERSION}. `
                + `Reason: ${fallbackSummary}`
            );
            fallbackFailure.cause = fallbackError;
            throw fallbackFailure;
        }
    }
}

async function ensureMongoReady() {
    if (mongoBootstrapped && mongoose.connection.readyState === 1) {
        return;
    }

    if (!mongoBootstrapPromise) {
        mongoBootstrapPromise = connectMongoWithTlsPolicy()
            .then(async () => {
                if (!mongoBootstrapped) {
                    const migrationSummary = await ensureDefaultDoctorAndBackfill();
                    if (!DOCTORS_IN_POSTGRES) {
                        await Doctor.syncIndexes();
                    }
                    if (!USERS_IN_POSTGRES) {
                        await User.syncIndexes();
                    }
                    if (!APPOINTMENTS_IN_POSTGRES) {
                        await Appointment.syncIndexes();
                    }
                    mongoBootstrapped = true;
                    const tlsDiagnostics = getMongoTlsDiagnosticsSnapshot();
                    console.log(
                        `[MONGO_TLS] Connected to MongoDB `
                        + `(state=${tlsDiagnostics.connectionState}, `
                        + `tlsRequired=${tlsDiagnostics.tlsRequired}, `
                        + `configuredMinVersion=${tlsDiagnostics.configuredMinVersion}, `
                        + `effectiveMinVersion=${tlsDiagnostics.effectiveMinVersion}, `
                        + `fallbackToTls12Used=${tlsDiagnostics.fallbackToTls12Used}, `
                        + `uriScheme=${tlsDiagnostics.uriScheme}, `
                        + `hosts=${tlsDiagnostics.hostCount}, `
                        + `node=${tlsDiagnostics.nodeVersion})`
                    );
                    console.log('Startup migration summary:', migrationSummary);
                }
            })
            .catch((error) => {
                mongoBootstrapPromise = null;
                mongoTlsRuntime.lastConnectionError = getSafeMongoErrorSummary(error);
                throw error;
            });
    }

    await mongoBootstrapPromise;
}

ensureMongoReady().catch((err) => {
    console.error(`MongoDB connection error: ${formatSafeMongoError(err)}`);
});

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
app.use(['/api', '/debug'], async (req, res, next) => {
    try {
        await ensureMongoReady();
        return next();
    } catch (error) {
        console.error(`MongoDB unavailable for request: ${formatSafeMongoError(error)}`);
        return res.status(503).json({ error: 'Database unavailable. Please retry shortly.' });
    }
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
const MONGODB_OBJECT_ID_REGEX = /^[a-fA-F0-9]{24}$/;
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
    if (!MONGODB_OBJECT_ID_REGEX.test(idValue)) {
        throw new Error(`${fieldName} is invalid.`);
    }
    return idValue;
}

function isValidUserIdentifier(value) {
    const normalized = String(value || '').trim();
    return MONGODB_OBJECT_ID_REGEX.test(normalized) || POSTGRES_UUID_REGEX.test(normalized);
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

function parseDoctorBookingSettings(value, { optional = false } = {}) {
    if (value === undefined && optional) return undefined;
    const payload = ensureObjectStrict(value, ['consultationDurationMinutes', 'workdayStart', 'workdayEnd', 'monthsToShow', 'timezone']);
    const consultationDurationMinutes = parseConsultationDurationField(payload.consultationDurationMinutes, 'bookingSettings.consultationDurationMinutes');
    const workdayStart = parseTimeField(payload.workdayStart, 'bookingSettings.workdayStart');
    const workdayEnd = parseTimeField(payload.workdayEnd, 'bookingSettings.workdayEnd');
    const monthsToShow = parseMonthsToShowField(payload.monthsToShow, 'bookingSettings.monthsToShow');
    const timezone = parseStringField(payload.timezone, 'bookingSettings.timezone', { min: 3, max: 64 });

    const startMinutes = parseHHMMToMinutes(workdayStart);
    const endMinutes = parseHHMMToMinutes(workdayEnd);
    if (!Number.isFinite(startMinutes) || !Number.isFinite(endMinutes) || endMinutes <= startMinutes) {
        throw new Error('bookingSettings workday interval is invalid.');
    }
    if ((endMinutes - startMinutes) < consultationDurationMinutes) {
        throw new Error('bookingSettings interval is shorter than consultation duration.');
    }

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
    const payload = ensureObjectStrict(value, ['weekdays']);
    return {
        weekdays: parseWeekdaysField(payload.weekdays, 'availabilityRules.weekdays')
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
        if (!MONGODB_OBJECT_ID_REGEX.test(id)) continue;
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

function getMongoCompatibleUserId(user) {
    const candidates = [
        user?.legacyMongoId,
        user?._id,
        user?.id
    ];
    for (const candidate of candidates) {
        const value = String(candidate || '').trim();
        if (MONGODB_OBJECT_ID_REGEX.test(value)) {
            return value;
        }
    }
    return null;
}

async function migrateMongoUserToPostgres(mongoUser) {
    if (!USERS_IN_POSTGRES || !mongoUser) {
        return mongoUser || null;
    }

    const managedDoctorIds = normalizeManagedDoctorIds(mongoUser.managedDoctorIds || []);
    return pgUsers.upsertUserFromMongo({
        _id: String(mongoUser._id),
        email: mongoUser.email || null,
        phone: mongoUser.phone || null,
        password: mongoUser.password || '',
        googleId: mongoUser.googleId || null,
        displayName: mongoUser.displayName || '',
        role: normalizeRoleValue(mongoUser.role),
        managedDoctorIds,
        createdAt: mongoUser.createdAt || new Date()
    });
}

async function findUserById(userId, { allowDualFallback = true } = {}) {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) return null;

    if (!USERS_IN_POSTGRES) {
        return User.findById(normalizedUserId);
    }

    let user = await pgUsers.findUserByPublicId(normalizedUserId);
    if (user || !allowDualFallback || !DUAL_MONGO_USER_FALLBACK || !MONGODB_OBJECT_ID_REGEX.test(normalizedUserId)) {
        return user;
    }

    const mongoUser = await User.findById(normalizedUserId);
    if (!mongoUser) return null;
    return migrateMongoUserToPostgres(mongoUser);
}

async function findUserByEmail(email, { allowDualFallback = true } = {}) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!normalizedEmail) return null;

    if (!USERS_IN_POSTGRES) {
        return User.findOne({ email: normalizedEmail });
    }

    let user = await pgUsers.findUserByEmail(normalizedEmail);
    if (user || !allowDualFallback || !DUAL_MONGO_USER_FALLBACK) {
        return user;
    }

    const mongoUser = await User.findOne({ email: normalizedEmail });
    if (!mongoUser) return null;
    return migrateMongoUserToPostgres(mongoUser);
}

async function findUserByPhone(phone, { allowDualFallback = true } = {}) {
    const normalizedPhone = String(phone || '').trim();
    if (!normalizedPhone) return null;

    if (!USERS_IN_POSTGRES) {
        return User.findOne({ phone: normalizedPhone });
    }

    let user = await pgUsers.findUserByPhone(normalizedPhone);
    if (user || !allowDualFallback || !DUAL_MONGO_USER_FALLBACK) {
        return user;
    }

    const mongoUser = await User.findOne({ phone: normalizedPhone });
    if (!mongoUser) return null;
    return migrateMongoUserToPostgres(mongoUser);
}

async function persistUser(user, { managedDoctorIdsChanged = false } = {}) {
    if (!user) return null;
    if (!USERS_IN_POSTGRES) {
        await user.save();
        return user;
    }
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

async function migrateMongoDoctorToPostgres(mongoDoctor) {
    if (!DOCTORS_IN_POSTGRES || !mongoDoctor) {
        return mongoDoctor || null;
    }

    return pgDoctors.upsertDoctorFromMongo({
        _id: String(mongoDoctor._id),
        slug: mongoDoctor.slug || '',
        displayName: mongoDoctor.displayName || '',
        specialty: mongoDoctor.specialty || DEFAULT_DOCTOR_SPECIALTY,
        isActive: mongoDoctor.isActive !== false,
        bookingSettings: mongoDoctor.bookingSettings || DEFAULT_BOOKING_SETTINGS,
        availabilityRules: mongoDoctor.availabilityRules || { weekdays: DEFAULT_AVAILABILITY_WEEKDAYS },
        blockedDates: Array.isArray(mongoDoctor.blockedDates) ? mongoDoctor.blockedDates : [],
        createdByUserId: getMongoCompatibleUserId({ _id: mongoDoctor.createdByUserId }) || null,
        updatedByUserId: getMongoCompatibleUserId({ _id: mongoDoctor.updatedByUserId }) || null
    });
}

async function migrateMongoAppointmentToPostgres(mongoAppointment, { defaultDoctorId = null } = {}) {
    if (!APPOINTMENTS_IN_POSTGRES || !mongoAppointment) {
        return mongoAppointment || null;
    }

    const doctorLegacyId = String(mongoAppointment.doctorId || defaultDoctorId || '').trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(doctorLegacyId)) {
        return null;
    }

    const ensuredDoctor = await resolveDoctorByIdentifier(doctorLegacyId, { requireActive: false, allowDualFallback: true });
    if (!ensuredDoctor) {
        return null;
    }

    return pgAppointments.upsertAppointmentFromMongo({
        _id: String(mongoAppointment._id || ''),
        name: mongoAppointment.name || '',
        phone: mongoAppointment.phone || '',
        type: mongoAppointment.type || '',
        date: mongoAppointment.date || '',
        time: mongoAppointment.time || '',
        notes: mongoAppointment.notes || '',
        email: mongoAppointment.email || '',
        emailSent: !!mongoAppointment.emailSent,
        hasDiagnosis: !!mongoAppointment.hasDiagnosis,
        diagnosticFileMeta: mongoAppointment.diagnosticFileMeta || null,
        doctorId: doctorLegacyId,
        doctorSnapshotName: mongoAppointment.doctorSnapshotName || ensuredDoctor.displayName || '',
        userId: getMongoCompatibleUserId({ _id: mongoAppointment.userId }) || null,
        createdAt: mongoAppointment.createdAt || new Date()
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

function getScopedDoctorObjectIds(user) {
    return getUserManagedDoctorIds(user).map((id) => new mongoose.Types.ObjectId(id));
}

function canUserAccessDoctor(user, doctorId) {
    if (!doctorId) return false;
    if (isSuperadminUser(user)) return true;
    const wanted = String(doctorId);
    return getUserManagedDoctorIds(user).includes(wanted);
}

function doctorScopeQueryForUser(user, fieldName = '_id') {
    if (isSuperadminUser(user)) {
        return {};
    }
    const doctorIds = getScopedDoctorObjectIds(user);
    if (doctorIds.length === 0) {
        return null;
    }
    return { [fieldName]: { $in: doctorIds } };
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
    const start = parseHHMMToMinutes(settings.workdayStart);
    const end = parseHHMMToMinutes(settings.workdayEnd);
    const duration = Number(settings.consultationDurationMinutes);
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
            weekdays: Array.isArray(doctor.availabilityRules?.weekdays) ? doctor.availabilityRules.weekdays : []
        }
    };
}

function sanitizeDoctorForAdmin(doctor, { includeAudit = false } = {}) {
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
            weekdays: Array.isArray(doctor.availabilityRules?.weekdays) ? doctor.availabilityRules.weekdays : []
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

async function resolveDoctorByIdentifier(rawIdentifier, { requireActive = true, allowDualFallback = true } = {}) {
    const normalized = sanitizeInlineString(rawIdentifier).toLowerCase();
    if (!normalized) return null;

    if (!DOCTORS_IN_POSTGRES) {
        const query = MONGODB_OBJECT_ID_REGEX.test(normalized)
            ? { _id: normalized }
            : { slug: normalized };
        if (requireActive) {
            query.isActive = true;
        }
        return Doctor.findOne(query);
    }

    let doctor = await pgDoctors.findDoctorByIdentifier(normalized, { requireActive });
    if (doctor || !allowDualFallback || !DUAL_MONGO_DOCTOR_FALLBACK) {
        return doctor;
    }

    const query = MONGODB_OBJECT_ID_REGEX.test(normalized)
        ? { _id: normalized }
        : { slug: normalized };
    if (requireActive) {
        query.isActive = true;
    }
    const mongoDoctor = await Doctor.findOne(query);
    if (!mongoDoctor) {
        return null;
    }
    doctor = await migrateMongoDoctorToPostgres(mongoDoctor);
    if (doctor && requireActive && !doctor.isActive) {
        return null;
    }
    return doctor;
}

async function validateDoctorIdsExist(ids = []) {
    if (!Array.isArray(ids) || ids.length === 0) {
        return true;
    }

    if (!DOCTORS_IN_POSTGRES) {
        const count = await Doctor.countDocuments({ _id: { $in: ids } });
        return count === ids.length;
    }

    const normalizedLegacyIds = normalizeManagedDoctorIds(ids.map((id) => String(id)));
    if (!normalizedLegacyIds.length) {
        return false;
    }

    if (DUAL_MONGO_DOCTOR_FALLBACK) {
        for (const legacyId of normalizedLegacyIds) {
            const existing = await pgDoctors.findDoctorByIdentifier(legacyId, { requireActive: false });
            if (existing) continue;
            const mongoDoctor = await Doctor.findById(legacyId);
            if (!mongoDoctor) continue;
            await migrateMongoDoctorToPostgres(mongoDoctor);
        }
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
    if (req.path === '/debug/charset') {
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
        const actorUserId = getMongoCompatibleUserId(actorUser) || String(actorUser?._id || actorUser?.id || '').trim() || null;
        if (AUDIT_IN_POSTGRES) {
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
            return;
        }

        await AuditLog.create({
            actorUserId: getMongoCompatibleUserId(actorUser) || null,
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
    const user = await findUserById(payload.sub, { allowDualFallback: true });
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

app.get('/debug/charset', async (req, res) => {
    setAuthNoStore(res);
    res.set('Content-Type', 'application/json; charset=utf-8');

    const responseContentType = String(res.getHeader('Content-Type') || '');
    console.log(`[DEBUG CHARSET] GET response Content-Type: ${responseContentType}`);

    return res.status(200).json({
        ok: true,
        sample: DEBUG_CHARSET_SAMPLE_TEXT,
        responseContentType
    });
});

app.post('/debug/charset', async (req, res) => {
    setAuthNoStore(res);
    res.set('Content-Type', 'application/json; charset=utf-8');

    const incomingText = typeof req.body?.text === 'string' ? req.body.text : DEBUG_CHARSET_SAMPLE_TEXT;
    console.log('[DEBUG CHARSET] POST req.body:', req.body);

    try {
        const created = await CharsetProbe.create({ text: incomingText });
        const loaded = await CharsetProbe.findById(created._id).lean();
        const loadedText = loaded?.text || '';
        const responseContentType = String(res.getHeader('Content-Type') || '');

        console.log(`[DEBUG CHARSET] POST response Content-Type: ${responseContentType}`);
        console.log(`[DEBUG CHARSET] DB write text: ${JSON.stringify(incomingText)}`);
        console.log(`[DEBUG CHARSET] DB read text: ${JSON.stringify(loadedText)}`);

        return res.status(200).json({
            ok: true,
            incomingText,
            writtenText: created.text,
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
            user = await findUserByEmail(identifier.toLowerCase(), { allowDualFallback: true });
        } else {
            const cleanedPhone = cleanPhone(identifier);
            user = await findUserByPhone(cleanedPhone, { allowDualFallback: true });
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
        const user = await findUserById(payload.sub, { allowDualFallback: true });

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
        const user = await ensureNormalizedRole(await findUserById(payload.sub, { allowDualFallback: true }));
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
        const doctors = DOCTORS_IN_POSTGRES
            ? await pgDoctors.listDoctors({ isActive: true })
            : await Doctor.find({ isActive: true }).sort({ displayName: 1 }).lean();
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

        if (APPOINTMENTS_IN_POSTGRES) {
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
        }

        if (!isDateInDoctorRange(date, doctor.bookingSettings?.monthsToShow)) {
            return res.status(400).json({ error: 'Data selectata este in afara intervalului permis pentru acest medic.' });
        }

        const day = getUtcDateFromISO(date).getUTCDay();
        const weekdays = Array.isArray(doctor.availabilityRules?.weekdays) ? doctor.availabilityRules.weekdays : DEFAULT_AVAILABILITY_WEEKDAYS;
        if (!weekdays.includes(day)) {
            return res.status(400).json({ error: 'Medicul selectat nu are disponibilitate in aceasta zi.' });
        }

        const allSlots = generateDoctorSlots(doctor);
        const isBlockedDate = Array.isArray(doctor.blockedDates) && doctor.blockedDates.includes(date);

        const bookedTimes = (await Appointment.find({ date, doctorId: doctor._id }).select('time').lean()).map((a) => a.time);
        const availableSlots = allSlots.map((time) => ({
            time,
            available: !isBlockedDate && !bookedTimes.includes(time)
        }));

        return res.json({
            doctor: sanitizeDoctorForPublic(doctor),
            date,
            blocked: !!isBlockedDate,
            slots: availableSlots
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

        if (!APPOINTMENTS_IN_POSTGRES) {
            const appointmentDay = getUtcDateFromISO(date).getUTCDay();
            const weekdays = Array.isArray(doctor.availabilityRules?.weekdays) ? doctor.availabilityRules.weekdays : DEFAULT_AVAILABILITY_WEEKDAYS;
            if (!weekdays.includes(appointmentDay)) {
                return res.status(400).json({ error: 'Medicul selectat nu are disponibilitate in aceasta zi.' });
            }

            if (Array.isArray(doctor.blockedDates) && doctor.blockedDates.includes(date)) {
                return res.status(409).json({ error: 'Ziua selectata este indisponibila pentru medicul ales.' });
            }

            const allowedSlots = generateDoctorSlots(doctor);
            if (!allowedSlots.includes(time)) {
                return res.status(400).json({ error: 'Ora selectata este invalida pentru medicul ales.' });
            }
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

        let newAppointment;
        if (APPOINTMENTS_IN_POSTGRES) {
            newAppointment = await pgAppointments.createAppointmentTransactional({
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
                userPublicId: getMongoCompatibleUserId(req.user) || req.user?._id || null,
                auditContext: {
                    action: 'appointment_book',
                    result: 'success',
                    targetType: 'appointment',
                    actorUserPublicId: getMongoCompatibleUserId(req.user) || req.user?._id || null,
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
        } else {
            const newAppointmentPayload = {
                name,
                phone: cleanPhone(phone),
                email: email.toLowerCase().trim(),
                type,
                date,
                time,
                doctorId: doctor._id,
                doctorSnapshotName: doctor.displayName,
                hasDiagnosis: !!hasDiagnosis,
                userId: getMongoCompatibleUserId(req.user) || null
            };
            if (safeDiagnosticFileMeta) {
                newAppointmentPayload.diagnosticFileMeta = safeDiagnosticFileMeta;
            }

            const mongoAppointment = new Appointment(newAppointmentPayload);
            await mongoAppointment.save();
            newAppointment = mongoAppointment;
        }

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
                if (APPOINTMENTS_IN_POSTGRES) {
                    await pgAppointments.setAppointmentEmailSentByPublicId(newAppointment._id, true);
                } else {
                    await Appointment.findByIdAndUpdate(newAppointment._id, { emailSent: true });
                }
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
        if (err?.code === 11000 || (APPOINTMENTS_IN_POSTGRES && pgAppointments.isUniqueViolation(err))) {
            return res.status(409).json({ error: 'Interval deja rezervat.' });
        }
        return res.status(500).json({ error: 'Eroare la salvare.' });
    }
}

app.post('/api/book', optionalAuth, validateBody(bookBodySchema), handleAppointmentBooking);
app.post('/api/appointments', optionalAuth, validateBody(bookBodySchema), handleAppointmentBooking);

function getAdminDoctorScopeQuery(user, fieldName = 'doctorId') {
    const scope = doctorScopeQueryForUser(user, fieldName);
    if (scope === null) {
        return null;
    }
    return scope;
}

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
    if (DOCTORS_IN_POSTGRES) {
        return validateDoctorIdsExist((managedDoctorIds || []).map((id) => String(id)));
    }
    const ids = (managedDoctorIds || []).map((id) => new mongoose.Types.ObjectId(id));
    return validateDoctorIdsExist(ids);
}

async function loadDoctorsMapByIds(rawIds = []) {
    const ids = normalizeManagedDoctorIds(rawIds);
    if (ids.length === 0) {
        return new Map();
    }

    let doctors;
    if (DOCTORS_IN_POSTGRES) {
        doctors = await pgDoctors.listDoctors({ legacyIds: ids, isActive: null });
    } else {
        doctors = await Doctor.find({ _id: { $in: ids } }).select('_id slug displayName').lean();
    }

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
        if (APPOINTMENTS_IN_POSTGRES) {
            if (isSuperadminUser(req.user)) {
                appointments = await pgAppointments.listAppointments();
            } else {
                const scopedDoctorIds = getUserManagedDoctorIds(req.user);
                if (scopedDoctorIds.length === 0) {
                    return res.status(403).json({ error: 'Nu aveti niciun medic asignat.' });
                }
                appointments = await pgAppointments.listAppointments({ doctorLegacyIds: scopedDoctorIds });
            }
        } else {
            const scopeQuery = getAdminDoctorScopeQuery(req.user, 'doctorId');
            if (scopeQuery === null) {
                return res.status(403).json({ error: 'Nu aveti niciun medic asignat.' });
            }
            appointments = await Appointment.find(scopeQuery).sort({ date: 1, time: 1 }).lean();
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
    if (!MONGODB_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const appointment = APPOINTMENTS_IN_POSTGRES
            ? await pgAppointments.findAppointmentByPublicId(appointmentId)
            : await Appointment.findById(appointmentId).lean();
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
    if (!MONGODB_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const appointment = APPOINTMENTS_IN_POSTGRES
            ? await pgAppointments.findAppointmentByPublicId(appointmentId)
            : await Appointment.findById(appointmentId).lean();
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
    if (!MONGODB_OBJECT_ID_REGEX.test(appointmentId)) {
        return res.status(400).json({ error: 'Programare invalida.' });
    }

    try {
        const appointment = APPOINTMENTS_IN_POSTGRES
            ? await pgAppointments.findAppointmentByPublicId(appointmentId)
            : await Appointment.findById(appointmentId);
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
            if (APPOINTMENTS_IN_POSTGRES) {
                await pgAppointments.setAppointmentEmailSentByPublicId(appointment._id, true);
            } else {
                await Appointment.findByIdAndUpdate(appointment._id, { emailSent: true });
            }
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
        let usedSize = 0;
        if (APPOINTMENTS_IN_POSTGRES) {
            const stats = await pgAppointments.getAppointmentStorageStats();
            usedSize = Number(stats.appointmentsBytes || 0);
        } else {
            const stats = await mongoose.connection.db.command({ dbStats: 1 });
            usedSize = stats.storageSize || stats.dataSize;
        }
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

app.get('/api/admin/mongo-tls', requireSuperadminOnly, async (req, res) => {
    setAuthNoStore(res);

    try {
        const diagnostics = getMongoTlsDiagnosticsSnapshot();
        await writeAuditLog(req, {
            action: 'admin_mongo_tls_view',
            result: 'success',
            targetType: 'system',
            targetId: 'mongo_tls',
            actorUser: req.user,
            metadata: {
                connectionState: diagnostics.connectionState,
                configuredMinVersion: diagnostics.configuredMinVersion,
                effectiveMinVersion: diagnostics.effectiveMinVersion,
                fallbackToTls12Used: diagnostics.fallbackToTls12Used
            }
        });
        return res.json(diagnostics);
    } catch (_) {
        await writeAuditLog(req, {
            action: 'admin_mongo_tls_view',
            result: 'failure',
            targetType: 'system',
            targetId: 'mongo_tls',
            actorUser: req.user
        });
        return res.status(500).json({ error: 'Could not fetch MongoDB TLS diagnostics' });
    }
});

app.post('/api/admin/reset', requireSuperadminOnly, requireStepUp('appointments_reset'), async (req, res) => {
    setAuthNoStore(res);

    try {
        const deletedCount = APPOINTMENTS_IN_POSTGRES
            ? await pgAppointments.deleteAllAppointments()
            : (await Appointment.deleteMany({})).deletedCount || 0;
        await writeAuditLog(req, {
            action: 'appointments_reset',
            result: 'success',
            targetType: 'appointment_collection',
            actorUser: req.user,
            metadata: { deletedCount }
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
        const deleted = APPOINTMENTS_IN_POSTGRES
            ? await pgAppointments.deleteAppointmentByPublicId(appointmentId)
            : await Appointment.findByIdAndDelete(appointmentId);
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
        const deletedCount = APPOINTMENTS_IN_POSTGRES
            ? await pgAppointments.deleteAppointmentsByDate(date)
            : (await Appointment.deleteMany({ date })).deletedCount || 0;
        await writeAuditLog(req, {
            action: 'appointments_delete_by_date',
            result: 'success',
            targetType: 'appointment_collection',
            targetId: date,
            actorUser: req.user,
            metadata: { deletedCount }
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
        const appointments = APPOINTMENTS_IN_POSTGRES
            ? await pgAppointments.listAppointments()
            : await Appointment.find().sort({ date: 1, time: 1 }).lean();

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
        if (DOCTORS_IN_POSTGRES) {
            if (isSuperadminUser(req.user)) {
                doctors = await pgDoctors.listDoctors({ isActive: null });
            } else {
                const scopedDoctorIds = getUserManagedDoctorIds(req.user);
                if (scopedDoctorIds.length === 0) {
                    return res.status(403).json({ error: 'Nu aveti niciun medic asignat.' });
                }
                doctors = await pgDoctors.listDoctors({ legacyIds: scopedDoctorIds, isActive: null });
            }
        } else {
            const scopeQuery = doctorScopeQueryForUser(req.user);
            if (scopeQuery === null) {
                return res.status(403).json({ error: 'Nu aveti niciun medic asignat.' });
            }
            doctors = await Doctor.find(scopeQuery).sort({ displayName: 1 }).lean();
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
        const doctor = DOCTORS_IN_POSTGRES
            ? await pgDoctors.createDoctor({
                slug: payload.slug,
                displayName: sanitizeInlineString(payload.displayName),
                specialty: sanitizeInlineString(payload.specialty),
                isActive: !!payload.isActive,
                bookingSettings: payload.bookingSettings,
                availabilityRules: payload.availabilityRules,
                blockedDates: payload.blockedDates,
                createdByUserPublicId: getMongoCompatibleUserId(req.user) || req.user?._id || null,
                updatedByUserPublicId: getMongoCompatibleUserId(req.user) || req.user?._id || null
            })
            : await (async () => {
                const mongoDoctor = new Doctor({
                    slug: payload.slug,
                    displayName: sanitizeInlineString(payload.displayName),
                    specialty: sanitizeInlineString(payload.specialty),
                    isActive: !!payload.isActive,
                    bookingSettings: payload.bookingSettings,
                    availabilityRules: payload.availabilityRules,
                    blockedDates: payload.blockedDates,
                    createdByUserId: getMongoCompatibleUserId(req.user) || null,
                    updatedByUserId: getMongoCompatibleUserId(req.user) || null
                });
                await mongoDoctor.save();
                return mongoDoctor.toObject();
            })();

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
        if ((!DOCTORS_IN_POSTGRES && error?.code === 11000) || (DOCTORS_IN_POSTGRES && pgDoctors.isUniqueViolation(error))) {
            return res.status(409).json({ error: 'Slug-ul medicului exista deja.' });
        }
        return res.status(500).json({ error: 'Eroare la crearea medicului.' });
    }
});

app.patch('/api/admin/doctors/:id', requireSchedulerOrSuperadmin, validateBody(doctorPatchBodySchema), async (req, res) => {
    setAuthNoStore(res);

    const doctorId = String(req.params.id || '').trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(doctorId)) {
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
        updateDoc.updatedByUserPublicId = getMongoCompatibleUserId(req.user) || req.user?._id || null;

        const doctor = DOCTORS_IN_POSTGRES
            ? await pgDoctors.updateDoctorByLegacyId(doctorId, updateDoc)
            : await (async () => {
                const mongoUpdateDoc = { ...updateDoc };
                delete mongoUpdateDoc.updatedByUserPublicId;
                mongoUpdateDoc.updatedByUserId = getMongoCompatibleUserId(req.user) || null;
                return Doctor.findByIdAndUpdate(
                    doctorId,
                    { $set: mongoUpdateDoc },
                    { new: true, runValidators: true }
                );
            })();
        if (!doctor) {
            return res.status(404).json({ error: 'Medic negasit.' });
        }

        if (APPOINTMENTS_IN_POSTGRES) {
            await pgAppointments.updateDoctorSnapshotNameByDoctorLegacyId(doctor._id, doctor.displayName);
        } else {
            await Appointment.updateMany(
                { doctorId: doctor._id, doctorSnapshotName: { $ne: sanitizeInlineString(doctor.displayName) } },
                { $set: { doctorSnapshotName: doctor.displayName } }
            );
        }

        await writeAuditLog(req, {
            action: 'doctor_update',
            result: 'success',
            targetType: 'doctor',
            targetId: doctorId,
            actorUser: req.user,
            metadata: { fields: Object.keys(updates || {}) }
        });
        return res.json({ success: true, doctor: sanitizeDoctorForAdmin(DOCTORS_IN_POSTGRES ? doctor : doctor.toObject(), { includeAudit: true }) });
    } catch (error) {
        await writeAuditLog(req, {
            action: 'doctor_update',
            result: 'failure',
            targetType: 'doctor',
            targetId: doctorId,
            actorUser: req.user
        });
        if ((!DOCTORS_IN_POSTGRES && error?.code === 11000) || (DOCTORS_IN_POSTGRES && pgDoctors.isUniqueViolation(error))) {
            return res.status(409).json({ error: 'Slug-ul medicului exista deja.' });
        }
        return res.status(500).json({ error: 'Eroare la actualizarea medicului.' });
    }
});

app.post('/api/admin/doctors/:id/block-date', requireSchedulerOrSuperadmin, validateBody(doctorBlockDateBodySchema), async (req, res) => {
    setAuthNoStore(res);

    const doctorId = String(req.params.id || '').trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(doctorId)) {
        return res.status(400).json({ error: 'Medic invalid.' });
    }
    if (!isSuperadminUser(req.user) && !canUserAccessDoctor(req.user, doctorId)) {
        return res.status(403).json({ error: 'Acces interzis pentru acest medic.' });
    }

    try {
        const { date } = req.validatedBody;
        const doctor = DOCTORS_IN_POSTGRES
            ? await pgDoctors.blockDoctorDateByLegacyId(
                doctorId,
                date,
                { actorUserPublicId: getMongoCompatibleUserId(req.user) || req.user?._id || null }
            )
            : await Doctor.findByIdAndUpdate(
                doctorId,
                {
                    $addToSet: { blockedDates: date },
                    $set: { updatedByUserId: getMongoCompatibleUserId(req.user) || null }
                },
                { new: true, runValidators: true }
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
        return res.json({ success: true, doctor: sanitizeDoctorForAdmin(DOCTORS_IN_POSTGRES ? doctor : doctor.toObject(), { includeAudit: true }) });
    } catch (_) {
        return res.status(500).json({ error: 'Eroare la blocarea zilei.' });
    }
});

app.delete('/api/admin/doctors/:id/block-date/:date', requireSchedulerOrSuperadmin, async (req, res) => {
    setAuthNoStore(res);

    const doctorId = String(req.params.id || '').trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(doctorId)) {
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
        const doctor = DOCTORS_IN_POSTGRES
            ? await pgDoctors.unblockDoctorDateByLegacyId(
                doctorId,
                rawDate,
                { actorUserPublicId: getMongoCompatibleUserId(req.user) || req.user?._id || null }
            )
            : await Doctor.findByIdAndUpdate(
                doctorId,
                {
                    $pull: { blockedDates: rawDate },
                    $set: { updatedByUserId: getMongoCompatibleUserId(req.user) || null }
                },
                { new: true, runValidators: true }
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

        return res.json({ success: true, doctor: sanitizeDoctorForAdmin(DOCTORS_IN_POSTGRES ? doctor : doctor.toObject(), { includeAudit: true }) });
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

        const existingEmail = await findUserByEmail(normalizedEmail, { allowDualFallback: true });
        if (existingEmail) {
            return res.status(409).json({ error: 'Acest email este deja inregistrat.' });
        }

        const existingPhone = await findUserByPhone(cleanedPhone, { allowDualFallback: true });
        if (existingPhone) {
            return res.status(409).json({ error: 'Acest numar de telefon este deja inregistrat.' });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        let user;
        if (USERS_IN_POSTGRES) {
            user = await pgUsers.withTransaction(async (client) => pgUsers.createUser({
                email: normalizedEmail,
                phone: cleanedPhone,
                passwordHash: hashedPassword,
                displayName: displayName.trim(),
                role,
                managedDoctorIds: normalizedDoctorIds
            }, client));
        } else {
            user = new User({
                email: normalizedEmail,
                phone: cleanedPhone,
                password: hashedPassword,
                displayName: displayName.trim(),
                role,
                managedDoctorIds: normalizedDoctorIds.map((id) => new mongoose.Types.ObjectId(id))
            });
            await user.save();
        }

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
            user: sanitizeUserForAdmin(USERS_IN_POSTGRES ? user : user.toObject(), doctorsMap)
        });
    } catch (error) {
        await writeAuditLog(req, {
            action: 'user_create',
            result: 'failure',
            targetType: 'user',
            actorUser: req.user
        });
        if (!USERS_IN_POSTGRES && error?.code === 11000) {
            return res.status(409).json({ error: 'Email sau telefon deja inregistrat.' });
        }
        if (USERS_IN_POSTGRES && pgUsers.isUniqueViolation(error)) {
            return res.status(409).json({ error: 'Email sau telefon deja inregistrat.' });
        }
        return res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/users', requireSuperadminOnly, async (req, res) => {
    setAuthNoStore(res);

    try {
        if (USERS_IN_POSTGRES && DUAL_MONGO_USER_FALLBACK) {
            const mongoUsers = await User.find().lean();
            for (const mongoUser of mongoUsers) {
                await migrateMongoUserToPostgres(mongoUser);
            }
        }

        const users = USERS_IN_POSTGRES
            ? await pgUsers.listUsers()
            : await User.find().select('-password').sort({ createdAt: -1 }).lean();
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

        const user = await findUserById(userId, { allowDualFallback: true });
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
        const existingUser = await findUserById(userId, { allowDualFallback: true });
        if (!existingUser) {
            return res.status(404).json({ error: 'Utilizator negasit.' });
        }

        const updates = req.validatedBody;
        const changedFields = [];

        if (updates.email !== undefined) {
            const normalizedEmail = updates.email.toLowerCase();
            const duplicate = await findUserByEmail(normalizedEmail, { allowDualFallback: true });
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
            const duplicatePhone = await findUserByPhone(cleanedPhone, { allowDualFallback: true });
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
                const superadminCount = USERS_IN_POSTGRES
                    ? await pgUsers.countUsersByRole(ROLE.SUPERADMIN)
                    : await User.countDocuments({ role: ROLE.SUPERADMIN });
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
            existingUser.managedDoctorIds = USERS_IN_POSTGRES
                ? normalizedDoctorIds
                : normalizedDoctorIds.map((id) => new mongoose.Types.ObjectId(id));
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
            user: sanitizeUserForAdmin(USERS_IN_POSTGRES ? savedUser : savedUser.toObject(), doctorsMap)
        });
    } catch (error) {
        await writeAuditLog(req, {
            action: 'user_update',
            result: 'failure',
            targetType: 'user',
            targetId: userId,
            actorUser: req.user
        });
        if (!USERS_IN_POSTGRES && error?.code === 11000) {
            return res.status(409).json({ error: 'Email sau telefon deja inregistrat.' });
        }
        if (USERS_IN_POSTGRES && pgUsers.isUniqueViolation(error)) {
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
        const target = await findUserById(userId, { allowDualFallback: true });
        if (!target) {
            return res.status(404).json({ error: 'Utilizator negasit.' });
        }

        if (target.role === ROLE.SUPERADMIN) {
            const superadminCount = USERS_IN_POSTGRES
                ? await pgUsers.countUsersByRole(ROLE.SUPERADMIN)
                : await User.countDocuments({ role: ROLE.SUPERADMIN });
            if (superadminCount <= 1) {
                return res.status(403).json({ error: 'Nu puteti sterge ultimul superadmin.' });
            }
        }

        if (USERS_IN_POSTGRES) {
            await pgUsers.deleteUserByPublicId(target._id);
        } else {
            await User.deleteOne({ _id: target._id });
        }
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
    if (!POSTGRES_ENABLED) {
        console.log(`[POSTGRES] Startup health check skipped (DB_PROVIDER=${DB_PROVIDER}).`);
        return;
    }

    const health = await runPostgresHealthCheck();
    if (health.skipped) {
        console.log(`[POSTGRES] Startup health check skipped (${health.reason}).`);
        return;
    }

    console.log(
        `[POSTGRES] Startup health check OK `
        + `(provider=${DB_PROVIDER}, target=${health.target}, latencyMs=${health.latencyMs}).`
    );
}

async function bootstrapServer() {
    try {
        await validatePostgresStartupHealth();
    } catch (error) {
        console.error(`[POSTGRES] Startup health check failed: ${redactPostgresUrlInText(error?.message || String(error))}`);
        process.exit(1);
    }

    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT} (MongoDB active, DB_PROVIDER=${DB_PROVIDER})`);
    });
}

bootstrapServer().catch((error) => {
    console.error(`Server bootstrap failed: ${redactPostgresUrlInText(error?.message || String(error))}`);
    process.exit(1);
});
