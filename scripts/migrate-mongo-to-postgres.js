#!/usr/bin/env node
require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { MongoClient } = require('mongodb');
const {
    getPostgresPool,
    closePostgresPool,
    getPostgresTargetSummary,
    redactPostgresUrlInText
} = require('../db/postgres');
const { validateDatabaseUrl } = require('./env-utils');
const {
    buildMongoTlsPolicy,
    buildMongoDriverTlsOptions,
    getSafeMongoErrorSummary,
    isLikelyTlsCompatibilityError,
    FALLBACK_MONGO_TLS_MIN_VERSION
} = require('../utils/mongo-tls-config');

const MONGODB_OBJECT_ID_REGEX = /^[a-fA-F0-9]{24}$/;
const DOCTOR_SLUG_REGEX = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const TIME_HHMM_REGEX = /^([01]\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?$/;
const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;
const DEFAULT_BOOKING_SETTINGS = Object.freeze({
    consultationDurationMinutes: 20,
    workdayStart: '09:00',
    workdayEnd: '14:00',
    monthsToShow: 3,
    timezone: 'Europe/Bucharest'
});
const DEFAULT_AVAILABILITY_WEEKDAYS = Object.freeze([3]);
const DEFAULT_DOCTOR_SPECIALTY = 'Oftalmologie';
const DEFAULT_BATCH_SIZE = 200;
const DEFAULT_SAMPLE_SIZE = 10;
const MAX_ERROR_SAMPLES = 50;

function printHelp() {
    console.log(`
Usage:
  node scripts/migrate-mongo-to-postgres.js [options]

Options:
  --dry-run                 Show what would be migrated without writing to Postgres
  --include-audit-logs      Include audit log migration (optional)
  --batch-size=N            Mongo cursor batch size (default: ${DEFAULT_BATCH_SIZE})
  --sample-size=N           Validation sample size per entity (default: ${DEFAULT_SAMPLE_SIZE})
  --report-file=PATH        Write JSON report to a file
  --mongo-db=NAME           Force Mongo database name (overrides URI db name)
  --help                    Show this help
`);
}

function parseCliArgs(argv) {
    const options = {
        dryRun: false,
        includeAuditLogs: false,
        batchSize: DEFAULT_BATCH_SIZE,
        sampleSize: DEFAULT_SAMPLE_SIZE,
        reportFile: null,
        mongoDbName: null
    };

    for (const rawArg of argv) {
        const arg = String(rawArg || '').trim();
        if (!arg) continue;

        if (arg === '--help') {
            printHelp();
            process.exit(0);
        } else if (arg === '--dry-run') {
            options.dryRun = true;
        } else if (arg === '--include-audit-logs') {
            options.includeAuditLogs = true;
        } else if (arg.startsWith('--batch-size=')) {
            const value = Number.parseInt(arg.split('=', 2)[1], 10);
            if (!Number.isInteger(value) || value <= 0) {
                throw new Error('--batch-size must be a positive integer.');
            }
            options.batchSize = value;
        } else if (arg.startsWith('--sample-size=')) {
            const value = Number.parseInt(arg.split('=', 2)[1], 10);
            if (!Number.isInteger(value) || value < 0) {
                throw new Error('--sample-size must be a non-negative integer.');
            }
            options.sampleSize = value;
        } else if (arg.startsWith('--report-file=')) {
            const value = String(arg.split('=', 2)[1] || '').trim();
            if (!value) {
                throw new Error('--report-file requires a file path.');
            }
            options.reportFile = value;
        } else if (arg.startsWith('--mongo-db=')) {
            const value = String(arg.split('=', 2)[1] || '').trim();
            if (!value) {
                throw new Error('--mongo-db requires a database name.');
            }
            options.mongoDbName = value;
        } else {
            throw new Error(`Unknown argument: ${arg}`);
        }
    }

    return options;
}

function toErrorMessage(error) {
    return redactPostgresUrlInText(error?.message || String(error || 'Unknown error'));
}

function toSafeString(value) {
    if (value === undefined || value === null) return '';
    return String(value);
}

function normalizeLegacyObjectId(value) {
    if (!value) return null;
    const candidate = toSafeString(value?.toHexString ? value.toHexString() : value).trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(candidate)) return null;
    return candidate;
}

function normalizeEmail(value) {
    const normalized = toSafeString(value).trim().toLowerCase();
    return normalized || null;
}

function normalizePhone(value) {
    const normalized = toSafeString(value).trim();
    return normalized || null;
}

function normalizeRole(value) {
    const raw = toSafeString(value).trim().toLowerCase();
    if (raw === 'superadmin') return 'superadmin';
    if (raw === 'scheduler' || raw === 'admin') return 'scheduler';
    return 'viewer';
}

function normalizeDisplayName(value, fallback = 'Unknown User') {
    const normalized = toSafeString(value).trim();
    return normalized || fallback;
}

function normalizeSlug(value) {
    const normalized = toSafeString(value).trim().toLowerCase();
    if (!DOCTOR_SLUG_REGEX.test(normalized)) {
        return null;
    }
    return normalized;
}

function normalizeTimeHHMM(value) {
    const normalized = toSafeString(value).trim();
    const match = normalized.match(TIME_HHMM_REGEX);
    if (!match) return null;
    return `${match[1]}:${match[2]}`;
}

function normalizeISODate(value) {
    const normalized = toSafeString(value).trim();
    if (!ISO_DATE_REGEX.test(normalized)) return null;
    return normalized;
}

function parseTimeToMinutes(value) {
    const normalized = normalizeTimeHHMM(value);
    if (!normalized) return NaN;
    const [hours, minutes] = normalized.split(':').map(Number);
    return (hours * 60) + minutes;
}

function normalizeMongoDate(value, fallback = null) {
    if (!value) return fallback;
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return fallback;
    return parsed;
}

function normalizeWeekdays(value) {
    if (!Array.isArray(value)) return [];
    const out = [];
    const seen = new Set();
    for (const item of value) {
        const weekday = Number(item);
        if (!Number.isInteger(weekday) || weekday < 0 || weekday > 6) continue;
        if (seen.has(weekday)) continue;
        seen.add(weekday);
        out.push(weekday);
    }
    return out.sort((a, b) => a - b);
}

function normalizeBlockedDates(value) {
    if (!Array.isArray(value)) return [];
    const out = [];
    const seen = new Set();
    for (const item of value) {
        const normalized = normalizeISODate(item);
        if (!normalized || seen.has(normalized)) continue;
        seen.add(normalized);
        out.push(normalized);
    }
    return out.sort();
}

function normalizeManagedDoctorIds(value) {
    if (!Array.isArray(value)) return [];
    const out = [];
    const seen = new Set();
    for (const item of value) {
        const normalized = normalizeLegacyObjectId(item);
        if (!normalized || seen.has(normalized)) continue;
        seen.add(normalized);
        out.push(normalized);
    }
    return out;
}

function normalizeDoctorBookingSettings(rawSettings = {}) {
    const settings = rawSettings && typeof rawSettings === 'object' ? rawSettings : {};

    let consultationDurationMinutes = Number(settings.consultationDurationMinutes);
    if (!Number.isInteger(consultationDurationMinutes) || consultationDurationMinutes < 5 || consultationDurationMinutes > 120) {
        consultationDurationMinutes = DEFAULT_BOOKING_SETTINGS.consultationDurationMinutes;
    }

    let workdayStart = normalizeTimeHHMM(settings.workdayStart);
    if (!workdayStart) workdayStart = DEFAULT_BOOKING_SETTINGS.workdayStart;

    let workdayEnd = normalizeTimeHHMM(settings.workdayEnd);
    if (!workdayEnd) workdayEnd = DEFAULT_BOOKING_SETTINGS.workdayEnd;

    const startMinutes = parseTimeToMinutes(workdayStart);
    const endMinutes = parseTimeToMinutes(workdayEnd);
    if (!Number.isFinite(startMinutes) || !Number.isFinite(endMinutes) || endMinutes <= startMinutes) {
        workdayStart = DEFAULT_BOOKING_SETTINGS.workdayStart;
        workdayEnd = DEFAULT_BOOKING_SETTINGS.workdayEnd;
    }

    let monthsToShow = Number(settings.monthsToShow);
    if (!Number.isInteger(monthsToShow) || monthsToShow < 1 || monthsToShow > 12) {
        monthsToShow = DEFAULT_BOOKING_SETTINGS.monthsToShow;
    }

    const timezone = toSafeString(settings.timezone || DEFAULT_BOOKING_SETTINGS.timezone).trim() || DEFAULT_BOOKING_SETTINGS.timezone;

    return {
        consultationDurationMinutes,
        workdayStart,
        workdayEnd,
        monthsToShow,
        timezone
    };
}

function normalizeAuditResult(value) {
    const normalized = toSafeString(value).trim().toLowerCase();
    if (normalized === 'success' || normalized === 'failure' || normalized === 'denied') {
        return normalized;
    }
    return 'failure';
}

function toSerializableJson(value) {
    if (!value || typeof value !== 'object') {
        return {};
    }
    try {
        return JSON.parse(JSON.stringify(value, (_key, current) => {
            if (typeof current === 'bigint') {
                return String(current);
            }
            if (current && typeof current === 'object' && current._bsontype === 'ObjectId' && typeof current.toHexString === 'function') {
                return current.toHexString();
            }
            return current;
        }));
    } catch (_) {
        return { value: toSafeString(value) };
    }
}

function createEntityReport(name) {
    return {
        name,
        mongoCount: 0,
        processed: 0,
        inserted: 0,
        updated: 0,
        skipped: 0,
        conflicts: 0,
        errors: 0,
        unresolvedReferences: 0,
        dryRunPlanned: 0,
        notes: [],
        errorSamples: []
    };
}

function pushEntityError(entityReport, error, extra = {}) {
    entityReport.errors += 1;
    if (entityReport.errorSamples.length >= MAX_ERROR_SAMPLES) {
        return;
    }
    entityReport.errorSamples.push({
        message: toErrorMessage(error),
        code: toSafeString(error?.code || ''),
        ...extra
    });
}

function createMigrationConflictError(message, details = {}) {
    const error = new Error(message);
    error.code = 'MIGRATION_CONFLICT';
    error.details = details;
    return error;
}

function addReservoirSample(tracker, item) {
    if (!tracker || tracker.limit <= 0) return;
    tracker.seen += 1;
    if (tracker.items.length < tracker.limit) {
        tracker.items.push(item);
        return;
    }

    const slot = crypto.randomInt(0, tracker.seen);
    if (slot < tracker.limit) {
        tracker.items[slot] = item;
    }
}

async function withPgTransaction(pool, task) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const result = await task(client);
        await client.query('COMMIT');
        return result;
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
}
async function loadUserIdMap(pool, map) {
    const result = await pool.query(`
        SELECT id::text AS id, TRIM(legacy_mongo_id) AS legacy_mongo_id
        FROM users
        WHERE legacy_mongo_id IS NOT NULL
    `);
    map.clear();
    for (const row of result.rows) {
        if (!row.legacy_mongo_id) continue;
        map.set(row.legacy_mongo_id, row.id);
    }
}

async function loadDoctorIdMap(pool, map) {
    const result = await pool.query(`
        SELECT id::text AS id, TRIM(legacy_mongo_id) AS legacy_mongo_id
        FROM doctors
        WHERE legacy_mongo_id IS NOT NULL
    `);
    map.clear();
    for (const row of result.rows) {
        if (!row.legacy_mongo_id) continue;
        map.set(row.legacy_mongo_id, row.id);
    }
}

async function upsertUser(pool, payload) {
    const sql = `
        INSERT INTO users (
            legacy_mongo_id,
            email,
            phone,
            password_hash,
            google_id,
            display_name,
            role,
            created_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7::user_role, COALESCE($8::timestamptz, now())
        )
        ON CONFLICT (legacy_mongo_id)
        DO UPDATE SET
            email = EXCLUDED.email,
            phone = EXCLUDED.phone,
            password_hash = EXCLUDED.password_hash,
            google_id = EXCLUDED.google_id,
            display_name = EXCLUDED.display_name,
            role = EXCLUDED.role,
            updated_at = now()
        RETURNING id::text AS id, (xmax = 0) AS inserted
    `;

    try {
        const result = await pool.query(sql, [
            payload.legacyMongoId,
            payload.email,
            payload.phone,
            payload.passwordHash,
            payload.googleId,
            payload.displayName,
            payload.role,
            payload.createdAt ? payload.createdAt.toISOString() : null
        ]);
        return { id: result.rows[0].id, inserted: !!result.rows[0].inserted };
    } catch (error) {
        if (error?.code !== '23505') {
            throw error;
        }

        const existing = await pool.query(
            `
            SELECT id::text AS id, TRIM(legacy_mongo_id) AS legacy_mongo_id
            FROM users
            WHERE ($1::text IS NOT NULL AND lower(email) = lower($1))
               OR ($2::text IS NOT NULL AND phone = $2)
            LIMIT 1
            `,
            [payload.email, payload.phone]
        );

        const row = existing.rows[0];
        if (!row) {
            throw error;
        }

        const existingLegacy = toSafeString(row.legacy_mongo_id).trim();
        if (existingLegacy && existingLegacy !== payload.legacyMongoId) {
            throw createMigrationConflictError(
                `User merge conflict for legacy id ${payload.legacyMongoId}; existing row bound to ${existingLegacy}.`,
                { legacyMongoId: payload.legacyMongoId, existingLegacyMongoId: existingLegacy }
            );
        }

        const updated = await pool.query(
            `
            UPDATE users
            SET
                legacy_mongo_id = COALESCE(legacy_mongo_id, $2),
                email = $3,
                phone = $4,
                password_hash = $5,
                google_id = $6,
                display_name = $7,
                role = $8::user_role,
                updated_at = now()
            WHERE id = $1::uuid
            RETURNING id::text AS id
            `,
            [
                row.id,
                payload.legacyMongoId,
                payload.email,
                payload.phone,
                payload.passwordHash,
                payload.googleId,
                payload.displayName,
                payload.role
            ]
        );

        return { id: updated.rows[0].id, inserted: false };
    }
}

async function upsertDoctor(pool, payload) {
    const sql = `
        INSERT INTO doctors (
            legacy_mongo_id,
            slug,
            display_name,
            specialty,
            is_active,
            consultation_duration_minutes,
            workday_start,
            workday_end,
            months_to_show,
            timezone,
            created_by_user_id,
            updated_by_user_id,
            created_at,
            updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7::time, $8::time, $9, $10, $11::uuid, $12::uuid, COALESCE($13::timestamptz, now()), COALESCE($14::timestamptz, now())
        )
        ON CONFLICT (legacy_mongo_id)
        DO UPDATE SET
            slug = EXCLUDED.slug,
            display_name = EXCLUDED.display_name,
            specialty = EXCLUDED.specialty,
            is_active = EXCLUDED.is_active,
            consultation_duration_minutes = EXCLUDED.consultation_duration_minutes,
            workday_start = EXCLUDED.workday_start,
            workday_end = EXCLUDED.workday_end,
            months_to_show = EXCLUDED.months_to_show,
            timezone = EXCLUDED.timezone,
            created_by_user_id = EXCLUDED.created_by_user_id,
            updated_by_user_id = EXCLUDED.updated_by_user_id,
            updated_at = COALESCE(EXCLUDED.updated_at, now())
        RETURNING id::text AS id, (xmax = 0) AS inserted
    `;

    try {
        const result = await pool.query(sql, [
            payload.legacyMongoId,
            payload.slug,
            payload.displayName,
            payload.specialty,
            payload.isActive,
            payload.bookingSettings.consultationDurationMinutes,
            payload.bookingSettings.workdayStart,
            payload.bookingSettings.workdayEnd,
            payload.bookingSettings.monthsToShow,
            payload.bookingSettings.timezone,
            payload.createdByUserPgId,
            payload.updatedByUserPgId,
            payload.createdAt ? payload.createdAt.toISOString() : null,
            payload.updatedAt ? payload.updatedAt.toISOString() : null
        ]);
        return { id: result.rows[0].id, inserted: !!result.rows[0].inserted };
    } catch (error) {
        if (error?.code !== '23505') {
            throw error;
        }

        const existing = await pool.query(
            `
            SELECT id::text AS id, TRIM(legacy_mongo_id) AS legacy_mongo_id
            FROM doctors
            WHERE slug = $1
            LIMIT 1
            `,
            [payload.slug]
        );
        const row = existing.rows[0];
        if (!row) {
            throw error;
        }

        const existingLegacy = toSafeString(row.legacy_mongo_id).trim();
        if (existingLegacy && existingLegacy !== payload.legacyMongoId) {
            throw createMigrationConflictError(
                `Doctor slug conflict for ${payload.slug}; existing row bound to ${existingLegacy}.`,
                { slug: payload.slug, legacyMongoId: payload.legacyMongoId, existingLegacyMongoId: existingLegacy }
            );
        }

        const updated = await pool.query(
            `
            UPDATE doctors
            SET
                legacy_mongo_id = COALESCE(legacy_mongo_id, $2),
                slug = $3,
                display_name = $4,
                specialty = $5,
                is_active = $6,
                consultation_duration_minutes = $7,
                workday_start = $8::time,
                workday_end = $9::time,
                months_to_show = $10,
                timezone = $11,
                created_by_user_id = $12::uuid,
                updated_by_user_id = $13::uuid,
                updated_at = COALESCE($14::timestamptz, now())
            WHERE id = $1::uuid
            RETURNING id::text AS id
            `,
            [
                row.id,
                payload.legacyMongoId,
                payload.slug,
                payload.displayName,
                payload.specialty,
                payload.isActive,
                payload.bookingSettings.consultationDurationMinutes,
                payload.bookingSettings.workdayStart,
                payload.bookingSettings.workdayEnd,
                payload.bookingSettings.monthsToShow,
                payload.bookingSettings.timezone,
                payload.createdByUserPgId,
                payload.updatedByUserPgId,
                payload.updatedAt ? payload.updatedAt.toISOString() : null
            ]
        );

        return { id: updated.rows[0].id, inserted: false };
    }
}

async function upsertAppointment(pool, payload) {
    const sql = `
        INSERT INTO appointments (
            legacy_mongo_id,
            name,
            phone,
            type,
            appointment_date,
            appointment_time,
            notes,
            email,
            email_sent,
            has_diagnosis,
            diagnostic_file_key,
            diagnostic_file_mime,
            diagnostic_file_size,
            diagnostic_uploaded_at,
            doctor_id,
            doctor_snapshot_name,
            user_id,
            created_at
        )
        VALUES (
            $1, $2, $3, $4, $5::date, $6::time, $7, $8, $9, $10, $11, $12, $13, $14::timestamptz, $15::uuid, $16, $17::uuid, COALESCE($18::timestamptz, now())
        )
        ON CONFLICT (legacy_mongo_id)
        DO UPDATE SET
            name = EXCLUDED.name,
            phone = EXCLUDED.phone,
            type = EXCLUDED.type,
            appointment_date = EXCLUDED.appointment_date,
            appointment_time = EXCLUDED.appointment_time,
            notes = EXCLUDED.notes,
            email = EXCLUDED.email,
            email_sent = EXCLUDED.email_sent,
            has_diagnosis = EXCLUDED.has_diagnosis,
            diagnostic_file_key = EXCLUDED.diagnostic_file_key,
            diagnostic_file_mime = EXCLUDED.diagnostic_file_mime,
            diagnostic_file_size = EXCLUDED.diagnostic_file_size,
            diagnostic_uploaded_at = EXCLUDED.diagnostic_uploaded_at,
            doctor_id = EXCLUDED.doctor_id,
            doctor_snapshot_name = EXCLUDED.doctor_snapshot_name,
            user_id = EXCLUDED.user_id
        RETURNING id::text AS id, (xmax = 0) AS inserted
    `;

    try {
        const result = await pool.query(sql, [
            payload.legacyMongoId,
            payload.name,
            payload.phone,
            payload.type,
            payload.date,
            payload.time,
            payload.notes,
            payload.email,
            payload.emailSent,
            payload.hasDiagnosis,
            payload.diagnosticFileKey,
            payload.diagnosticFileMime,
            payload.diagnosticFileSize,
            payload.diagnosticUploadedAt ? payload.diagnosticUploadedAt.toISOString() : null,
            payload.doctorPgId,
            payload.doctorSnapshotName,
            payload.userPgId,
            payload.createdAt ? payload.createdAt.toISOString() : null
        ]);
        return { id: result.rows[0].id, inserted: !!result.rows[0].inserted };
    } catch (error) {
        if (error?.code !== '23505') {
            throw error;
        }

        const conflict = await pool.query(
            `
            SELECT id::text AS id, TRIM(legacy_mongo_id) AS legacy_mongo_id
            FROM appointments
            WHERE doctor_id = $1::uuid
              AND appointment_date = $2::date
              AND appointment_time = $3::time
            LIMIT 1
            `,
            [payload.doctorPgId, payload.date, payload.time]
        );
        const row = conflict.rows[0];
        const existingLegacy = toSafeString(row?.legacy_mongo_id).trim();
        if (row && existingLegacy && existingLegacy !== payload.legacyMongoId) {
            throw createMigrationConflictError(
                `Appointment slot conflict for doctor ${payload.doctorLegacyMongoId} at ${payload.date} ${payload.time}.`,
                {
                    doctorLegacyMongoId: payload.doctorLegacyMongoId,
                    date: payload.date,
                    time: payload.time,
                    legacyMongoId: payload.legacyMongoId,
                    existingLegacyMongoId: existingLegacy
                }
            );
        }
        throw error;
    }
}

async function upsertAuditLog(pool, payload) {
    const sql = `
        INSERT INTO audit_logs (
            legacy_mongo_id,
            actor_user_id,
            actor_role,
            action,
            target_type,
            target_id,
            result,
            ip,
            user_agent,
            metadata,
            logged_at
        )
        VALUES (
            $1, $2::uuid, $3, $4, $5, $6, $7::audit_log_result, $8, $9, $10::jsonb, COALESCE($11::timestamptz, now())
        )
        ON CONFLICT (legacy_mongo_id)
        DO UPDATE SET
            actor_user_id = EXCLUDED.actor_user_id,
            actor_role = EXCLUDED.actor_role,
            action = EXCLUDED.action,
            target_type = EXCLUDED.target_type,
            target_id = EXCLUDED.target_id,
            result = EXCLUDED.result,
            ip = EXCLUDED.ip,
            user_agent = EXCLUDED.user_agent,
            metadata = EXCLUDED.metadata,
            logged_at = EXCLUDED.logged_at
        RETURNING id::bigint AS id, (xmax = 0) AS inserted
    `;

    const result = await pool.query(sql, [
        payload.legacyMongoId,
        payload.actorUserPgId,
        payload.actorRole,
        payload.action,
        payload.targetType,
        payload.targetId,
        payload.result,
        payload.ip,
        payload.userAgent,
        JSON.stringify(payload.metadata),
        payload.loggedAt ? payload.loggedAt.toISOString() : null
    ]);
    return { id: result.rows[0].id, inserted: !!result.rows[0].inserted };
}

function pickCollectionName(availableSet, candidates = []) {
    for (const candidate of candidates) {
        if (availableSet.has(candidate)) {
            return candidate;
        }
    }
    return candidates[0] || null;
}
async function validateCounts({ pool, report }) {
    const oneCount = async (sql) => {
        const result = await pool.query(sql);
        return Number(result.rows?.[0]?.count || 0);
    };

    report.validations.counts = {
        users: {
            mongo: report.entities.users.mongoCount,
            postgres: await oneCount('SELECT COUNT(*)::bigint AS count FROM users')
        },
        doctors: {
            mongo: report.entities.doctors.mongoCount,
            postgres: await oneCount('SELECT COUNT(*)::bigint AS count FROM doctors')
        },
        doctorAdminAssignments: {
            mongoDerived: report.entities.doctorAdminAssignments.mongoCount,
            postgres: await oneCount('SELECT COUNT(*)::bigint AS count FROM doctor_admin_assignments')
        },
        doctorAvailabilityRules: {
            mongoDerived: report.entities.doctorAvailabilityRules.mongoCount,
            postgres: await oneCount('SELECT COUNT(*)::bigint AS count FROM doctor_availability_rules')
        },
        doctorBlockedDays: {
            mongoDerived: report.entities.doctorBlockedDays.mongoCount,
            postgres: await oneCount('SELECT COUNT(*)::bigint AS count FROM doctor_blocked_days')
        },
        appointments: {
            mongo: report.entities.appointments.mongoCount,
            postgres: await oneCount('SELECT COUNT(*)::bigint AS count FROM appointments')
        },
        auditLogs: {
            mongo: report.entities.auditLogs.mongoCount,
            postgres: await oneCount('SELECT COUNT(*)::bigint AS count FROM audit_logs')
        }
    };
}

async function validateSamples({ pool, report, userSampleTracker, doctorSampleTracker, appointmentSampleTracker }) {
    if (report.options.dryRun) {
        report.validations.samples = {
            skipped: true,
            reason: 'dry-run mode'
        };
        return;
    }

    const userChecks = [];
    for (const sample of userSampleTracker.items) {
        const result = await pool.query(
            `
            SELECT TRIM(legacy_mongo_id) AS legacy_mongo_id, email, phone, role
            FROM users
            WHERE TRIM(legacy_mongo_id) = $1
            LIMIT 1
            `,
            [sample.legacyMongoId]
        );
        const row = result.rows[0];
        const mismatches = [];
        if (!row) {
            mismatches.push('missing_row');
        } else {
            if ((row.email || null) !== (sample.email || null)) mismatches.push('email');
            if ((row.phone || null) !== (sample.phone || null)) mismatches.push('phone');
            if (toSafeString(row.role) !== toSafeString(sample.role)) mismatches.push('role');
        }
        userChecks.push({ legacyMongoId: sample.legacyMongoId, ok: mismatches.length === 0, mismatches });
    }

    const doctorChecks = [];
    for (const sample of doctorSampleTracker.items) {
        const result = await pool.query(
            `
            SELECT TRIM(legacy_mongo_id) AS legacy_mongo_id, slug, display_name, is_active
            FROM doctors
            WHERE TRIM(legacy_mongo_id) = $1
            LIMIT 1
            `,
            [sample.legacyMongoId]
        );
        const row = result.rows[0];
        const mismatches = [];
        if (!row) {
            mismatches.push('missing_row');
        } else {
            if (toSafeString(row.slug) !== toSafeString(sample.slug)) mismatches.push('slug');
            if (toSafeString(row.display_name) !== toSafeString(sample.displayName)) mismatches.push('display_name');
            if (!!row.is_active !== !!sample.isActive) mismatches.push('is_active');
        }
        doctorChecks.push({ legacyMongoId: sample.legacyMongoId, ok: mismatches.length === 0, mismatches });
    }

    const appointmentChecks = [];
    for (const sample of appointmentSampleTracker.items) {
        const result = await pool.query(
            `
            SELECT
                TRIM(a.legacy_mongo_id) AS legacy_mongo_id,
                a.appointment_date::text AS appointment_date,
                to_char(a.appointment_time, 'HH24:MI') AS appointment_time,
                a.email,
                TRIM(d.legacy_mongo_id) AS doctor_legacy_mongo_id
            FROM appointments a
            JOIN doctors d ON d.id = a.doctor_id
            WHERE TRIM(a.legacy_mongo_id) = $1
            LIMIT 1
            `,
            [sample.legacyMongoId]
        );
        const row = result.rows[0];
        const mismatches = [];
        if (!row) {
            mismatches.push('missing_row');
        } else {
            if (toSafeString(row.doctor_legacy_mongo_id) !== toSafeString(sample.doctorLegacyMongoId)) mismatches.push('doctor');
            if (toSafeString(row.appointment_date) !== toSafeString(sample.date)) mismatches.push('date');
            if (toSafeString(row.appointment_time) !== toSafeString(sample.time)) mismatches.push('time');
            if (toSafeString(row.email || '') !== toSafeString(sample.email || '')) mismatches.push('email');
        }
        appointmentChecks.push({ legacyMongoId: sample.legacyMongoId, ok: mismatches.length === 0, mismatches });
    }

    report.validations.samples = {
        users: userChecks,
        doctors: doctorChecks,
        appointments: appointmentChecks
    };
}

async function validateReferentialIntegrity({ pool, report }) {
    const oneCount = async (sql) => {
        const result = await pool.query(sql);
        return Number(result.rows?.[0]?.count || 0);
    };

    report.validations.referentialIntegrity = {
        assignmentsMissingUserRow: await oneCount(`
            SELECT COUNT(*)::bigint AS count
            FROM doctor_admin_assignments daa
            LEFT JOIN users u ON u.id = daa.user_id
            WHERE u.id IS NULL
        `),
        assignmentsMissingDoctorBinding: await oneCount(`
            SELECT COUNT(*)::bigint AS count
            FROM doctor_admin_assignments
            WHERE legacy_doctor_mongo_id IS NOT NULL
              AND doctor_id IS NULL
        `),
        assignmentsDoctorLegacyMismatch: await oneCount(`
            SELECT COUNT(*)::bigint AS count
            FROM doctor_admin_assignments daa
            JOIN doctors d ON d.id = daa.doctor_id
            WHERE daa.legacy_doctor_mongo_id IS NOT NULL
              AND TRIM(d.legacy_mongo_id) <> TRIM(daa.legacy_doctor_mongo_id)
        `),
        appointmentsMissingDoctorRow: await oneCount(`
            SELECT COUNT(*)::bigint AS count
            FROM appointments a
            LEFT JOIN doctors d ON d.id = a.doctor_id
            WHERE d.id IS NULL
        `),
        appointmentsMissingUserRow: await oneCount(`
            SELECT COUNT(*)::bigint AS count
            FROM appointments a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.user_id IS NOT NULL
              AND u.id IS NULL
        `),
        duplicateAppointmentSlots: await oneCount(`
            SELECT COUNT(*)::bigint AS count
            FROM (
                SELECT doctor_id, appointment_date, appointment_time, COUNT(*) AS c
                FROM appointments
                GROUP BY doctor_id, appointment_date, appointment_time
                HAVING COUNT(*) > 1
            ) x
        `)
    };

    report.validations.duplicateAndConflictSummary = {
        usersConflicts: report.entities.users.conflicts,
        doctorsConflicts: report.entities.doctors.conflicts,
        appointmentsConflicts: report.entities.appointments.conflicts,
        auditLogConflicts: report.entities.auditLogs.conflicts
    };
}

function computeTotals(report) {
    const totals = {
        processed: 0,
        inserted: 0,
        updated: 0,
        skipped: 0,
        conflicts: 0,
        errors: 0,
        unresolvedReferences: 0,
        dryRunPlanned: 0
    };

    for (const entity of Object.values(report.entities)) {
        totals.processed += Number(entity.processed || 0);
        totals.inserted += Number(entity.inserted || 0);
        totals.updated += Number(entity.updated || 0);
        totals.skipped += Number(entity.skipped || 0);
        totals.conflicts += Number(entity.conflicts || 0);
        totals.errors += Number(entity.errors || 0);
        totals.unresolvedReferences += Number(entity.unresolvedReferences || 0);
        totals.dryRunPlanned += Number(entity.dryRunPlanned || 0);
    }

    return totals;
}

async function connectMongoClient() {
    const mongoTlsPolicy = buildMongoTlsPolicy(process.env);
    if (mongoTlsPolicy.validationErrors.length) {
        throw new Error(mongoTlsPolicy.validationErrors.join(' '));
    }

    const tryConnect = async (minVersion) => {
        const options = buildMongoDriverTlsOptions(mongoTlsPolicy, minVersion);
        const client = new MongoClient(mongoTlsPolicy.mongodbUri, {
            ...options,
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 10000
        });
        await client.connect();
        return client;
    };

    try {
        const client = await tryConnect(mongoTlsPolicy.configuredMinVersion);
        return {
            client,
            policy: mongoTlsPolicy,
            effectiveMinVersion: mongoTlsPolicy.configuredMinVersion,
            fallbackToTls12Used: false
        };
    } catch (error) {
        if (
            !isLikelyTlsCompatibilityError(error)
            || !mongoTlsPolicy.allowFallbackTo12
            || mongoTlsPolicy.configuredMinVersion === FALLBACK_MONGO_TLS_MIN_VERSION
        ) {
            throw error;
        }

        const fallbackClient = await tryConnect(FALLBACK_MONGO_TLS_MIN_VERSION);
        return {
            client: fallbackClient,
            policy: mongoTlsPolicy,
            effectiveMinVersion: FALLBACK_MONGO_TLS_MIN_VERSION,
            fallbackToTls12Used: true
        };
    }
}
async function run() {
    const options = parseCliArgs(process.argv.slice(2));

    const databaseUrlValidation = validateDatabaseUrl(process.env.DATABASE_URL);
    if (!databaseUrlValidation.ok) {
        throw new Error(databaseUrlValidation.errors.join(' '));
    }
    if (!process.env.MONGODB_URI || !String(process.env.MONGODB_URI).trim()) {
        throw new Error('MONGODB_URI is required.');
    }

    const report = {
        startedAt: new Date().toISOString(),
        finishedAt: null,
        durationMs: null,
        idempotencyStrategy: 'rerun-safe upserts for core entities + replace-per-source for assignments/rules/blocked days',
        options: {
            dryRun: options.dryRun,
            includeAuditLogs: options.includeAuditLogs,
            batchSize: options.batchSize,
            sampleSize: options.sampleSize
        },
        source: {},
        target: {
            postgresTarget: getPostgresTargetSummary(process.env.DATABASE_URL)
        },
        mappings: {
            users: 0,
            doctors: 0
        },
        entities: {
            users: createEntityReport('users'),
            doctors: createEntityReport('doctors'),
            doctorAdminAssignments: createEntityReport('doctor_admin_assignments'),
            doctorAvailabilityRules: createEntityReport('doctor_availability_rules'),
            doctorBlockedDays: createEntityReport('doctor_blocked_days'),
            appointments: createEntityReport('appointments'),
            auditLogs: createEntityReport('audit_logs')
        },
        validations: {},
        totals: {}
    };

    const userIdMap = new Map();
    const doctorIdMap = new Map();
    const doctorDisplayNameMap = new Map();
    const assignmentSources = [];
    const doctorSources = [];

    const userSampleTracker = { limit: options.sampleSize, seen: 0, items: [] };
    const doctorSampleTracker = { limit: options.sampleSize, seen: 0, items: [] };
    const appointmentSampleTracker = { limit: options.sampleSize, seen: 0, items: [] };

    const startedAtMs = Date.now();

    let mongoClient;
    const pool = getPostgresPool();

    try {
        console.log(`[MIGRATE] Starting migration (dryRun=${options.dryRun}, includeAuditLogs=${options.includeAuditLogs})`);
        console.log(`[MIGRATE] Postgres target: ${report.target.postgresTarget}`);

        const mongoConnection = await connectMongoClient();
        mongoClient = mongoConnection.client;
        report.source.mongoHosts = mongoConnection.policy.redactedHosts;
        report.source.mongoHostCount = mongoConnection.policy.hostCount;
        report.source.mongoTlsConfiguredMinVersion = mongoConnection.policy.configuredMinVersion;
        report.source.mongoTlsEffectiveMinVersion = mongoConnection.effectiveMinVersion;
        report.source.mongoTlsFallbackTo12Used = mongoConnection.fallbackToTls12Used;

        const mongoDb = options.mongoDbName ? mongoClient.db(options.mongoDbName) : mongoClient.db();
        report.source.mongoDatabase = mongoDb.databaseName;

        const collections = await mongoDb.listCollections({}, { nameOnly: true }).toArray();
        const collectionNames = new Set(collections.map((entry) => entry.name));
        const usersCollectionName = pickCollectionName(collectionNames, ['users']);
        const doctorsCollectionName = pickCollectionName(collectionNames, ['doctors']);
        const appointmentsCollectionName = pickCollectionName(collectionNames, ['appointments']);
        const auditLogsCollectionName = pickCollectionName(collectionNames, ['auditlogs', 'audit_logs']);

        const usersCollection = mongoDb.collection(usersCollectionName || 'users');
        const doctorsCollection = mongoDb.collection(doctorsCollectionName || 'doctors');
        const appointmentsCollection = mongoDb.collection(appointmentsCollectionName || 'appointments');
        const auditLogsCollection = mongoDb.collection(auditLogsCollectionName || 'auditlogs');

        if (!auditLogsCollectionName) {
            report.entities.auditLogs.notes.push('Mongo audit log collection not found (`auditlogs` or `audit_logs`).');
        }

        console.log('[MIGRATE] Step 1/7 users');
        report.entities.users.mongoCount = await usersCollection.countDocuments({});
        let userProcessedSinceLog = 0;
        for await (const doc of usersCollection.find({}, { batchSize: options.batchSize })) {
            const entity = report.entities.users;
            entity.processed += 1;
            userProcessedSinceLog += 1;

            const legacyMongoId = normalizeLegacyObjectId(doc?._id);
            const managedDoctorLegacyIds = normalizeManagedDoctorIds(doc?.managedDoctorIds || []);
            if (legacyMongoId) {
                assignmentSources.push({ userLegacyMongoId: legacyMongoId, managedDoctorLegacyIds });
                addReservoirSample(userSampleTracker, {
                    legacyMongoId,
                    email: normalizeEmail(doc?.email),
                    phone: normalizePhone(doc?.phone),
                    role: normalizeRole(doc?.role)
                });
            }

            if (!legacyMongoId) {
                entity.skipped += 1;
                pushEntityError(entity, new Error('Invalid user _id; expected ObjectId.'), { sourceId: toSafeString(doc?._id || '') });
                continue;
            }

            const payload = {
                legacyMongoId,
                email: normalizeEmail(doc?.email),
                phone: normalizePhone(doc?.phone),
                passwordHash: toSafeString(doc?.password || ''),
                googleId: toSafeString(doc?.googleId).trim() || null,
                displayName: normalizeDisplayName(doc?.displayName),
                role: normalizeRole(doc?.role),
                createdAt: normalizeMongoDate(doc?.createdAt, new Date())
            };

            if (options.dryRun) {
                entity.dryRunPlanned += 1;
                userIdMap.set(payload.legacyMongoId, payload.legacyMongoId);
                continue;
            }

            try {
                const result = await upsertUser(pool, payload);
                if (result.inserted) entity.inserted += 1; else entity.updated += 1;
                userIdMap.set(payload.legacyMongoId, result.id);
            } catch (error) {
                if (error?.code === 'MIGRATION_CONFLICT') {
                    entity.conflicts += 1;
                }
                entity.skipped += 1;
                pushEntityError(entity, error, { sourceId: payload.legacyMongoId });
            }

            if (userProcessedSinceLog >= 500) {
                userProcessedSinceLog = 0;
                console.log(`[MIGRATE] users processed=${entity.processed}/${entity.mongoCount}`);
            }
        }

        if (!options.dryRun) {
            await loadUserIdMap(pool, userIdMap);
        }
        report.mappings.users = userIdMap.size;

        console.log('[MIGRATE] Step 2/7 doctors');
        report.entities.doctors.mongoCount = await doctorsCollection.countDocuments({});
        let doctorProcessedSinceLog = 0;
        for await (const doc of doctorsCollection.find({}, { batchSize: options.batchSize })) {
            const entity = report.entities.doctors;
            entity.processed += 1;
            doctorProcessedSinceLog += 1;

            const source = {
                legacyMongoId: normalizeLegacyObjectId(doc?._id),
                slug: normalizeSlug(doc?.slug),
                displayName: normalizeDisplayName(doc?.displayName, 'Doctor'),
                specialty: toSafeString(doc?.specialty).trim() || DEFAULT_DOCTOR_SPECIALTY,
                isActive: doc?.isActive !== false,
                bookingSettings: normalizeDoctorBookingSettings(doc?.bookingSettings || {}),
                weekdays: (() => {
                    const normalized = normalizeWeekdays(doc?.availabilityRules?.weekdays || []);
                    return normalized.length ? normalized : [...DEFAULT_AVAILABILITY_WEEKDAYS];
                })(),
                blockedDates: normalizeBlockedDates(doc?.blockedDates || []),
                createdByLegacyUserId: normalizeLegacyObjectId(doc?.createdByUserId),
                updatedByLegacyUserId: normalizeLegacyObjectId(doc?.updatedByUserId),
                createdAt: normalizeMongoDate(doc?.createdAt, new Date()),
                updatedAt: normalizeMongoDate(doc?.updatedAt, normalizeMongoDate(doc?.createdAt, new Date()))
            };

            if (source.legacyMongoId) {
                doctorSources.push(source);
                doctorDisplayNameMap.set(source.legacyMongoId, source.displayName);
                addReservoirSample(doctorSampleTracker, {
                    legacyMongoId: source.legacyMongoId,
                    slug: source.slug,
                    displayName: source.displayName,
                    isActive: source.isActive
                });
            }

            if (!source.legacyMongoId || !source.slug) {
                entity.skipped += 1;
                pushEntityError(entity, new Error('Doctor row missing valid _id or slug.'), {
                    sourceId: toSafeString(doc?._id || ''),
                    slug: toSafeString(doc?.slug || '')
                });
                continue;
            }

            if (options.dryRun) {
                entity.dryRunPlanned += 1;
                doctorIdMap.set(source.legacyMongoId, source.legacyMongoId);
                continue;
            }

            const payload = {
                ...source,
                createdByUserPgId: source.createdByLegacyUserId ? (userIdMap.get(source.createdByLegacyUserId) || null) : null,
                updatedByUserPgId: source.updatedByLegacyUserId
                    ? (userIdMap.get(source.updatedByLegacyUserId) || null)
                    : (source.createdByLegacyUserId ? (userIdMap.get(source.createdByLegacyUserId) || null) : null)
            };

            try {
                const result = await upsertDoctor(pool, payload);
                if (result.inserted) entity.inserted += 1; else entity.updated += 1;
                doctorIdMap.set(payload.legacyMongoId, result.id);
            } catch (error) {
                if (error?.code === 'MIGRATION_CONFLICT') {
                    entity.conflicts += 1;
                }
                entity.skipped += 1;
                pushEntityError(entity, error, { sourceId: payload.legacyMongoId, slug: payload.slug });
            }

            if (doctorProcessedSinceLog >= 500) {
                doctorProcessedSinceLog = 0;
                console.log(`[MIGRATE] doctors processed=${entity.processed}/${entity.mongoCount}`);
            }
        }

        if (!options.dryRun) {
            await loadDoctorIdMap(pool, doctorIdMap);
        }
        report.mappings.doctors = doctorIdMap.size;

        console.log('[MIGRATE] Step 3/7 doctor_admin_assignments');
        {
            const entity = report.entities.doctorAdminAssignments;
            const uniquePairs = new Set();
            for (const source of assignmentSources) {
                for (const doctorLegacyId of source.managedDoctorLegacyIds) {
                    uniquePairs.add(`${source.userLegacyMongoId}:${doctorLegacyId}`);
                }
            }
            entity.mongoCount = uniquePairs.size;

            for (const source of assignmentSources) {
                entity.processed += 1;
                const userPgId = userIdMap.get(source.userLegacyMongoId);
                const uniqueDoctorIds = Array.from(new Set(source.managedDoctorLegacyIds));

                if (!userPgId) {
                    entity.unresolvedReferences += 1;
                    entity.skipped += 1;
                    pushEntityError(entity, new Error('User id mapping missing while creating doctor assignments.'), {
                        userLegacyMongoId: source.userLegacyMongoId
                    });
                    continue;
                }

                if (options.dryRun) {
                    entity.dryRunPlanned += uniqueDoctorIds.length;
                    continue;
                }

                try {
                    await withPgTransaction(pool, async (client) => {
                        await client.query(`DELETE FROM doctor_admin_assignments WHERE user_id = $1::uuid`, [userPgId]);
                        for (const doctorLegacyId of uniqueDoctorIds) {
                            const doctorPgId = doctorIdMap.get(doctorLegacyId) || null;
                            if (!doctorPgId) {
                                entity.unresolvedReferences += 1;
                            }
                            await client.query(
                                `
                                INSERT INTO doctor_admin_assignments (
                                    doctor_id,
                                    user_id,
                                    legacy_doctor_mongo_id,
                                    legacy_user_mongo_id
                                )
                                VALUES ($1::uuid, $2::uuid, $3, $4)
                                `,
                                [doctorPgId, userPgId, doctorLegacyId, source.userLegacyMongoId]
                            );
                            entity.inserted += 1;
                        }
                    });
                } catch (error) {
                    entity.skipped += 1;
                    pushEntityError(entity, error, { userLegacyMongoId: source.userLegacyMongoId });
                }
            }
        }

        console.log('[MIGRATE] Step 4/7 doctor_availability_rules');
        {
            const entity = report.entities.doctorAvailabilityRules;
            entity.mongoCount = doctorSources.reduce((acc, source) => acc + source.weekdays.length, 0);

            for (const source of doctorSources) {
                entity.processed += 1;
                const doctorPgId = doctorIdMap.get(source.legacyMongoId);
                if (!doctorPgId) {
                    entity.unresolvedReferences += 1;
                    entity.skipped += 1;
                    pushEntityError(entity, new Error('Doctor id mapping missing while migrating availability rules.'), {
                        doctorLegacyMongoId: source.legacyMongoId
                    });
                    continue;
                }

                if (options.dryRun) {
                    entity.dryRunPlanned += source.weekdays.length;
                    continue;
                }

                try {
                    await withPgTransaction(pool, async (client) => {
                        await client.query(`DELETE FROM doctor_availability_rules WHERE doctor_id = $1::uuid`, [doctorPgId]);
                        for (const weekday of source.weekdays) {
                            await client.query(
                                `
                                INSERT INTO doctor_availability_rules (
                                    doctor_id,
                                    weekday,
                                    start_time,
                                    end_time,
                                    slot_minutes,
                                    is_active,
                                    effective_from,
                                    effective_to
                                )
                                VALUES (
                                    $1::uuid,
                                    $2,
                                    $3::time,
                                    $4::time,
                                    $5,
                                    TRUE,
                                    NULL,
                                    NULL
                                )
                                `,
                                [doctorPgId, weekday, source.bookingSettings.workdayStart, source.bookingSettings.workdayEnd, source.bookingSettings.consultationDurationMinutes]
                            );
                            entity.inserted += 1;
                        }
                    });
                } catch (error) {
                    entity.skipped += 1;
                    pushEntityError(entity, error, { doctorLegacyMongoId: source.legacyMongoId });
                }
            }
        }

        console.log('[MIGRATE] Step 5/7 doctor_blocked_days');
        {
            const entity = report.entities.doctorBlockedDays;
            entity.mongoCount = doctorSources.reduce((acc, source) => acc + source.blockedDates.length, 0);

            for (const source of doctorSources) {
                entity.processed += 1;
                const doctorPgId = doctorIdMap.get(source.legacyMongoId);
                if (!doctorPgId) {
                    entity.unresolvedReferences += 1;
                    entity.skipped += 1;
                    pushEntityError(entity, new Error('Doctor id mapping missing while migrating blocked days.'), {
                        doctorLegacyMongoId: source.legacyMongoId
                    });
                    continue;
                }

                const actorLegacyUserId = source.updatedByLegacyUserId || source.createdByLegacyUserId;
                const actorUserPgId = actorLegacyUserId ? (userIdMap.get(actorLegacyUserId) || null) : null;

                if (options.dryRun) {
                    entity.dryRunPlanned += source.blockedDates.length;
                    continue;
                }

                try {
                    await withPgTransaction(pool, async (client) => {
                        await client.query(`DELETE FROM doctor_blocked_days WHERE doctor_id = $1::uuid`, [doctorPgId]);
                        for (const blockedDate of source.blockedDates) {
                            await client.query(
                                `
                                INSERT INTO doctor_blocked_days (
                                    doctor_id,
                                    blocked_date,
                                    reason,
                                    is_active,
                                    created_by_user_id,
                                    updated_by_user_id,
                                    disabled_at,
                                    disabled_by_user_id
                                )
                                VALUES ($1::uuid, $2::date, NULL, TRUE, $3::uuid, $3::uuid, NULL, NULL)
                                `,
                                [doctorPgId, blockedDate, actorUserPgId]
                            );
                            entity.inserted += 1;
                        }
                    });
                } catch (error) {
                    entity.skipped += 1;
                    pushEntityError(entity, error, { doctorLegacyMongoId: source.legacyMongoId });
                }
            }
        }
        console.log('[MIGRATE] Step 6/7 appointments');
        report.entities.appointments.mongoCount = await appointmentsCollection.countDocuments({});
        let appointmentProcessedSinceLog = 0;
        for await (const doc of appointmentsCollection.find({}, { batchSize: options.batchSize })) {
            const entity = report.entities.appointments;
            entity.processed += 1;
            appointmentProcessedSinceLog += 1;

            const legacyMongoId = normalizeLegacyObjectId(doc?._id);
            const doctorLegacyMongoId = normalizeLegacyObjectId(doc?.doctorId);
            const date = normalizeISODate(doc?.date);
            const time = normalizeTimeHHMM(doc?.time);

            if (!legacyMongoId || !doctorLegacyMongoId || !date || !time) {
                entity.skipped += 1;
                pushEntityError(entity, new Error('Appointment missing valid _id/doctor/date/time.'), {
                    sourceId: toSafeString(doc?._id || ''),
                    doctorId: toSafeString(doc?.doctorId || ''),
                    date: toSafeString(doc?.date || ''),
                    time: toSafeString(doc?.time || '')
                });
                continue;
            }

            const doctorPgId = doctorIdMap.get(doctorLegacyMongoId);
            if (!doctorPgId) {
                entity.unresolvedReferences += 1;
                entity.skipped += 1;
                pushEntityError(entity, new Error('Doctor mapping missing for appointment.'), {
                    sourceId: legacyMongoId,
                    doctorLegacyMongoId
                });
                continue;
            }

            const userLegacyMongoId = normalizeLegacyObjectId(doc?.userId);
            const userPgId = userLegacyMongoId ? (userIdMap.get(userLegacyMongoId) || null) : null;
            if (userLegacyMongoId && !userPgId) {
                entity.unresolvedReferences += 1;
            }

            const diagnosticMeta = doc?.diagnosticFileMeta && typeof doc.diagnosticFileMeta === 'object'
                ? doc.diagnosticFileMeta
                : {};

            const payload = {
                legacyMongoId,
                name: toSafeString(doc?.name).trim(),
                phone: toSafeString(doc?.phone).trim(),
                type: toSafeString(doc?.type).trim(),
                date,
                time,
                notes: toSafeString(doc?.notes || ''),
                email: normalizeEmail(doc?.email) || '',
                emailSent: !!doc?.emailSent,
                hasDiagnosis: !!doc?.hasDiagnosis,
                diagnosticFileKey: toSafeString(diagnosticMeta?.key).trim() || null,
                diagnosticFileMime: toSafeString(diagnosticMeta?.mime).trim() || null,
                diagnosticFileSize: Number.isInteger(Number(diagnosticMeta?.size)) ? Number(diagnosticMeta.size) : null,
                diagnosticUploadedAt: normalizeMongoDate(diagnosticMeta?.uploadedAt, null),
                doctorPgId,
                doctorLegacyMongoId,
                doctorSnapshotName: toSafeString(doc?.doctorSnapshotName).trim() || doctorDisplayNameMap.get(doctorLegacyMongoId) || '',
                userPgId,
                createdAt: normalizeMongoDate(doc?.createdAt, new Date())
            };

            addReservoirSample(appointmentSampleTracker, {
                legacyMongoId,
                doctorLegacyMongoId,
                date,
                time,
                email: payload.email
            });

            if (options.dryRun) {
                entity.dryRunPlanned += 1;
                continue;
            }

            try {
                const result = await upsertAppointment(pool, payload);
                if (result.inserted) entity.inserted += 1; else entity.updated += 1;
            } catch (error) {
                if (error?.code === 'MIGRATION_CONFLICT') {
                    entity.conflicts += 1;
                }
                entity.skipped += 1;
                pushEntityError(entity, error, {
                    sourceId: legacyMongoId,
                    doctorLegacyMongoId,
                    date,
                    time
                });
            }

            if (appointmentProcessedSinceLog >= 500) {
                appointmentProcessedSinceLog = 0;
                console.log(`[MIGRATE] appointments processed=${entity.processed}/${entity.mongoCount}`);
            }
        }

        console.log('[MIGRATE] Step 7/7 audit_logs');
        if (!options.includeAuditLogs) {
            report.entities.auditLogs.notes.push('Skipped: run with --include-audit-logs to migrate audit logs.');
        } else {
            report.entities.auditLogs.mongoCount = await auditLogsCollection.countDocuments({});
            let auditProcessedSinceLog = 0;

            for await (const doc of auditLogsCollection.find({}, { batchSize: options.batchSize })) {
                const entity = report.entities.auditLogs;
                entity.processed += 1;
                auditProcessedSinceLog += 1;

                const legacyMongoId = normalizeLegacyObjectId(doc?._id) || crypto.randomBytes(12).toString('hex');
                const actorLegacyUserId = normalizeLegacyObjectId(doc?.actorUserId);
                const actorUserPgId = actorLegacyUserId ? (userIdMap.get(actorLegacyUserId) || null) : null;
                if (actorLegacyUserId && !actorUserPgId) {
                    entity.unresolvedReferences += 1;
                }

                const action = toSafeString(doc?.action).trim();
                if (!action) {
                    entity.skipped += 1;
                    pushEntityError(entity, new Error('Audit log action is required.'), { sourceId: legacyMongoId });
                    continue;
                }

                const payload = {
                    legacyMongoId,
                    actorUserPgId,
                    actorRole: toSafeString(doc?.actorRole || 'anonymous').trim() || 'anonymous',
                    action,
                    targetType: toSafeString(doc?.targetType || '').trim(),
                    targetId: toSafeString(doc?.targetId || '').trim(),
                    result: normalizeAuditResult(doc?.result),
                    ip: toSafeString(doc?.ip || '').trim(),
                    userAgent: toSafeString(doc?.userAgent || '').slice(0, 512),
                    metadata: toSerializableJson(doc?.metadata || {}),
                    loggedAt: normalizeMongoDate(doc?.timestamp, new Date())
                };

                if (options.dryRun) {
                    entity.dryRunPlanned += 1;
                    continue;
                }

                try {
                    const result = await upsertAuditLog(pool, payload);
                    if (result.inserted) entity.inserted += 1; else entity.updated += 1;
                } catch (error) {
                    entity.skipped += 1;
                    pushEntityError(entity, error, { sourceId: legacyMongoId });
                }

                if (auditProcessedSinceLog >= 500) {
                    auditProcessedSinceLog = 0;
                    console.log(`[MIGRATE] auditLogs processed=${entity.processed}/${entity.mongoCount}`);
                }
            }
        }

        console.log('[MIGRATE] Running validations');
        await validateCounts({ pool, report });
        await validateSamples({ pool, report, userSampleTracker, doctorSampleTracker, appointmentSampleTracker });
        await validateReferentialIntegrity({ pool, report });

        report.totals = computeTotals(report);
        report.finishedAt = new Date().toISOString();
        report.durationMs = Date.now() - startedAtMs;

        if (options.reportFile) {
            const absolutePath = path.resolve(process.cwd(), options.reportFile);
            fs.writeFileSync(absolutePath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
            console.log(`[MIGRATE] Report written: ${absolutePath}`);
        }

        console.log('[MIGRATE] Migration report:');
        console.log(JSON.stringify(report, null, 2));

        if (report.totals.errors > 0) {
            console.error(`[MIGRATE] Completed with ${report.totals.errors} errors.`);
            process.exitCode = 1;
        } else if (report.totals.conflicts > 0 || report.totals.unresolvedReferences > 0) {
            console.warn(
                `[MIGRATE] Completed with warnings `
                + `(conflicts=${report.totals.conflicts}, unresolvedReferences=${report.totals.unresolvedReferences}).`
            );
        } else {
            console.log('[MIGRATE] Completed successfully.');
        }
    } finally {
        if (mongoClient) {
            try {
                await mongoClient.close();
            } catch (error) {
                const safeMongoError = getSafeMongoErrorSummary(error);
                console.error(`[MIGRATE] Mongo close warning: ${safeMongoError.name}: ${safeMongoError.message}`);
            }
        }
        await closePostgresPool();
    }
}

run().catch((error) => {
    console.error(`[MIGRATE] Failed: ${toErrorMessage(error)}`);
    process.exit(1);
});
