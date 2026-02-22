const crypto = require('crypto');
const { getPostgresPool } = require('./postgres');

const LEGACY_OBJECT_ID_REGEX = /^[a-fA-F0-9]{24}$/;
const POSTGRES_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TIME_HHMM_REGEX = /^([01]\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?$/;
const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;
const APPOINTMENT_SLOT_CONSTRAINTS = new Set([
    'appointments_doctor_id_appointment_date_appointment_time_key'
]);

class BookingValidationError extends Error {
    constructor(message, { code = 'booking_validation_error', status = 400 } = {}) {
        super(message);
        this.name = 'BookingValidationError';
        this.code = code;
        this.status = status;
    }
}

function isUniqueViolation(error) {
    return error?.code === '23505';
}

function isPostgresUuid(value) {
    return POSTGRES_UUID_REGEX.test(String(value || '').trim());
}

function isAppointmentSlotUniqueViolation(error) {
    if (!isUniqueViolation(error)) {
        return false;
    }

    const constraintName = String(error?.constraint || '').trim();
    if (constraintName && APPOINTMENT_SLOT_CONSTRAINTS.has(constraintName)) {
        return true;
    }

    const detail = String(error?.detail || '');
    return /\(doctor_id,\s*appointment_date,\s*appointment_time\)=/i.test(detail);
}

function generateLegacyPublicId() {
    return crypto.randomBytes(12).toString('hex');
}

function normalizePublicId(value) {
    const normalized = String(value || '').trim();
    return normalized || null;
}

function normalizeLegacyObjectId(value) {
    const normalized = String(value || '').trim();
    if (!LEGACY_OBJECT_ID_REGEX.test(normalized)) {
        return null;
    }
    return normalized;
}

function normalizeISODate(value) {
    const normalized = String(value || '').trim();
    if (!ISO_DATE_REGEX.test(normalized)) {
        return null;
    }
    return normalized;
}

function normalizeTimeHHMM(value) {
    const normalized = String(value || '').trim();
    const match = normalized.match(TIME_HHMM_REGEX);
    if (!match) {
        return null;
    }
    return `${match[1]}:${match[2]}`;
}

function parseTimeToMinutes(value) {
    const normalized = normalizeTimeHHMM(value);
    if (!normalized) return NaN;
    const [hours, minutes] = normalized.split(':').map(Number);
    return (hours * 60) + minutes;
}

function minutesToTime(value) {
    const hours = Math.floor(value / 60);
    const minutes = value % 60;
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
}

function generateSlots({ startTime, endTime, slotMinutes }) {
    const start = parseTimeToMinutes(startTime);
    const end = parseTimeToMinutes(endTime);
    const duration = Number(slotMinutes);
    if (!Number.isFinite(start) || !Number.isFinite(end) || !Number.isInteger(duration) || duration <= 0 || end <= start) {
        return [];
    }
    const slots = [];
    for (let minute = start; minute + duration <= end; minute += duration) {
        slots.push(minutesToTime(minute));
    }
    return slots;
}

function getUtcDateFromISO(dateStr) {
    const [year, month, day] = String(dateStr).split('-').map(Number);
    return new Date(Date.UTC(year, month - 1, day));
}

function isDateInDoctorRange(dateStr, monthsToShow) {
    const normalizedDate = normalizeISODate(dateStr);
    if (!normalizedDate) return false;
    const target = getUtcDateFromISO(normalizedDate);
    const today = new Date();
    const todayUtc = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
    if (target < todayUtc) return false;

    const maxDate = new Date(todayUtc);
    maxDate.setUTCMonth(maxDate.getUTCMonth() + Number(monthsToShow || 1));
    return target <= maxDate;
}

function mapDiagnosticFileMeta(row) {
    if (!row.diagnostic_file_key) {
        return null;
    }
    return {
        key: row.diagnostic_file_key,
        mime: row.diagnostic_file_mime || null,
        size: row.diagnostic_file_size ?? null,
        uploadedAt: row.diagnostic_uploaded_at || null
    };
}

function mapAppointmentRow(row) {
    return {
        _id: row.legacy_mongo_id || row.id,
        pgId: row.id,
        legacyPublicId: row.legacy_mongo_id || null,
        doctorId: row.doctor_legacy_mongo_id || row.doctor_id,
        doctorSnapshotName: row.doctor_snapshot_name || '',
        name: row.name,
        phone: row.phone,
        email: row.email || '',
        date: row.appointment_date,
        time: row.appointment_time,
        type: row.type,
        notes: row.notes || '',
        hasDiagnosis: !!row.has_diagnosis,
        diagnosticFileMeta: mapDiagnosticFileMeta(row),
        emailSent: !!row.email_sent,
        createdAt: row.created_at
    };
}

async function withTransaction(task) {
    const pool = getPostgresPool();
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

async function queryOneRow(sql, params = [], client = null) {
    const executor = client || getPostgresPool();
    const result = await executor.query(sql, params);
    return result.rows[0] || null;
}

async function queryUserPgIdByPublicId(publicId, client = null) {
    const normalized = normalizePublicId(publicId);
    if (!normalized) return null;

    let row = null;
    if (normalizeLegacyObjectId(normalized)) {
        row = await queryOneRow(
            `SELECT id
             FROM users
             WHERE legacy_mongo_id = $1::char(24)
             LIMIT 1`,
            [normalized],
            client
        );
    } else if (isPostgresUuid(normalized)) {
        row = await queryOneRow(
            `SELECT id
             FROM users
             WHERE id = $1::uuid
             LIMIT 1`,
            [normalized],
            client
        );
    }

    return row ? String(row.id) : null;
}

async function queryDoctorRowByIdentifier(identifier, { requireActive = true } = {}, client = null) {
    const normalized = normalizePublicId(identifier)?.toLowerCase();
    if (!normalized) return null;

    const byLegacyId = normalizeLegacyObjectId(normalized);
    const params = [];
    const filters = [];
    if (byLegacyId) {
        params.push(byLegacyId);
        filters.push(`d.legacy_mongo_id = $${params.length}::char(24)`);
    } else {
        params.push(normalized);
        filters.push(`d.slug = $${params.length}`);
    }
    if (requireActive) {
        filters.push('d.is_active = TRUE');
    }

    return queryOneRow(
        `SELECT
            d.id,
            TRIM(d.legacy_mongo_id) AS legacy_mongo_id,
            d.slug,
            d.display_name,
            d.is_active,
            d.consultation_duration_minutes,
            d.workday_start,
            d.workday_end,
            d.months_to_show,
            d.timezone
         FROM doctors d
         WHERE ${filters.join(' AND ')}
         LIMIT 1`,
        params,
        client
    );
}

async function queryDoctorAvailabilityRuleForDate(doctorPgId, dateISO, client = null) {
    const weekday = getUtcDateFromISO(dateISO).getUTCDay();
    return queryOneRow(
        `SELECT
            weekday,
            start_time,
            end_time,
            slot_minutes,
            is_active,
            effective_from,
            effective_to,
            CASE
                WHEN effective_from = $3::date AND effective_to = $3::date THEN 'override'
                ELSE 'default'
            END AS rule_source
         FROM doctor_availability_rules
         WHERE doctor_id = $1
            AND weekday = $2
            AND is_active = TRUE
            AND (effective_from IS NULL OR effective_from <= $3::date)
            AND (effective_to IS NULL OR effective_to >= $3::date)
         ORDER BY
            CASE
                WHEN effective_from = $3::date AND effective_to = $3::date THEN 0
                WHEN effective_from IS NULL AND effective_to IS NULL THEN 2
                ELSE 1
            END ASC,
            effective_from DESC NULLS LAST
         LIMIT 1`,
        [doctorPgId, weekday, dateISO],
        client
    );
}

async function isDoctorDateBlocked(doctorPgId, dateISO, client = null) {
    const row = await queryOneRow(
        `SELECT 1
         FROM doctor_blocked_days
         WHERE doctor_id = $1
           AND blocked_date = $2::date
           AND is_active = TRUE
         LIMIT 1`,
        [doctorPgId, dateISO],
        client
    );
    return !!row;
}

async function queryMappedAppointmentByPgId(appointmentPgId, client = null) {
    const row = await queryOneRow(
        `SELECT
            a.id::text AS id,
            TRIM(a.legacy_mongo_id) AS legacy_mongo_id,
            a.name,
            a.phone,
            a.type,
            a.appointment_date::text AS appointment_date,
            to_char(a.appointment_time, 'HH24:MI') AS appointment_time,
            a.notes,
            a.email,
            a.email_sent,
            a.has_diagnosis,
            a.diagnostic_file_key,
            a.diagnostic_file_mime,
            a.diagnostic_file_size,
            a.diagnostic_uploaded_at,
            a.doctor_id::text AS doctor_id,
            a.doctor_snapshot_name,
            a.created_at,
            TRIM(d.legacy_mongo_id) AS doctor_legacy_mongo_id
         FROM appointments a
         JOIN doctors d ON d.id = a.doctor_id
         WHERE a.id = $1::uuid
         LIMIT 1`,
        [appointmentPgId],
        client
    );
    return row ? mapAppointmentRow(row) : null;
}

async function listBookedTimesByDoctorDate(doctorIdentifier, dateISO, client = null) {
    const normalizedDoctorIdentifier = normalizePublicId(doctorIdentifier);
    const normalizedDate = normalizeISODate(dateISO);
    if (!normalizedDoctorIdentifier || !normalizedDate) {
        return [];
    }

    const executor = client || getPostgresPool();
    let result;
    if (normalizeLegacyObjectId(normalizedDoctorIdentifier)) {
        result = await executor.query(
            `SELECT to_char(a.appointment_time, 'HH24:MI') AS appointment_time
             FROM appointments a
             JOIN doctors d ON d.id = a.doctor_id
             WHERE d.legacy_mongo_id = $1::char(24)
               AND a.appointment_date = $2::date
             ORDER BY a.appointment_time ASC`,
            [normalizedDoctorIdentifier, normalizedDate]
        );
    } else if (isPostgresUuid(normalizedDoctorIdentifier)) {
        result = await executor.query(
            `SELECT to_char(a.appointment_time, 'HH24:MI') AS appointment_time
             FROM appointments a
             WHERE a.doctor_id = $1::uuid
               AND a.appointment_date = $2::date
             ORDER BY a.appointment_time ASC`,
            [normalizedDoctorIdentifier, normalizedDate]
        );
    } else {
        return [];
    }

    return result.rows.map((row) => row.appointment_time);
}

async function getSlotMatrixForDoctorDate(doctorIdentifier, dateISO, client = null) {
    const normalizedDate = normalizeISODate(dateISO);
    if (!normalizedDate) {
        throw new BookingValidationError('Data invalida.', { code: 'invalid_date', status: 400 });
    }

    const doctor = await queryDoctorRowByIdentifier(doctorIdentifier, { requireActive: true }, client);
    if (!doctor) {
        return { found: false };
    }

    if (!isDateInDoctorRange(normalizedDate, doctor.months_to_show)) {
        return { found: true, inRange: false, doctor };
    }

    const rule = await queryDoctorAvailabilityRuleForDate(doctor.id, normalizedDate, client);
    if (!rule) {
        return {
            found: true,
            inRange: true,
            hasAvailability: false,
            blocked: false,
            allSlots: [],
            slots: [],
            bookedTimes: [],
            doctor
        };
    }

    const blocked = await isDoctorDateBlocked(doctor.id, normalizedDate, client);
    const allSlots = generateSlots({
        startTime: rule.start_time,
        endTime: rule.end_time,
        slotMinutes: rule.slot_minutes
    });
    const bookedTimes = await listBookedTimesByDoctorDate(doctor.id, normalizedDate, client);
    const slots = allSlots.map((slotTime) => ({
        time: slotTime,
        available: !blocked && !bookedTimes.includes(slotTime)
    }));

    return {
        found: true,
        inRange: true,
        hasAvailability: true,
        blocked,
        allSlots,
        slots,
        bookedTimes,
        rule,
        doctor
    };
}

async function createAuditLog({
    action,
    result = 'success',
    targetType = '',
    targetId = '',
    actorUserPublicId = null,
    actorRole = 'anonymous',
    ip = '',
    userAgent = '',
    metadata = {}
} = {}, client = null) {
    const task = async (txClient) => {
        const actorUserPgId = await queryUserPgIdByPublicId(actorUserPublicId, txClient);
        await txClient.query(
            `INSERT INTO audit_logs (
                legacy_mongo_id,
                actor_user_id,
                actor_role,
                action,
                target_type,
                target_id,
                result,
                ip,
                user_agent,
                metadata
            )
            VALUES (
                $1,
                $2::uuid,
                $3,
                $4,
                $5,
                $6,
                $7::audit_log_result,
                $8,
                $9,
                $10::jsonb
            )`,
            [
                generateLegacyPublicId(),
                actorUserPgId,
                String(actorRole || 'anonymous'),
                String(action || 'unknown_action'),
                String(targetType || ''),
                String(targetId || ''),
                String(result || 'success'),
                String(ip || ''),
                String(userAgent || '').slice(0, 512),
                JSON.stringify(metadata && typeof metadata === 'object' ? metadata : {})
            ]
        );
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function createAppointmentTransactional({
    doctorIdentifier,
    name,
    phone,
    email,
    type,
    date,
    time,
    notes = '',
    hasDiagnosis = false,
    diagnosticFileMeta = null,
    userPublicId = null,
    auditContext = null
} = {}, client = null) {
    const normalizedDate = normalizeISODate(date);
    const normalizedTime = normalizeTimeHHMM(time);
    if (!normalizedDate || !normalizedTime) {
        throw new BookingValidationError('Data sau ora invalida.', { code: 'invalid_datetime', status: 400 });
    }
    const normalizedName = String(name || '').trim();
    const normalizedPhone = String(phone || '').trim();
    const normalizedEmail = String(email || '').trim().toLowerCase();
    const normalizedType = String(type || '').trim();
    if (!normalizedName || !normalizedPhone || !normalizedEmail || !normalizedType) {
        throw new BookingValidationError('Datele programarii sunt incomplete.', { code: 'invalid_payload', status: 400 });
    }

    const task = async (txClient) => {
        const doctor = await queryDoctorRowByIdentifier(doctorIdentifier, { requireActive: true }, txClient);
        if (!doctor) {
            throw new BookingValidationError('Medicul selectat nu exista sau nu este activ.', { code: 'doctor_not_found', status: 404 });
        }

        if (!isDateInDoctorRange(normalizedDate, doctor.months_to_show)) {
            throw new BookingValidationError('Data selectata este in afara intervalului permis pentru acest medic.', {
                code: 'doctor_date_out_of_range',
                status: 400
            });
        }

        const availabilityRule = await queryDoctorAvailabilityRuleForDate(doctor.id, normalizedDate, txClient);
        if (!availabilityRule) {
            throw new BookingValidationError('Medicul selectat nu are disponibilitate in aceasta zi.', {
                code: 'doctor_unavailable_weekday',
                status: 400
            });
        }

        const isBlocked = await isDoctorDateBlocked(doctor.id, normalizedDate, txClient);
        if (isBlocked) {
            throw new BookingValidationError('Ziua selectata este indisponibila pentru medicul ales.', {
                code: 'doctor_date_blocked',
                status: 409
            });
        }

        const availableSlots = generateSlots({
            startTime: availabilityRule.start_time,
            endTime: availabilityRule.end_time,
            slotMinutes: availabilityRule.slot_minutes
        });
        if (!availableSlots.includes(normalizedTime)) {
            throw new BookingValidationError('Ora selectata este invalida pentru medicul ales.', {
                code: 'doctor_invalid_slot',
                status: 400
            });
        }

        const userPgId = await queryUserPgIdByPublicId(userPublicId, txClient);
        let insertedId;
        try {
            const insertResult = await txClient.query(
                `INSERT INTO appointments (
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
                    user_id
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5::date,
                    $6::time,
                    $7,
                    $8,
                    FALSE,
                    $9,
                    $10,
                    $11,
                    $12,
                    $13::timestamptz,
                    $14::uuid,
                    $15,
                    $16::uuid
                )
                RETURNING id::text AS id`,
                [
                    generateLegacyPublicId(),
                    normalizedName,
                    normalizedPhone,
                    normalizedType,
                    normalizedDate,
                    normalizedTime,
                    String(notes || ''),
                    normalizedEmail,
                    !!hasDiagnosis,
                    diagnosticFileMeta?.key || null,
                    diagnosticFileMeta?.mime || null,
                    diagnosticFileMeta?.size ?? null,
                    diagnosticFileMeta?.uploadedAt || null,
                    doctor.id,
                    String(doctor.display_name || ''),
                    userPgId
                ]
            );
            insertedId = insertResult.rows[0]?.id || null;
        } catch (error) {
            if (isAppointmentSlotUniqueViolation(error)) {
                throw new BookingValidationError('Interval deja rezervat.', {
                    code: 'doctor_slot_already_booked',
                    status: 409
                });
            }
            throw error;
        }

        const created = await queryMappedAppointmentByPgId(insertedId, txClient);
        if (!created) {
            throw new Error('Appointment insert succeeded but row could not be loaded.');
        }

        if (auditContext && typeof auditContext === 'object') {
            await createAuditLog({
                action: String(auditContext.action || 'appointment_book'),
                result: String(auditContext.result || 'success'),
                targetType: String(auditContext.targetType || 'appointment'),
                targetId: String(created._id || ''),
                actorUserPublicId: auditContext.actorUserPublicId || null,
                actorRole: auditContext.actorRole || 'anonymous',
                ip: auditContext.ip || '',
                userAgent: auditContext.userAgent || '',
                metadata: {
                    doctorId: created.doctorId,
                    date: created.date,
                    time: created.time,
                    ...(auditContext.metadata && typeof auditContext.metadata === 'object' ? auditContext.metadata : {})
                }
            }, txClient);
        }

        return created;
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function listAppointments({
    doctorLegacyIds = null,
    date = null,
    dateFrom = null,
    dateTo = null
} = {}, client = null) {
    const executor = client || getPostgresPool();
    const conditions = [];
    const params = [];

    if (Array.isArray(doctorLegacyIds)) {
        const normalizedIds = Array.from(new Set(doctorLegacyIds
            .map((id) => normalizeLegacyObjectId(id))
            .filter(Boolean)));
        if (!normalizedIds.length) {
            return [];
        }
        params.push(normalizedIds);
        conditions.push(`d.legacy_mongo_id = ANY($${params.length}::char(24)[])`);
    }

    const normalizedDate = normalizeISODate(date);
    if (normalizedDate) {
        params.push(normalizedDate);
        conditions.push(`a.appointment_date = $${params.length}::date`);
    } else {
        const normalizedDateFrom = normalizeISODate(dateFrom);
        if (normalizedDateFrom) {
            params.push(normalizedDateFrom);
            conditions.push(`a.appointment_date >= $${params.length}::date`);
        }
        const normalizedDateTo = normalizeISODate(dateTo);
        if (normalizedDateTo) {
            params.push(normalizedDateTo);
            conditions.push(`a.appointment_date <= $${params.length}::date`);
        }
    }

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const result = await executor.query(
        `SELECT
            a.id::text AS id,
            TRIM(a.legacy_mongo_id) AS legacy_mongo_id,
            a.name,
            a.phone,
            a.type,
            a.appointment_date::text AS appointment_date,
            to_char(a.appointment_time, 'HH24:MI') AS appointment_time,
            a.notes,
            a.email,
            a.email_sent,
            a.has_diagnosis,
            a.diagnostic_file_key,
            a.diagnostic_file_mime,
            a.diagnostic_file_size,
            a.diagnostic_uploaded_at,
            a.doctor_id::text AS doctor_id,
            a.doctor_snapshot_name,
            a.created_at,
            TRIM(d.legacy_mongo_id) AS doctor_legacy_mongo_id
         FROM appointments a
         JOIN doctors d ON d.id = a.doctor_id
         ${whereClause}
         ORDER BY a.appointment_date ASC, a.appointment_time ASC`,
        params
    );
    return result.rows.map(mapAppointmentRow);
}

async function findAppointmentByPublicId(publicId, client = null) {
    const normalizedId = normalizePublicId(publicId);
    if (!normalizedId) {
        return null;
    }

    let row = null;
    if (normalizeLegacyObjectId(normalizedId)) {
        row = await queryOneRow(
            `SELECT
                a.id::text AS id,
                TRIM(a.legacy_mongo_id) AS legacy_mongo_id,
                a.name,
                a.phone,
                a.type,
                a.appointment_date::text AS appointment_date,
                to_char(a.appointment_time, 'HH24:MI') AS appointment_time,
                a.notes,
                a.email,
                a.email_sent,
                a.has_diagnosis,
                a.diagnostic_file_key,
                a.diagnostic_file_mime,
                a.diagnostic_file_size,
                a.diagnostic_uploaded_at,
                a.doctor_id::text AS doctor_id,
                a.doctor_snapshot_name,
                a.created_at,
                TRIM(d.legacy_mongo_id) AS doctor_legacy_mongo_id
             FROM appointments a
             JOIN doctors d ON d.id = a.doctor_id
             WHERE a.legacy_mongo_id = $1::char(24)
             LIMIT 1`,
            [normalizedId],
            client
        );
    } else if (isPostgresUuid(normalizedId)) {
        row = await queryOneRow(
            `SELECT
                a.id::text AS id,
                TRIM(a.legacy_mongo_id) AS legacy_mongo_id,
                a.name,
                a.phone,
                a.type,
                a.appointment_date::text AS appointment_date,
                to_char(a.appointment_time, 'HH24:MI') AS appointment_time,
                a.notes,
                a.email,
                a.email_sent,
                a.has_diagnosis,
                a.diagnostic_file_key,
                a.diagnostic_file_mime,
                a.diagnostic_file_size,
                a.diagnostic_uploaded_at,
                a.doctor_id::text AS doctor_id,
                a.doctor_snapshot_name,
                a.created_at,
                TRIM(d.legacy_mongo_id) AS doctor_legacy_mongo_id
             FROM appointments a
             JOIN doctors d ON d.id = a.doctor_id
             WHERE a.id = $1::uuid
             LIMIT 1`,
            [normalizedId],
            client
        );
    }

    return row ? mapAppointmentRow(row) : null;
}

async function setAppointmentEmailSentByPublicId(publicId, value = true, client = null) {
    const normalizedId = normalizePublicId(publicId);
    if (!normalizedId) return null;

    const task = async (txClient) => {
        let row = null;
        if (normalizeLegacyObjectId(normalizedId)) {
            row = await queryOneRow(
                `UPDATE appointments
                 SET email_sent = $2
                 WHERE legacy_mongo_id = $1::char(24)
                 RETURNING id::text AS id`,
                [normalizedId, !!value],
                txClient
            );
        } else if (isPostgresUuid(normalizedId)) {
            row = await queryOneRow(
                `UPDATE appointments
                 SET email_sent = $2
                 WHERE id = $1::uuid
                 RETURNING id::text AS id`,
                [normalizedId, !!value],
                txClient
            );
        }

        if (!row) return null;
        return queryMappedAppointmentByPgId(row.id, txClient);
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function updateDoctorSnapshotNameByDoctorLegacyId(doctorLegacyId, displayName, client = null) {
    const normalizedDoctorLegacyId = normalizeLegacyObjectId(doctorLegacyId);
    if (!normalizedDoctorLegacyId) {
        return 0;
    }
    const executor = client || getPostgresPool();
    const result = await executor.query(
        `UPDATE appointments a
         SET doctor_snapshot_name = $2
         FROM doctors d
         WHERE a.doctor_id = d.id
           AND d.legacy_mongo_id = $1::char(24)
           AND a.doctor_snapshot_name <> $2`,
        [normalizedDoctorLegacyId, String(displayName || '')]
    );
    return Number(result.rowCount || 0);
}

async function deleteAppointmentByPublicId(publicId, client = null) {
    const normalizedId = normalizePublicId(publicId);
    if (!normalizedId) return null;

    const task = async (txClient) => {
        const found = await findAppointmentByPublicId(normalizedId, txClient);
        if (!found) {
            return null;
        }
        if (normalizeLegacyObjectId(normalizedId)) {
            await txClient.query(
                `DELETE FROM appointments
                 WHERE legacy_mongo_id = $1::char(24)`,
                [normalizedId]
            );
        } else if (isPostgresUuid(normalizedId)) {
            await txClient.query(
                `DELETE FROM appointments
                 WHERE id = $1::uuid`,
                [normalizedId]
            );
        } else {
            return null;
        }
        return found;
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function deleteAppointmentsByDate(dateISO, client = null) {
    const normalizedDate = normalizeISODate(dateISO);
    if (!normalizedDate) {
        return 0;
    }
    const executor = client || getPostgresPool();
    const result = await executor.query(
        `DELETE FROM appointments
         WHERE appointment_date = $1::date`,
        [normalizedDate]
    );
    return Number(result.rowCount || 0);
}

async function deleteAllAppointments(client = null) {
    const executor = client || getPostgresPool();
    const result = await executor.query(`DELETE FROM appointments`);
    return Number(result.rowCount || 0);
}

async function getAppointmentStorageStats(client = null) {
    const executor = client || getPostgresPool();
    const [sizeResult, countResult] = await Promise.all([
        executor.query(
            `SELECT pg_total_relation_size('appointments')::bigint AS appointments_bytes`
        ),
        executor.query(
            `SELECT COUNT(*)::int AS appointment_count
             FROM appointments`
        )
    ]);
    return {
        appointmentsBytes: Number(sizeResult.rows?.[0]?.appointments_bytes || 0),
        appointmentCount: Number(countResult.rows?.[0]?.appointment_count || 0)
    };
}

module.exports = {
    BookingValidationError,
    LEGACY_OBJECT_ID_REGEX,
    isUniqueViolation,
    withTransaction,
    createAuditLog,
    createAppointmentTransactional,
    getSlotMatrixForDoctorDate,
    listBookedTimesByDoctorDate,
    listAppointments,
    findAppointmentByPublicId,
    setAppointmentEmailSentByPublicId,
    updateDoctorSnapshotNameByDoctorLegacyId,
    deleteAppointmentByPublicId,
    deleteAppointmentsByDate,
    deleteAllAppointments,
    getAppointmentStorageStats
};
