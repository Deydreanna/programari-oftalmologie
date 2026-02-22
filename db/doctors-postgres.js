const crypto = require('crypto');
const { getPostgresPool } = require('./postgres');

const LEGACY_OBJECT_ID_REGEX = /^[a-fA-F0-9]{24}$/;
const POSTGRES_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
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
const DEFAULT_SPECIALTY = 'Oftalmologie';

function isUniqueViolation(error) {
    return error?.code === '23505';
}

function generateLegacyPublicId() {
    return crypto.randomBytes(12).toString('hex');
}

function normalizeLegacyDoctorId(value) {
    const candidate = String(value || '').trim();
    if (!LEGACY_OBJECT_ID_REGEX.test(candidate)) {
        return null;
    }
    return candidate;
}

function isPostgresUuid(value) {
    return POSTGRES_UUID_REGEX.test(String(value || '').trim());
}

function normalizeDoctorSlug(value) {
    const slug = String(value || '').trim().toLowerCase();
    if (!DOCTOR_SLUG_REGEX.test(slug)) {
        return null;
    }
    return slug;
}

function normalizeTimeHHMM(value, fallback) {
    const normalized = String(value || '').trim();
    const match = normalized.match(TIME_HHMM_REGEX);
    if (!match) {
        return fallback;
    }
    return `${match[1]}:${match[2]}`;
}

function normalizeIsoDate(value) {
    const normalized = String(value || '').trim();
    if (!ISO_DATE_REGEX.test(normalized)) {
        return null;
    }
    return normalized;
}

function normalizeBlockedDates(value = []) {
    if (!Array.isArray(value)) {
        return [];
    }
    const seen = new Set();
    const normalized = [];
    for (const item of value) {
        const parsed = normalizeIsoDate(item);
        if (!parsed || seen.has(parsed)) continue;
        seen.add(parsed);
        normalized.push(parsed);
    }
    return normalized.sort();
}

function normalizeWeekdays(value = []) {
    if (!Array.isArray(value)) {
        return [];
    }
    const seen = new Set();
    const normalized = [];
    for (const item of value) {
        const weekday = Number(item);
        if (!Number.isInteger(weekday) || weekday < 0 || weekday > 6) {
            continue;
        }
        if (seen.has(weekday)) continue;
        seen.add(weekday);
        normalized.push(weekday);
    }
    return normalized.sort((a, b) => a - b);
}

function parseHHMMToMinutes(value) {
    const normalized = normalizeTimeHHMM(value);
    if (!normalized) return NaN;
    const [hours, minutes] = normalized.split(':').map(Number);
    return (hours * 60) + minutes;
}

function isValidTimeWindow(startTime, endTime, consultationDurationMinutes, { requireDivisible = false } = {}) {
    const start = parseHHMMToMinutes(startTime);
    const end = parseHHMMToMinutes(endTime);
    const duration = Number(consultationDurationMinutes);
    if (!Number.isFinite(start) || !Number.isFinite(end) || !Number.isInteger(duration)) {
        return false;
    }
    if (duration < 5 || duration > 120) {
        return false;
    }
    const intervalMinutes = end - start;
    if (intervalMinutes <= 0 || intervalMinutes < duration) {
        return false;
    }
    if (requireDivisible && (intervalMinutes % duration !== 0)) {
        return false;
    }
    return true;
}

function normalizeBookingSettings(settings = {}) {
    const consultationDurationMinutes = Number(settings.consultationDurationMinutes);
    const duration = Number.isInteger(consultationDurationMinutes)
        && consultationDurationMinutes >= 5
        && consultationDurationMinutes <= 120
        ? consultationDurationMinutes
        : DEFAULT_BOOKING_SETTINGS.consultationDurationMinutes;

    const workdayStart = normalizeTimeHHMM(settings.workdayStart, DEFAULT_BOOKING_SETTINGS.workdayStart);
    const workdayEnd = normalizeTimeHHMM(settings.workdayEnd, DEFAULT_BOOKING_SETTINGS.workdayEnd);
    const monthsToShowRaw = Number(settings.monthsToShow);
    const monthsToShow = Number.isInteger(monthsToShowRaw)
        && monthsToShowRaw >= 1
        && monthsToShowRaw <= 12
        ? monthsToShowRaw
        : DEFAULT_BOOKING_SETTINGS.monthsToShow;
    const timezone = String(settings.timezone || DEFAULT_BOOKING_SETTINGS.timezone).trim() || DEFAULT_BOOKING_SETTINGS.timezone;

    return {
        consultationDurationMinutes: duration,
        workdayStart,
        workdayEnd,
        monthsToShow,
        timezone
    };
}

function buildDayConfigsFromWeekdays(weekdays, bookingSettings) {
    const normalizedWeekdays = normalizeWeekdays(weekdays);
    const normalizedBooking = normalizeBookingSettings(bookingSettings);
    return normalizedWeekdays.map((weekday) => ({
        weekday,
        startTime: normalizedBooking.workdayStart,
        endTime: normalizedBooking.workdayEnd,
        consultationDurationMinutes: normalizedBooking.consultationDurationMinutes
    }));
}

function normalizeDayConfigs(value = [], bookingSettings = DEFAULT_BOOKING_SETTINGS, fallbackWeekdays = []) {
    const normalizedBooking = normalizeBookingSettings(bookingSettings);
    const out = [];
    const seenWeekdays = new Set();

    if (Array.isArray(value)) {
        for (const entry of value) {
            if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
                continue;
            }

            const weekday = Number(entry.weekday);
            if (!Number.isInteger(weekday) || weekday < 0 || weekday > 6) {
                continue;
            }
            if (seenWeekdays.has(weekday)) {
                continue;
            }

            const startTime = normalizeTimeHHMM(entry.startTime ?? entry.start_time, normalizedBooking.workdayStart);
            const endTime = normalizeTimeHHMM(entry.endTime ?? entry.end_time, normalizedBooking.workdayEnd);
            const durationRaw = Number(entry.consultationDurationMinutes ?? entry.slotMinutes ?? entry.slot_minutes);
            const consultationDurationMinutes = Number.isInteger(durationRaw)
                && durationRaw >= 5
                && durationRaw <= 120
                ? durationRaw
                : normalizedBooking.consultationDurationMinutes;

            if (!isValidTimeWindow(startTime, endTime, consultationDurationMinutes)) {
                continue;
            }

            seenWeekdays.add(weekday);
            out.push({
                weekday,
                startTime,
                endTime,
                consultationDurationMinutes
            });
        }
    }

    if (out.length > 0) {
        return out.sort((a, b) => a.weekday - b.weekday);
    }

    const fallback = normalizeWeekdays(fallbackWeekdays);
    if (!fallback.length) {
        return [];
    }
    return buildDayConfigsFromWeekdays(fallback, normalizedBooking);
}

function normalizeAvailabilityRules(availabilityRules = {}, bookingSettings = DEFAULT_BOOKING_SETTINGS, { defaultIfEmpty = false } = {}) {
    const normalizedBooking = normalizeBookingSettings(bookingSettings);
    const payload = (availabilityRules && typeof availabilityRules === 'object' && !Array.isArray(availabilityRules))
        ? availabilityRules
        : {};

    let dayConfigs = normalizeDayConfigs(payload.dayConfigs, normalizedBooking, []);
    if (!dayConfigs.length) {
        const requestedWeekdays = normalizeWeekdays(payload.weekdays || []);
        if (requestedWeekdays.length) {
            dayConfigs = buildDayConfigsFromWeekdays(requestedWeekdays, normalizedBooking);
        }
    }

    if (!dayConfigs.length && defaultIfEmpty) {
        dayConfigs = buildDayConfigsFromWeekdays(DEFAULT_AVAILABILITY_WEEKDAYS, normalizedBooking);
    }

    return {
        weekdays: dayConfigs.map((config) => config.weekday),
        dayConfigs
    };
}

function inferLegacyBookingSettingsFromDayConfigs(bookingSettings, dayConfigs = []) {
    const normalizedBooking = normalizeBookingSettings(bookingSettings);
    const normalizedDayConfigs = normalizeDayConfigs(dayConfigs, normalizedBooking, []);
    if (!normalizedDayConfigs.length) {
        return normalizedBooking;
    }
    const firstConfig = normalizedDayConfigs[0];
    return {
        consultationDurationMinutes: firstConfig.consultationDurationMinutes,
        workdayStart: firstConfig.startTime,
        workdayEnd: firstConfig.endTime,
        monthsToShow: normalizedBooking.monthsToShow,
        timezone: normalizedBooking.timezone
    };
}

function pgTimeToHHMM(value, fallback = '00:00') {
    const normalized = String(value || '').trim();
    const match = normalized.match(TIME_HHMM_REGEX);
    if (!match) {
        return fallback;
    }
    return `${match[1]}:${match[2]}`;
}

function mapDoctorRow(row, { dayConfigs = [], blockedDates = [] } = {}) {
    const publicId = normalizeLegacyDoctorId(row.legacy_mongo_id) || String(row.id || '');
    const bookingSettings = {
        consultationDurationMinutes: Number(row.consultation_duration_minutes),
        workdayStart: pgTimeToHHMM(row.workday_start, DEFAULT_BOOKING_SETTINGS.workdayStart),
        workdayEnd: pgTimeToHHMM(row.workday_end, DEFAULT_BOOKING_SETTINGS.workdayEnd),
        monthsToShow: Number(row.months_to_show),
        timezone: row.timezone || DEFAULT_BOOKING_SETTINGS.timezone
    };
    const normalizedDayConfigs = normalizeDayConfigs(dayConfigs, bookingSettings, []);
    return {
        _id: publicId,
        pgId: String(row.id),
        legacyPublicId: normalizeLegacyDoctorId(row.legacy_mongo_id) || null,
        slug: row.slug,
        displayName: row.display_name,
        specialty: row.specialty || DEFAULT_SPECIALTY,
        isActive: !!row.is_active,
        bookingSettings,
        availabilityRules: {
            weekdays: normalizedDayConfigs.map((config) => config.weekday),
            dayConfigs: normalizedDayConfigs
        },
        blockedDates: normalizeBlockedDates(blockedDates),
        createdByUserId: row.created_by_public_id || null,
        updatedByUserId: row.updated_by_public_id || null,
        createdAt: row.created_at,
        updatedAt: row.updated_at
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

async function queryDoctorRowByPgId(doctorPgId, client = null) {
    return queryOneRow(
        `SELECT
            d.id,
            TRIM(d.legacy_mongo_id) AS legacy_mongo_id,
            d.slug,
            d.display_name,
            d.specialty,
            d.is_active,
            d.consultation_duration_minutes,
            d.workday_start,
            d.workday_end,
            d.months_to_show,
            d.timezone,
            d.created_at,
            d.updated_at,
            COALESCE(u_created.legacy_mongo_id, u_created.id::text) AS created_by_public_id,
            COALESCE(u_updated.legacy_mongo_id, u_updated.id::text) AS updated_by_public_id
         FROM doctors d
         LEFT JOIN users u_created ON u_created.id = d.created_by_user_id
         LEFT JOIN users u_updated ON u_updated.id = d.updated_by_user_id
         WHERE d.id = $1
         LIMIT 1`,
        [doctorPgId],
        client
    );
}

async function queryDoctorRowByLegacyId(legacyId, client = null) {
    return queryOneRow(
        `SELECT
            d.id,
            TRIM(d.legacy_mongo_id) AS legacy_mongo_id,
            d.slug,
            d.display_name,
            d.specialty,
            d.is_active,
            d.consultation_duration_minutes,
            d.workday_start,
            d.workday_end,
            d.months_to_show,
            d.timezone,
            d.created_at,
            d.updated_at,
            COALESCE(u_created.legacy_mongo_id, u_created.id::text) AS created_by_public_id,
            COALESCE(u_updated.legacy_mongo_id, u_updated.id::text) AS updated_by_public_id
         FROM doctors d
         LEFT JOIN users u_created ON u_created.id = d.created_by_user_id
         LEFT JOIN users u_updated ON u_updated.id = d.updated_by_user_id
         WHERE d.legacy_mongo_id = $1::char(24)
         LIMIT 1`,
        [legacyId],
        client
    );
}

async function queryDoctorDayConfigsByPgIds(doctorPgIds = [], client = null) {
    const ids = Array.from(new Set((doctorPgIds || []).map((id) => String(id || '').trim()).filter(Boolean)));
    const out = new Map();
    if (!ids.length) {
        return out;
    }

    const executor = client || getPostgresPool();
    const result = await executor.query(
        `SELECT doctor_id, weekday, start_time, end_time, slot_minutes
         FROM doctor_availability_rules
         WHERE doctor_id = ANY($1::uuid[])
           AND is_active = TRUE
           AND effective_from IS NULL
           AND effective_to IS NULL
         ORDER BY weekday ASC`,
        [ids]
    );

    for (const row of result.rows) {
        const key = String(row.doctor_id);
        if (!out.has(key)) {
            out.set(key, []);
        }
        out.get(key).push({
            weekday: Number(row.weekday),
            startTime: pgTimeToHHMM(row.start_time),
            endTime: pgTimeToHHMM(row.end_time),
            consultationDurationMinutes: Number(row.slot_minutes)
        });
    }
    return out;
}

async function queryDoctorBlockedDatesByPgIds(doctorPgIds = [], client = null) {
    const ids = Array.from(new Set((doctorPgIds || []).map((id) => String(id || '').trim()).filter(Boolean)));
    const out = new Map();
    if (!ids.length) {
        return out;
    }

    const executor = client || getPostgresPool();
    const result = await executor.query(
        `SELECT doctor_id, blocked_date::text AS blocked_date
         FROM doctor_blocked_days
         WHERE doctor_id = ANY($1::uuid[])
           AND is_active = TRUE
         ORDER BY blocked_date ASC`,
        [ids]
    );

    for (const row of result.rows) {
        const key = String(row.doctor_id);
        if (!out.has(key)) {
            out.set(key, []);
        }
        out.get(key).push(row.blocked_date);
    }
    return out;
}

async function mapDoctorRows(rows = [], client = null) {
    const rowList = Array.isArray(rows) ? rows : [];
    if (!rowList.length) {
        return [];
    }
    const pgIds = rowList.map((row) => String(row.id));
    const [dayConfigMap, blockedDatesMap] = await Promise.all([
        queryDoctorDayConfigsByPgIds(pgIds, client),
        queryDoctorBlockedDatesByPgIds(pgIds, client)
    ]);
    return rowList.map((row) => mapDoctorRow(row, {
        dayConfigs: dayConfigMap.get(String(row.id)) || [],
        blockedDates: blockedDatesMap.get(String(row.id)) || []
    }));
}

async function queryUserPgIdByPublicId(publicId, client = null) {
    const normalized = String(publicId || '').trim();
    if (!normalized) return null;

    let row = null;
    if (LEGACY_OBJECT_ID_REGEX.test(normalized)) {
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

async function replaceDoctorAvailabilityRulesByPgId(doctorPgId, availabilityRules, bookingSettings, client = null) {
    const executor = client || getPostgresPool();
    const normalizedSettings = normalizeBookingSettings(bookingSettings);
    const normalizedAvailability = normalizeAvailabilityRules(availabilityRules, normalizedSettings, { defaultIfEmpty: true });

    await executor.query(
        `DELETE FROM doctor_availability_rules
         WHERE doctor_id = $1
           AND effective_from IS NULL
           AND effective_to IS NULL`,
        [doctorPgId]
    );

    for (const dayConfig of normalizedAvailability.dayConfigs) {
        await executor.query(
            `INSERT INTO doctor_availability_rules (
                doctor_id,
                weekday,
                start_time,
                end_time,
                slot_minutes,
                is_active,
                effective_from,
                effective_to
            )
            VALUES ($1, $2, $3::time, $4::time, $5, TRUE, NULL, NULL)`,
            [
                doctorPgId,
                dayConfig.weekday,
                dayConfig.startTime,
                dayConfig.endTime,
                dayConfig.consultationDurationMinutes
            ]
        );
    }

    return normalizedAvailability;
}

async function replaceDoctorBlockedDatesByPgId(doctorPgId, blockedDates, actorUserPgId = null, client = null) {
    const executor = client || getPostgresPool();
    const normalizedDates = normalizeBlockedDates(blockedDates);

    await executor.query(
        `DELETE FROM doctor_blocked_days
         WHERE doctor_id = $1`,
        [doctorPgId]
    );

    for (const blockedDate of normalizedDates) {
        await executor.query(
            `INSERT INTO doctor_blocked_days (
                doctor_id,
                blocked_date,
                reason,
                is_active,
                created_by_user_id,
                updated_by_user_id,
                disabled_at,
                disabled_by_user_id
            )
            VALUES ($1, $2::date, NULL, TRUE, $3::uuid, $3::uuid, NULL, NULL)`,
            [doctorPgId, blockedDate, actorUserPgId]
        );
    }
}

function getUtcDateFromISO(dateISO) {
    const [year, month, day] = String(dateISO).split('-').map(Number);
    return new Date(Date.UTC(year, month - 1, day));
}

function getWeekdayFromISO(dateISO) {
    return getUtcDateFromISO(dateISO).getUTCDay();
}

function mapAvailabilityRuleRow(row, source = 'default') {
    if (!row) return null;
    return {
        weekday: Number(row.weekday),
        startTime: pgTimeToHHMM(row.start_time),
        endTime: pgTimeToHHMM(row.end_time),
        consultationDurationMinutes: Number(row.slot_minutes),
        source
    };
}

async function queryDoctorDateOverrideByPgId(doctorPgId, dateISO, client = null) {
    return queryOneRow(
        `SELECT weekday, start_time, end_time, slot_minutes
         FROM doctor_availability_rules
         WHERE doctor_id = $1
           AND is_active = TRUE
           AND effective_from = $2::date
           AND effective_to = $2::date
         LIMIT 1`,
        [doctorPgId, dateISO],
        client
    );
}

async function queryDoctorBaseRuleForDateByPgId(doctorPgId, dateISO, client = null) {
    const weekday = getWeekdayFromISO(dateISO);
    return queryOneRow(
        `SELECT weekday, start_time, end_time, slot_minutes
         FROM doctor_availability_rules
         WHERE doctor_id = $1
           AND weekday = $2
           AND is_active = TRUE
           AND effective_from IS NULL
           AND effective_to IS NULL
         LIMIT 1`,
        [doctorPgId, weekday],
        client
    );
}

async function isDoctorDateBlockedByPgId(doctorPgId, dateISO, client = null) {
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

async function queryDoctorDayScheduleByPgId(doctorPgId, dateISO, client = null) {
    const normalizedDate = normalizeIsoDate(dateISO);
    if (!normalizedDate) {
        return null;
    }

    const [overrideRow, baseRow, blocked] = await Promise.all([
        queryDoctorDateOverrideByPgId(doctorPgId, normalizedDate, client),
        queryDoctorBaseRuleForDateByPgId(doctorPgId, normalizedDate, client),
        isDoctorDateBlockedByPgId(doctorPgId, normalizedDate, client)
    ]);

    const chosenRule = overrideRow
        ? mapAvailabilityRuleRow(overrideRow, 'override')
        : mapAvailabilityRuleRow(baseRow, 'default');

    return {
        date: normalizedDate,
        weekday: getWeekdayFromISO(normalizedDate),
        blocked,
        hasAvailability: !!chosenRule,
        rule: chosenRule,
        overrideRule: mapAvailabilityRuleRow(overrideRow, 'override'),
        defaultRule: mapAvailabilityRuleRow(baseRow, 'default')
    };
}

async function getDoctorDayScheduleByLegacyId(legacyDoctorId, dateISO, client = null) {
    const normalizedLegacyDoctorId = normalizeLegacyDoctorId(legacyDoctorId);
    const normalizedDate = normalizeIsoDate(dateISO);
    if (!normalizedLegacyDoctorId || !normalizedDate) {
        return null;
    }

    const task = async (txClient) => {
        const doctorRow = await queryDoctorRowByLegacyId(normalizedLegacyDoctorId, txClient);
        if (!doctorRow) {
            return null;
        }

        const [doctor] = await mapDoctorRows([doctorRow], txClient);
        const daySchedule = await queryDoctorDayScheduleByPgId(doctorRow.id, normalizedDate, txClient);
        if (!daySchedule) {
            return null;
        }

        return {
            doctor,
            ...daySchedule
        };
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function upsertDoctorDayOverrideByLegacyId(
    legacyDoctorId,
    dateISO,
    {
        startTime,
        endTime,
        consultationDurationMinutes,
        actorUserPublicId = null
    } = {},
    client = null
) {
    const normalizedLegacyDoctorId = normalizeLegacyDoctorId(legacyDoctorId);
    const normalizedDate = normalizeIsoDate(dateISO);
    const normalizedStartTime = normalizeTimeHHMM(startTime);
    const normalizedEndTime = normalizeTimeHHMM(endTime);
    const duration = Number(consultationDurationMinutes);

    if (!normalizedLegacyDoctorId || !normalizedDate) {
        return null;
    }
    if (!isValidTimeWindow(normalizedStartTime, normalizedEndTime, duration, { requireDivisible: true })) {
        throw new Error('Invalid day override window.');
    }

    const task = async (txClient) => {
        const doctorRow = await queryDoctorRowByLegacyId(normalizedLegacyDoctorId, txClient);
        if (!doctorRow) {
            return null;
        }

        const weekday = getWeekdayFromISO(normalizedDate);
        const actorUserPgId = await queryUserPgIdByPublicId(actorUserPublicId, txClient);

        await txClient.query(
            `DELETE FROM doctor_availability_rules
             WHERE doctor_id = $1
               AND effective_from = $2::date
               AND effective_to = $2::date`,
            [doctorRow.id, normalizedDate]
        );

        await txClient.query(
            `INSERT INTO doctor_availability_rules (
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
                $1,
                $2,
                $3::time,
                $4::time,
                $5,
                TRUE,
                $6::date,
                $6::date
            )`,
            [
                doctorRow.id,
                weekday,
                normalizedStartTime,
                normalizedEndTime,
                duration,
                normalizedDate
            ]
        );

        await txClient.query(
            `UPDATE doctors
             SET updated_by_user_id = $1::uuid,
                 updated_at = now()
             WHERE id = $2`,
            [actorUserPgId, doctorRow.id]
        );

        return getDoctorDayScheduleByLegacyId(normalizedLegacyDoctorId, normalizedDate, txClient);
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function removeDoctorDayOverrideByLegacyId(legacyDoctorId, dateISO, { actorUserPublicId = null } = {}, client = null) {
    const normalizedLegacyDoctorId = normalizeLegacyDoctorId(legacyDoctorId);
    const normalizedDate = normalizeIsoDate(dateISO);
    if (!normalizedLegacyDoctorId || !normalizedDate) {
        return null;
    }

    const task = async (txClient) => {
        const doctorRow = await queryDoctorRowByLegacyId(normalizedLegacyDoctorId, txClient);
        if (!doctorRow) {
            return null;
        }

        const actorUserPgId = await queryUserPgIdByPublicId(actorUserPublicId, txClient);
        await txClient.query(
            `DELETE FROM doctor_availability_rules
             WHERE doctor_id = $1
               AND effective_from = $2::date
               AND effective_to = $2::date`,
            [doctorRow.id, normalizedDate]
        );

        await txClient.query(
            `UPDATE doctors
             SET updated_by_user_id = $1::uuid,
                 updated_at = now()
             WHERE id = $2`,
            [actorUserPgId, doctorRow.id]
        );

        return getDoctorDayScheduleByLegacyId(normalizedLegacyDoctorId, normalizedDate, txClient);
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function listDoctors({ legacyIds = null, isActive = null } = {}, client = null) {
    const executor = client || getPostgresPool();
    const conditions = [];
    const params = [];

    if (Array.isArray(legacyIds)) {
        const normalizedLegacyIds = Array.from(new Set(legacyIds
            .map((id) => normalizeLegacyDoctorId(id))
            .filter(Boolean)));
        if (!normalizedLegacyIds.length) {
            return [];
        }
        params.push(normalizedLegacyIds);
        conditions.push(`d.legacy_mongo_id = ANY($${params.length}::char(24)[])`);
    }

    if (typeof isActive === 'boolean') {
        params.push(isActive);
        conditions.push(`d.is_active = $${params.length}`);
    }

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const rows = await executor.query(
        `SELECT
            d.id,
            TRIM(d.legacy_mongo_id) AS legacy_mongo_id,
            d.slug,
            d.display_name,
            d.specialty,
            d.is_active,
            d.consultation_duration_minutes,
            d.workday_start,
            d.workday_end,
            d.months_to_show,
            d.timezone,
            d.created_at,
            d.updated_at,
            COALESCE(u_created.legacy_mongo_id, u_created.id::text) AS created_by_public_id,
            COALESCE(u_updated.legacy_mongo_id, u_updated.id::text) AS updated_by_public_id
         FROM doctors d
         LEFT JOIN users u_created ON u_created.id = d.created_by_user_id
         LEFT JOIN users u_updated ON u_updated.id = d.updated_by_user_id
         ${whereClause}
         ORDER BY d.display_name ASC`,
        params
    );

    return mapDoctorRows(rows.rows || [], client);
}

async function findDoctorByIdentifier(rawIdentifier, { requireActive = true } = {}, client = null) {
    const identifier = String(rawIdentifier || '').trim().toLowerCase();
    if (!identifier) return null;

    const conditions = [];
    const params = [];
    if (normalizeLegacyDoctorId(identifier)) {
        params.push(identifier);
        conditions.push(`d.legacy_mongo_id = $${params.length}::char(24)`);
    } else {
        params.push(identifier);
        conditions.push(`d.slug = $${params.length}`);
    }
    if (requireActive) {
        conditions.push('d.is_active = TRUE');
    }

    const row = await queryOneRow(
        `SELECT
            d.id,
            TRIM(d.legacy_mongo_id) AS legacy_mongo_id,
            d.slug,
            d.display_name,
            d.specialty,
            d.is_active,
            d.consultation_duration_minutes,
            d.workday_start,
            d.workday_end,
            d.months_to_show,
            d.timezone,
            d.created_at,
            d.updated_at,
            COALESCE(u_created.legacy_mongo_id, u_created.id::text) AS created_by_public_id,
            COALESCE(u_updated.legacy_mongo_id, u_updated.id::text) AS updated_by_public_id
         FROM doctors d
         LEFT JOIN users u_created ON u_created.id = d.created_by_user_id
         LEFT JOIN users u_updated ON u_updated.id = d.updated_by_user_id
         WHERE ${conditions.join(' AND ')}
         LIMIT 1`,
        params,
        client
    );
    if (!row) return null;

    const mapped = await mapDoctorRows([row], client);
    return mapped[0] || null;
}

async function countDoctorsByLegacyIds(legacyIds = [], client = null) {
    const normalizedLegacyIds = Array.from(new Set((legacyIds || [])
        .map((id) => normalizeLegacyDoctorId(id))
        .filter(Boolean)));
    if (!normalizedLegacyIds.length) {
        return 0;
    }
    const executor = client || getPostgresPool();
    const result = await executor.query(
        `SELECT COUNT(*)::int AS count
         FROM doctors
         WHERE legacy_mongo_id = ANY($1::char(24)[])`,
        [normalizedLegacyIds]
    );
    return Number(result.rows?.[0]?.count || 0);
}

async function createDoctor({
    slug,
    displayName,
    specialty = DEFAULT_SPECIALTY,
    isActive = true,
    bookingSettings = DEFAULT_BOOKING_SETTINGS,
    availabilityRules = { weekdays: DEFAULT_AVAILABILITY_WEEKDAYS },
    blockedDates = [],
    legacyPublicId = null,
    createdByUserPublicId = null,
    updatedByUserPublicId = null
} = {}, client = null) {
    const normalizedSlug = normalizeDoctorSlug(slug);
    if (!normalizedSlug) {
        throw new Error('createDoctor requires a valid slug');
    }
    const normalizedDisplayName = String(displayName || '').trim();
    if (!normalizedDisplayName) {
        throw new Error('createDoctor requires displayName');
    }
    const normalizedLegacyPublicId = normalizeLegacyDoctorId(legacyPublicId) || generateLegacyPublicId();
    const normalizedBookingSettings = normalizeBookingSettings(bookingSettings);
    const normalizedAvailability = normalizeAvailabilityRules(availabilityRules, normalizedBookingSettings, { defaultIfEmpty: true });
    const bookingSettingsForLegacyColumns = inferLegacyBookingSettingsFromDayConfigs(
        normalizedBookingSettings,
        normalizedAvailability.dayConfigs
    );
    const normalizedBlockedDates = normalizeBlockedDates(blockedDates);

    const task = async (txClient) => {
        const createdByUserPgId = await queryUserPgIdByPublicId(createdByUserPublicId, txClient);
        const updatedByUserPgId = await queryUserPgIdByPublicId(updatedByUserPublicId, txClient);
        const insertResult = await txClient.query(
            `INSERT INTO doctors (
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
                updated_by_user_id
            )
            VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7::time,
                $8::time,
                $9,
                $10,
                $11::uuid,
                $12::uuid
            )
            RETURNING id`,
            [
                normalizedLegacyPublicId,
                normalizedSlug,
                normalizedDisplayName,
                String(specialty || DEFAULT_SPECIALTY).trim() || DEFAULT_SPECIALTY,
                !!isActive,
                bookingSettingsForLegacyColumns.consultationDurationMinutes,
                bookingSettingsForLegacyColumns.workdayStart,
                bookingSettingsForLegacyColumns.workdayEnd,
                bookingSettingsForLegacyColumns.monthsToShow,
                bookingSettingsForLegacyColumns.timezone,
                createdByUserPgId,
                updatedByUserPgId || createdByUserPgId
            ]
        );

        const doctorPgId = String(insertResult.rows[0].id);
        await replaceDoctorAvailabilityRulesByPgId(
            doctorPgId,
            normalizedAvailability,
            bookingSettingsForLegacyColumns,
            txClient
        );
        await replaceDoctorBlockedDatesByPgId(
            doctorPgId,
            normalizedBlockedDates,
            updatedByUserPgId || createdByUserPgId,
            txClient
        );

        const row = await queryDoctorRowByPgId(doctorPgId, txClient);
        const mapped = await mapDoctorRows([row], txClient);
        return mapped[0] || null;
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function updateDoctorByLegacyId(legacyDoctorId, updates = {}, client = null) {
    const normalizedLegacyDoctorId = normalizeLegacyDoctorId(legacyDoctorId);
    if (!normalizedLegacyDoctorId) return null;

    const task = async (txClient) => {
        const existingRow = await queryDoctorRowByLegacyId(normalizedLegacyDoctorId, txClient);
        if (!existingRow) {
            return null;
        }

        const existingMapped = (await mapDoctorRows([existingRow], txClient))[0];
        let mergedBookingSettings = normalizeBookingSettings({
            ...existingMapped.bookingSettings,
            ...(updates.bookingSettings || {})
        });

        let availabilityToPersist = null;
        if (Object.prototype.hasOwnProperty.call(updates, 'availabilityRules')) {
            availabilityToPersist = normalizeAvailabilityRules(updates.availabilityRules, mergedBookingSettings, { defaultIfEmpty: true });
            mergedBookingSettings = inferLegacyBookingSettingsFromDayConfigs(
                mergedBookingSettings,
                availabilityToPersist.dayConfigs
            );
        } else if (Object.prototype.hasOwnProperty.call(updates, 'bookingSettings')) {
            const scheduleFieldsChanged = (
                mergedBookingSettings.workdayStart !== existingMapped.bookingSettings.workdayStart
                || mergedBookingSettings.workdayEnd !== existingMapped.bookingSettings.workdayEnd
                || mergedBookingSettings.consultationDurationMinutes !== existingMapped.bookingSettings.consultationDurationMinutes
            );
            if (scheduleFieldsChanged) {
                availabilityToPersist = normalizeAvailabilityRules(
                    { weekdays: existingMapped.availabilityRules.weekdays },
                    mergedBookingSettings,
                    { defaultIfEmpty: true }
                );
            }
        }

        const setClauses = [];
        const params = [];
        let index = 1;

        if (Object.prototype.hasOwnProperty.call(updates, 'slug')) {
            const normalizedSlug = normalizeDoctorSlug(updates.slug);
            if (!normalizedSlug) {
                throw new Error('Invalid doctor slug.');
            }
            setClauses.push(`slug = $${index++}`);
            params.push(normalizedSlug);
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'displayName')) {
            setClauses.push(`display_name = $${index++}`);
            params.push(String(updates.displayName || '').trim());
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'specialty')) {
            setClauses.push(`specialty = $${index++}`);
            params.push(String(updates.specialty || DEFAULT_SPECIALTY).trim() || DEFAULT_SPECIALTY);
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'isActive')) {
            setClauses.push(`is_active = $${index++}`);
            params.push(!!updates.isActive);
        }

        const shouldPersistBookingColumns = Object.prototype.hasOwnProperty.call(updates, 'bookingSettings')
            || Object.prototype.hasOwnProperty.call(updates, 'availabilityRules');
        if (shouldPersistBookingColumns) {
            setClauses.push(`consultation_duration_minutes = $${index++}`);
            params.push(mergedBookingSettings.consultationDurationMinutes);
            setClauses.push(`workday_start = $${index++}::time`);
            params.push(mergedBookingSettings.workdayStart);
            setClauses.push(`workday_end = $${index++}::time`);
            params.push(mergedBookingSettings.workdayEnd);
            setClauses.push(`months_to_show = $${index++}`);
            params.push(mergedBookingSettings.monthsToShow);
            setClauses.push(`timezone = $${index++}`);
            params.push(mergedBookingSettings.timezone);
        }

        const updatedByUserPgId = await queryUserPgIdByPublicId(updates.updatedByUserPublicId, txClient);
        setClauses.push(`updated_by_user_id = $${index++}::uuid`);
        params.push(updatedByUserPgId);
        setClauses.push('updated_at = now()');

        params.push(existingRow.id);
        await txClient.query(
            `UPDATE doctors
             SET ${setClauses.join(', ')}
             WHERE id = $${index}`,
            params
        );

        if (availabilityToPersist) {
            await replaceDoctorAvailabilityRulesByPgId(
                existingRow.id,
                availabilityToPersist,
                mergedBookingSettings,
                txClient
            );
        }

        if (Object.prototype.hasOwnProperty.call(updates, 'blockedDates')) {
            await replaceDoctorBlockedDatesByPgId(
                existingRow.id,
                updates.blockedDates,
                updatedByUserPgId,
                txClient
            );
        }

        const refreshedRow = await queryDoctorRowByPgId(existingRow.id, txClient);
        const mapped = await mapDoctorRows([refreshedRow], txClient);
        return mapped[0] || null;
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function deleteDoctorByLegacyId(legacyDoctorId, { actorUserPublicId = null } = {}, client = null) {
    const normalizedLegacyDoctorId = normalizeLegacyDoctorId(legacyDoctorId);
    if (!normalizedLegacyDoctorId) {
        return null;
    }

    const task = async (txClient) => {
        const existingRow = await queryDoctorRowByLegacyId(normalizedLegacyDoctorId, txClient);
        if (!existingRow) {
            return null;
        }

        const actorUserPgId = await queryUserPgIdByPublicId(actorUserPublicId, txClient);
        const appointmentCountResult = await txClient.query(
            `SELECT COUNT(*)::int AS count
             FROM appointments
             WHERE doctor_id = $1`,
            [existingRow.id]
        );
        const deletedAppointments = Number(appointmentCountResult.rows?.[0]?.count || 0);

        await txClient.query(
            `DELETE FROM appointments
             WHERE doctor_id = $1`,
            [existingRow.id]
        );

        await txClient.query(
            `DELETE FROM doctor_admin_assignments
             WHERE doctor_id = $1
                OR legacy_doctor_mongo_id = $2::char(24)`,
            [existingRow.id, normalizedLegacyDoctorId]
        );

        await txClient.query(
            `DELETE FROM doctors
             WHERE id = $1`,
            [existingRow.id]
        );

        return {
            _id: normalizedLegacyDoctorId,
            pgId: String(existingRow.id),
            slug: String(existingRow.slug || ''),
            displayName: String(existingRow.display_name || ''),
            deletedAppointments,
            deletedByUserId: actorUserPgId
        };
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function blockDoctorDateByLegacyId(legacyDoctorId, blockedDate, { reason = null, actorUserPublicId = null } = {}, client = null) {
    const normalizedLegacyDoctorId = normalizeLegacyDoctorId(legacyDoctorId);
    const normalizedBlockedDate = normalizeIsoDate(blockedDate);
    if (!normalizedLegacyDoctorId || !normalizedBlockedDate) {
        return null;
    }

    const task = async (txClient) => {
        const doctorRow = await queryDoctorRowByLegacyId(normalizedLegacyDoctorId, txClient);
        if (!doctorRow) return null;

        const actorUserPgId = await queryUserPgIdByPublicId(actorUserPublicId, txClient);
        await txClient.query(
            `INSERT INTO doctor_blocked_days (
                doctor_id,
                blocked_date,
                reason,
                is_active,
                created_by_user_id,
                updated_by_user_id,
                disabled_at,
                disabled_by_user_id
            )
            VALUES (
                $1,
                $2::date,
                $3,
                TRUE,
                $4::uuid,
                $4::uuid,
                NULL,
                NULL
            )
            ON CONFLICT (doctor_id, blocked_date)
            DO UPDATE SET
                reason = COALESCE(EXCLUDED.reason, doctor_blocked_days.reason),
                is_active = TRUE,
                updated_by_user_id = EXCLUDED.updated_by_user_id,
                disabled_at = NULL,
                disabled_by_user_id = NULL,
                updated_at = now()`,
            [doctorRow.id, normalizedBlockedDate, reason ? String(reason).trim() : null, actorUserPgId]
        );

        await txClient.query(
            `UPDATE doctors
             SET updated_by_user_id = $1::uuid,
                 updated_at = now()
             WHERE id = $2`,
            [actorUserPgId, doctorRow.id]
        );

        const refreshedRow = await queryDoctorRowByPgId(doctorRow.id, txClient);
        const mapped = await mapDoctorRows([refreshedRow], txClient);
        return mapped[0] || null;
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function unblockDoctorDateByLegacyId(legacyDoctorId, blockedDate, { actorUserPublicId = null } = {}, client = null) {
    const normalizedLegacyDoctorId = normalizeLegacyDoctorId(legacyDoctorId);
    const normalizedBlockedDate = normalizeIsoDate(blockedDate);
    if (!normalizedLegacyDoctorId || !normalizedBlockedDate) {
        return null;
    }

    const task = async (txClient) => {
        const doctorRow = await queryDoctorRowByLegacyId(normalizedLegacyDoctorId, txClient);
        if (!doctorRow) return null;

        const actorUserPgId = await queryUserPgIdByPublicId(actorUserPublicId, txClient);
        await txClient.query(
            `UPDATE doctor_blocked_days
             SET is_active = FALSE,
                 updated_by_user_id = $3::uuid,
                 disabled_at = now(),
                 disabled_by_user_id = $3::uuid,
                 updated_at = now()
             WHERE doctor_id = $1
               AND blocked_date = $2::date`,
            [doctorRow.id, normalizedBlockedDate, actorUserPgId]
        );

        await txClient.query(
            `UPDATE doctors
             SET updated_by_user_id = $1::uuid,
                 updated_at = now()
             WHERE id = $2`,
            [actorUserPgId, doctorRow.id]
        );

        const refreshedRow = await queryDoctorRowByPgId(doctorRow.id, txClient);
        const mapped = await mapDoctorRows([refreshedRow], txClient);
        return mapped[0] || null;
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

module.exports = {
    LEGACY_OBJECT_ID_REGEX,
    isUniqueViolation,
    normalizeLegacyDoctorId,
    normalizeWeekdays,
    normalizeBlockedDates,
    normalizeBookingSettings,
    normalizeDayConfigs,
    normalizeAvailabilityRules,
    withTransaction,
    listDoctors,
    findDoctorByIdentifier,
    countDoctorsByLegacyIds,
    createDoctor,
    updateDoctorByLegacyId,
    deleteDoctorByLegacyId,
    getDoctorDayScheduleByLegacyId,
    upsertDoctorDayOverrideByLegacyId,
    removeDoctorDayOverrideByLegacyId,
    blockDoctorDateByLegacyId,
    unblockDoctorDateByLegacyId
};
