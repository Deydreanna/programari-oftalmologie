const crypto = require('crypto');
const { getPostgresPool } = require('./postgres');

const MONGODB_OBJECT_ID_REGEX = /^[a-fA-F0-9]{24}$/;
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

function generateLegacyMongoId() {
    return crypto.randomBytes(12).toString('hex');
}

function normalizeLegacyDoctorId(value) {
    const candidate = String(value || '').trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(candidate)) {
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

function pgTimeToHHMM(value, fallback = '00:00') {
    const normalized = String(value || '').trim();
    const match = normalized.match(TIME_HHMM_REGEX);
    if (!match) {
        return fallback;
    }
    return `${match[1]}:${match[2]}`;
}

function mapDoctorRow(row, { weekdays = [], blockedDates = [] } = {}) {
    const publicId = normalizeLegacyDoctorId(row.legacy_mongo_id) || String(row.id || '');
    return {
        _id: publicId,
        pgId: String(row.id),
        legacyMongoId: normalizeLegacyDoctorId(row.legacy_mongo_id) || null,
        slug: row.slug,
        displayName: row.display_name,
        specialty: row.specialty || DEFAULT_SPECIALTY,
        isActive: !!row.is_active,
        bookingSettings: {
            consultationDurationMinutes: Number(row.consultation_duration_minutes),
            workdayStart: pgTimeToHHMM(row.workday_start, DEFAULT_BOOKING_SETTINGS.workdayStart),
            workdayEnd: pgTimeToHHMM(row.workday_end, DEFAULT_BOOKING_SETTINGS.workdayEnd),
            monthsToShow: Number(row.months_to_show),
            timezone: row.timezone || DEFAULT_BOOKING_SETTINGS.timezone
        },
        availabilityRules: {
            weekdays: normalizeWeekdays(weekdays)
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

async function queryDoctorWeekdaysByPgIds(doctorPgIds = [], client = null) {
    const ids = Array.from(new Set((doctorPgIds || []).map((id) => String(id || '').trim()).filter(Boolean)));
    const out = new Map();
    if (!ids.length) {
        return out;
    }

    const executor = client || getPostgresPool();
    const result = await executor.query(
        `SELECT doctor_id, weekday
         FROM doctor_availability_rules
         WHERE doctor_id = ANY($1::uuid[])
           AND is_active = TRUE
           AND (effective_from IS NULL OR effective_from <= CURRENT_DATE)
           AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
         ORDER BY weekday ASC`,
        [ids]
    );

    for (const row of result.rows) {
        const key = String(row.doctor_id);
        if (!out.has(key)) {
            out.set(key, []);
        }
        out.get(key).push(Number(row.weekday));
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
    const [weekdayMap, blockedDatesMap] = await Promise.all([
        queryDoctorWeekdaysByPgIds(pgIds, client),
        queryDoctorBlockedDatesByPgIds(pgIds, client)
    ]);
    return rowList.map((row) => mapDoctorRow(row, {
        weekdays: weekdayMap.get(String(row.id)) || [],
        blockedDates: blockedDatesMap.get(String(row.id)) || []
    }));
}

async function queryUserPgIdByPublicId(publicId, client = null) {
    const normalized = String(publicId || '').trim();
    if (!normalized) return null;

    let row = null;
    if (MONGODB_OBJECT_ID_REGEX.test(normalized)) {
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

async function replaceDoctorAvailabilityRulesByPgId(doctorPgId, weekdays, bookingSettings, client = null) {
    const executor = client || getPostgresPool();
    const normalizedWeekdays = normalizeWeekdays(weekdays);
    const normalizedSettings = normalizeBookingSettings(bookingSettings);

    await executor.query(
        `DELETE FROM doctor_availability_rules
         WHERE doctor_id = $1`,
        [doctorPgId]
    );

    for (const weekday of normalizedWeekdays) {
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
                weekday,
                normalizedSettings.workdayStart,
                normalizedSettings.workdayEnd,
                normalizedSettings.consultationDurationMinutes
            ]
        );
    }
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
    legacyMongoId = null,
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
    const normalizedLegacyMongoId = normalizeLegacyDoctorId(legacyMongoId) || generateLegacyMongoId();
    const normalizedBookingSettings = normalizeBookingSettings(bookingSettings);
    const normalizedWeekdays = normalizeWeekdays(availabilityRules?.weekdays || []);
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
                normalizedLegacyMongoId,
                normalizedSlug,
                normalizedDisplayName,
                String(specialty || DEFAULT_SPECIALTY).trim() || DEFAULT_SPECIALTY,
                !!isActive,
                normalizedBookingSettings.consultationDurationMinutes,
                normalizedBookingSettings.workdayStart,
                normalizedBookingSettings.workdayEnd,
                normalizedBookingSettings.monthsToShow,
                normalizedBookingSettings.timezone,
                createdByUserPgId,
                updatedByUserPgId || createdByUserPgId
            ]
        );

        const doctorPgId = String(insertResult.rows[0].id);
        await replaceDoctorAvailabilityRulesByPgId(
            doctorPgId,
            normalizedWeekdays.length ? normalizedWeekdays : DEFAULT_AVAILABILITY_WEEKDAYS,
            normalizedBookingSettings,
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
        const mergedBookingSettings = normalizeBookingSettings({
            ...existingMapped.bookingSettings,
            ...(updates.bookingSettings || {})
        });

        const setClauses = [];
        const params = [];
        let index = 1;

        if (Object.prototype.hasOwnProperty.call(updates, 'slug')) {
            setClauses.push(`slug = $${index++}`);
            params.push(normalizeDoctorSlug(updates.slug));
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
        if (Object.prototype.hasOwnProperty.call(updates, 'bookingSettings')) {
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

        if (Object.prototype.hasOwnProperty.call(updates, 'availabilityRules')
            || Object.prototype.hasOwnProperty.call(updates, 'bookingSettings')) {
            const weekdays = normalizeWeekdays(
                updates?.availabilityRules?.weekdays !== undefined
                    ? updates.availabilityRules.weekdays
                    : existingMapped.availabilityRules.weekdays
            );
            await replaceDoctorAvailabilityRulesByPgId(
                existingRow.id,
                weekdays.length ? weekdays : DEFAULT_AVAILABILITY_WEEKDAYS,
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

async function upsertDoctorFromMongo(mongoDoctor = {}, client = null) {
    const normalizedLegacyMongoId = normalizeLegacyDoctorId(mongoDoctor._id || mongoDoctor.legacyMongoId);
    if (!normalizedLegacyMongoId) {
        throw new Error('upsertDoctorFromMongo requires a valid legacy doctor id.');
    }

    const normalizedSlug = normalizeDoctorSlug(mongoDoctor.slug);
    if (!normalizedSlug) {
        throw new Error('upsertDoctorFromMongo requires a valid slug.');
    }

    const payload = {
        legacyMongoId: normalizedLegacyMongoId,
        slug: normalizedSlug,
        displayName: String(mongoDoctor.displayName || '').trim() || 'Doctor',
        specialty: String(mongoDoctor.specialty || DEFAULT_SPECIALTY).trim() || DEFAULT_SPECIALTY,
        isActive: mongoDoctor.isActive !== false,
        bookingSettings: normalizeBookingSettings(mongoDoctor.bookingSettings || {}),
        availabilityRules: {
            weekdays: normalizeWeekdays(mongoDoctor?.availabilityRules?.weekdays || DEFAULT_AVAILABILITY_WEEKDAYS)
        },
        blockedDates: normalizeBlockedDates(mongoDoctor.blockedDates || []),
        createdByUserPublicId: normalizeLegacyDoctorId(mongoDoctor.createdByUserId) || null,
        updatedByUserPublicId: normalizeLegacyDoctorId(mongoDoctor.updatedByUserId) || null
    };

    const task = async (txClient) => {
        let existingRow = await queryDoctorRowByLegacyId(normalizedLegacyMongoId, txClient);
        if (!existingRow) {
            existingRow = await queryOneRow(
                `SELECT id, TRIM(legacy_mongo_id) AS legacy_mongo_id
                 FROM doctors
                 WHERE slug = $1
                 LIMIT 1`,
                [payload.slug],
                txClient
            );
        }

        if (!existingRow) {
            return createDoctor(payload, txClient);
        }

        if (!existingRow.legacy_mongo_id) {
            await txClient.query(
                `UPDATE doctors
                 SET legacy_mongo_id = $1,
                     updated_at = now()
                 WHERE id = $2`,
                [normalizedLegacyMongoId, existingRow.id]
            );
        }

        return updateDoctorByLegacyId(
            normalizedLegacyMongoId,
            {
                slug: payload.slug,
                displayName: payload.displayName,
                specialty: payload.specialty,
                isActive: payload.isActive,
                bookingSettings: payload.bookingSettings,
                availabilityRules: payload.availabilityRules,
                blockedDates: payload.blockedDates,
                updatedByUserPublicId: payload.updatedByUserPublicId
            },
            txClient
        );
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

module.exports = {
    MONGODB_OBJECT_ID_REGEX,
    isUniqueViolation,
    normalizeLegacyDoctorId,
    normalizeWeekdays,
    normalizeBlockedDates,
    normalizeBookingSettings,
    withTransaction,
    listDoctors,
    findDoctorByIdentifier,
    countDoctorsByLegacyIds,
    createDoctor,
    updateDoctorByLegacyId,
    blockDoctorDateByLegacyId,
    unblockDoctorDateByLegacyId,
    upsertDoctorFromMongo
};
