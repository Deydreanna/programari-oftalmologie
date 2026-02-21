const crypto = require('crypto');
const { getPostgresPool } = require('./postgres');

const MONGODB_OBJECT_ID_REGEX = /^[a-fA-F0-9]{24}$/;
const POSTGRES_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUniqueViolation(error) {
    return error?.code === '23505';
}

function isPostgresUuid(value) {
    return POSTGRES_UUID_REGEX.test(String(value || '').trim());
}

function normalizeManagedDoctorIds(value = []) {
    if (!Array.isArray(value)) {
        return [];
    }
    const out = [];
    const seen = new Set();
    for (const entry of value) {
        const id = String(entry || '').trim();
        if (!MONGODB_OBJECT_ID_REGEX.test(id)) continue;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(id);
    }
    return out;
}

function generateLegacyMongoId() {
    return crypto.randomBytes(12).toString('hex');
}

function mapUserRow(row, managedDoctorIds = []) {
    const publicId = row.legacy_mongo_id || row.id;
    return {
        _id: publicId,
        pgId: row.id,
        legacyMongoId: row.legacy_mongo_id || null,
        email: row.email || null,
        phone: row.phone || null,
        password: row.password_hash,
        googleId: row.google_id || null,
        displayName: row.display_name,
        role: row.role,
        managedDoctorIds: normalizeManagedDoctorIds(managedDoctorIds),
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

async function queryManagedDoctorIdsByUserPgId(userPgId, client = null) {
    const executor = client || getPostgresPool();
    const result = await executor.query(
        `SELECT legacy_doctor_mongo_id
         FROM doctor_admin_assignments
         WHERE user_id = $1
           AND legacy_doctor_mongo_id IS NOT NULL
         ORDER BY created_at ASC`,
        [userPgId]
    );
    return normalizeManagedDoctorIds(result.rows.map((row) => row.legacy_doctor_mongo_id));
}

async function queryManagedDoctorMapByUserPgIds(userPgIds = [], client = null) {
    const normalizedIds = Array.from(new Set(
        (Array.isArray(userPgIds) ? userPgIds : [])
            .map((id) => String(id || '').trim())
            .filter(Boolean)
    ));
    const out = new Map();
    if (!normalizedIds.length) {
        return out;
    }

    const executor = client || getPostgresPool();
    const result = await executor.query(
        `SELECT user_id, legacy_doctor_mongo_id
         FROM doctor_admin_assignments
         WHERE user_id = ANY($1::uuid[])
           AND legacy_doctor_mongo_id IS NOT NULL
         ORDER BY created_at ASC`,
        [normalizedIds]
    );

    for (const row of result.rows) {
        const key = String(row.user_id);
        if (!out.has(key)) {
            out.set(key, []);
        }
        out.get(key).push(row.legacy_doctor_mongo_id);
    }

    for (const [key, ids] of out) {
        out.set(key, normalizeManagedDoctorIds(ids));
    }
    return out;
}

async function findUserRowByPublicId(publicId, client = null) {
    const id = String(publicId || '').trim();
    if (!id) return null;
    if (MONGODB_OBJECT_ID_REGEX.test(id)) {
        return queryOneRow(
            `SELECT id, legacy_mongo_id, email, phone, password_hash, google_id, display_name, role, created_at
             FROM users
             WHERE legacy_mongo_id = $1::char(24)
             LIMIT 1`,
            [id],
            client
        );
    }
    if (isPostgresUuid(id)) {
        return queryOneRow(
            `SELECT id, legacy_mongo_id, email, phone, password_hash, google_id, display_name, role, created_at
             FROM users
             WHERE id = $1::uuid
             LIMIT 1`,
            [id],
            client
        );
    }
    return null;
}

async function findUserByPublicId(publicId, client = null) {
    const row = await findUserRowByPublicId(publicId, client);
    if (!row) return null;
    const managedDoctorIds = await queryManagedDoctorIdsByUserPgId(row.id, client);
    return mapUserRow(row, managedDoctorIds);
}

async function findUserByEmail(email, client = null) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!normalizedEmail) return null;
    const row = await queryOneRow(
        `SELECT id, legacy_mongo_id, email, phone, password_hash, google_id, display_name, role, created_at
         FROM users
         WHERE lower(email) = $1
         LIMIT 1`,
        [normalizedEmail],
        client
    );
    if (!row) return null;
    const managedDoctorIds = await queryManagedDoctorIdsByUserPgId(row.id, client);
    return mapUserRow(row, managedDoctorIds);
}

async function findUserByPhone(phone, client = null) {
    const normalizedPhone = String(phone || '').trim();
    if (!normalizedPhone) return null;
    const row = await queryOneRow(
        `SELECT id, legacy_mongo_id, email, phone, password_hash, google_id, display_name, role, created_at
         FROM users
         WHERE phone = $1
         LIMIT 1`,
        [normalizedPhone],
        client
    );
    if (!row) return null;
    const managedDoctorIds = await queryManagedDoctorIdsByUserPgId(row.id, client);
    return mapUserRow(row, managedDoctorIds);
}

async function countUsersByRole(role, client = null) {
    const executor = client || getPostgresPool();
    const result = await executor.query(
        `SELECT COUNT(*)::int AS count
         FROM users
         WHERE role = $1`,
        [String(role || '').trim()]
    );
    return Number(result.rows?.[0]?.count || 0);
}

async function listUsers(client = null) {
    const executor = client || getPostgresPool();
    const result = await executor.query(
        `SELECT id, legacy_mongo_id, email, phone, password_hash, google_id, display_name, role, created_at
         FROM users
         ORDER BY created_at DESC`
    );

    const rows = result.rows || [];
    if (!rows.length) {
        return [];
    }

    const managedDoctorMap = await queryManagedDoctorMapByUserPgIds(rows.map((row) => row.id), client);
    return rows.map((row) => mapUserRow(row, managedDoctorMap.get(String(row.id)) || []));
}

async function replaceUserDoctorAssignmentsByPgId(userPgId, legacyUserMongoId, managedDoctorIds = [], client = null) {
    const normalizedDoctorIds = normalizeManagedDoctorIds(managedDoctorIds);
    const executor = client || getPostgresPool();

    await executor.query(
        `DELETE FROM doctor_admin_assignments
         WHERE user_id = $1`,
        [userPgId]
    );

    if (!normalizedDoctorIds.length) {
        return normalizedDoctorIds;
    }

    for (const doctorLegacyId of normalizedDoctorIds) {
        await executor.query(
            `INSERT INTO doctor_admin_assignments (doctor_id, user_id, legacy_doctor_mongo_id, legacy_user_mongo_id)
             VALUES (NULL, $1, $2, $3)`,
            [userPgId, doctorLegacyId, legacyUserMongoId || null]
        );
    }
    return normalizedDoctorIds;
}

async function createUser({
    email = null,
    phone = null,
    passwordHash,
    googleId = null,
    displayName,
    role,
    managedDoctorIds = [],
    legacyMongoId = null,
    createdAt = null
} = {}, client = null) {
    if (!passwordHash) {
        throw new Error('passwordHash is required for createUser');
    }
    if (!displayName) {
        throw new Error('displayName is required for createUser');
    }
    if (!role) {
        throw new Error('role is required for createUser');
    }

    const normalizedEmail = email ? String(email).trim().toLowerCase() : null;
    const normalizedPhone = phone ? String(phone).trim() : null;
    const normalizedLegacyId = String(legacyMongoId || '').trim() || generateLegacyMongoId();
    const normalizedCreatedAt = createdAt ? new Date(createdAt) : null;
    const normalizedDoctorIds = normalizeManagedDoctorIds(managedDoctorIds);

    const task = async (txClient) => {
        const inserted = await txClient.query(
            `INSERT INTO users (
                legacy_mongo_id, email, phone, password_hash, google_id, display_name, role, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, COALESCE($8::timestamptz, now())
            )
            RETURNING id, legacy_mongo_id, email, phone, password_hash, google_id, display_name, role, created_at`,
            [
                normalizedLegacyId,
                normalizedEmail,
                normalizedPhone,
                passwordHash,
                googleId ? String(googleId).trim() : null,
                String(displayName).trim(),
                String(role).trim(),
                normalizedCreatedAt ? normalizedCreatedAt.toISOString() : null
            ]
        );
        const row = inserted.rows[0];
        await replaceUserDoctorAssignmentsByPgId(row.id, row.legacy_mongo_id, normalizedDoctorIds, txClient);
        return mapUserRow(row, normalizedDoctorIds);
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function updateUserByPublicId(publicId, updates = {}, client = null) {
    const task = async (txClient) => {
        const existingRow = await findUserRowByPublicId(publicId, txClient);
        if (!existingRow) return null;

        const setClauses = [];
        const params = [];
        let index = 1;

        if (Object.prototype.hasOwnProperty.call(updates, 'email')) {
            setClauses.push(`email = $${index++}`);
            params.push(updates.email ? String(updates.email).trim().toLowerCase() : null);
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'phone')) {
            setClauses.push(`phone = $${index++}`);
            params.push(updates.phone ? String(updates.phone).trim() : null);
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'passwordHash')) {
            setClauses.push(`password_hash = $${index++}`);
            params.push(String(updates.passwordHash || ''));
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'googleId')) {
            setClauses.push(`google_id = $${index++}`);
            params.push(updates.googleId ? String(updates.googleId).trim() : null);
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'displayName')) {
            setClauses.push(`display_name = $${index++}`);
            params.push(String(updates.displayName || '').trim());
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'role')) {
            setClauses.push(`role = $${index++}`);
            params.push(String(updates.role || '').trim());
        }

        let updatedRow = existingRow;
        if (setClauses.length > 0) {
            setClauses.push(`updated_at = now()`);
            params.push(existingRow.id);
            const updateResult = await txClient.query(
                `UPDATE users
                 SET ${setClauses.join(', ')}
                 WHERE id = $${index}
                 RETURNING id, legacy_mongo_id, email, phone, password_hash, google_id, display_name, role, created_at`,
                params
            );
            updatedRow = updateResult.rows[0];
        }

        let managedDoctorIds = await queryManagedDoctorIdsByUserPgId(updatedRow.id, txClient);
        if (Object.prototype.hasOwnProperty.call(updates, 'managedDoctorIds')) {
            managedDoctorIds = await replaceUserDoctorAssignmentsByPgId(
                updatedRow.id,
                updatedRow.legacy_mongo_id,
                updates.managedDoctorIds,
                txClient
            );
        }

        return mapUserRow(updatedRow, managedDoctorIds);
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function deleteUserByPublicId(publicId, client = null) {
    const task = async (txClient) => {
        const existing = await findUserRowByPublicId(publicId, txClient);
        if (!existing) {
            return null;
        }
        const managedDoctorIds = await queryManagedDoctorIdsByUserPgId(existing.id, txClient);
        await txClient.query(`DELETE FROM users WHERE id = $1`, [existing.id]);
        return mapUserRow(existing, managedDoctorIds);
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function upsertUserFromMongo(mongoUser = {}, client = null) {
    const legacyMongoId = String(mongoUser.legacyMongoId || mongoUser._id || '').trim();
    if (!MONGODB_OBJECT_ID_REGEX.test(legacyMongoId)) {
        throw new Error('upsertUserFromMongo requires a valid legacy Mongo ObjectId.');
    }

    const normalizedPayload = {
        email: mongoUser.email ? String(mongoUser.email).trim().toLowerCase() : null,
        phone: mongoUser.phone ? String(mongoUser.phone).trim() : null,
        passwordHash: String(mongoUser.password || ''),
        googleId: mongoUser.googleId ? String(mongoUser.googleId).trim() : null,
        displayName: String(mongoUser.displayName || '').trim() || 'Unknown User',
        role: String(mongoUser.role || 'viewer').trim(),
        managedDoctorIds: normalizeManagedDoctorIds(mongoUser.managedDoctorIds || []),
        createdAt: mongoUser.createdAt ? new Date(mongoUser.createdAt) : null
    };

    const task = async (txClient) => {
        let existing = await findUserRowByPublicId(legacyMongoId, txClient);
        if (!existing && normalizedPayload.email) {
            existing = await queryOneRow(
                `SELECT id, legacy_mongo_id, email, phone, password_hash, google_id, display_name, role, created_at
                 FROM users
                 WHERE lower(email) = $1
                 LIMIT 1`,
                [normalizedPayload.email],
                txClient
            );
        }
        if (!existing && normalizedPayload.phone) {
            existing = await queryOneRow(
                `SELECT id, legacy_mongo_id, email, phone, password_hash, google_id, display_name, role, created_at
                 FROM users
                 WHERE phone = $1
                 LIMIT 1`,
                [normalizedPayload.phone],
                txClient
            );
        }

        if (!existing) {
            return createUser({
                legacyMongoId,
                email: normalizedPayload.email,
                phone: normalizedPayload.phone,
                passwordHash: normalizedPayload.passwordHash,
                googleId: normalizedPayload.googleId,
                displayName: normalizedPayload.displayName,
                role: normalizedPayload.role,
                managedDoctorIds: normalizedPayload.managedDoctorIds,
                createdAt: normalizedPayload.createdAt
            }, txClient);
        }

        if (!existing.legacy_mongo_id) {
            await txClient.query(
                `UPDATE users
                 SET legacy_mongo_id = $1,
                     updated_at = now()
                 WHERE id = $2`,
                [legacyMongoId, existing.id]
            );
        }

        return updateUserByPublicId(
            legacyMongoId,
            {
                email: normalizedPayload.email,
                phone: normalizedPayload.phone,
                passwordHash: normalizedPayload.passwordHash,
                googleId: normalizedPayload.googleId,
                displayName: normalizedPayload.displayName,
                role: normalizedPayload.role,
                managedDoctorIds: normalizedPayload.managedDoctorIds
            },
            txClient
        );
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function assignAdminToDoctor(userPublicId, doctorLegacyId, client = null) {
    const task = async (txClient) => {
        const userRow = await findUserRowByPublicId(userPublicId, txClient);
        if (!userRow) {
            return false;
        }
        const normalizedDoctorId = String(doctorLegacyId || '').trim();
        if (!MONGODB_OBJECT_ID_REGEX.test(normalizedDoctorId)) {
            return false;
        }

        await txClient.query(
            `INSERT INTO doctor_admin_assignments (doctor_id, user_id, legacy_doctor_mongo_id, legacy_user_mongo_id)
             SELECT NULL, $1, $2, $3
             WHERE NOT EXISTS (
                SELECT 1
                FROM doctor_admin_assignments
                WHERE user_id = $1
                  AND legacy_doctor_mongo_id = $2
             )`,
            [userRow.id, normalizedDoctorId, userRow.legacy_mongo_id || null]
        );
        return true;
    };

    if (client) {
        return task(client);
    }
    return withTransaction(task);
}

async function canUserManageDoctor(userPublicId, doctorLegacyId, client = null) {
    const user = await findUserByPublicId(userPublicId, client);
    if (!user) return false;
    return normalizeManagedDoctorIds(user.managedDoctorIds).includes(String(doctorLegacyId || '').trim());
}

async function listDoctorsForAdmin(userPublicId, client = null) {
    const user = await findUserByPublicId(userPublicId, client);
    if (!user) return [];
    return normalizeManagedDoctorIds(user.managedDoctorIds);
}

module.exports = {
    MONGODB_OBJECT_ID_REGEX,
    isUniqueViolation,
    normalizeManagedDoctorIds,
    withTransaction,
    findUserByPublicId,
    findUserByEmail,
    findUserByPhone,
    countUsersByRole,
    listUsers,
    createUser,
    updateUserByPublicId,
    deleteUserByPublicId,
    upsertUserFromMongo,
    assignAdminToDoctor,
    canUserManageDoctor,
    listDoctorsForAdmin
};
