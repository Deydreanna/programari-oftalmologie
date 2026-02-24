#!/usr/bin/env node
require('dotenv').config();

const {
    getPostgresPool,
    closePostgresPool,
    redactPostgresUrlInText
} = require('../db/postgres');
const {
    isEncryptedPayload,
    encryptTextField,
    decryptTextField,
    normalizePhone,
    normalizeEmail,
    normalizeCnp,
    computeBlindIndex,
    BLIND_INDEX_KIND
} = require('../db/patient-crypto');

function splitLegacyName(fullName) {
    const normalized = String(fullName || '').trim();
    if (!normalized) {
        return { firstName: '', lastName: '' };
    }
    const parts = normalized.split(/\s+/).filter(Boolean);
    if (parts.length === 1) {
        return { firstName: parts[0], lastName: parts[0] };
    }
    return {
        lastName: parts[0],
        firstName: parts.slice(1).join(' ')
    };
}

function buildUpdateStatement(id, updates) {
    const entries = Object.entries(updates).filter(([, value]) => value !== undefined);
    if (!entries.length) return null;

    const setSql = [];
    const params = [];
    let index = 1;
    for (const [column, value] of entries) {
        setSql.push(`${column} = $${index}`);
        params.push(value);
        index += 1;
    }

    params.push(id);
    return {
        sql: `UPDATE appointments SET ${setSql.join(', ')} WHERE id = $${index}`,
        params
    };
}

async function run() {
    const pool = getPostgresPool();
    const client = await pool.connect();
    let scanned = 0;
    let updated = 0;

    try {
        const result = await client.query(
            `SELECT
                id::text AS id,
                TRIM(legacy_mongo_id) AS legacy_mongo_id,
                name,
                first_name,
                last_name,
                phone,
                email,
                cnp,
                phone_index,
                email_index,
                cnp_index
             FROM appointments
             ORDER BY created_at ASC`
        );

        for (const row of result.rows || []) {
            scanned += 1;
            const rowLabel = row.legacy_mongo_id || row.id;
            const updates = {};

            const plainName = decryptTextField(row.name, { fieldName: 'name' }) || '';
            let plainFirstName = decryptTextField(row.first_name, { fieldName: 'first_name' }) || '';
            let plainLastName = decryptTextField(row.last_name, { fieldName: 'last_name' }) || '';

            if ((!plainFirstName || !plainLastName) && plainName) {
                const split = splitLegacyName(plainName);
                if (!plainFirstName) plainFirstName = split.firstName;
                if (!plainLastName) plainLastName = split.lastName;
            }

            const plainPhone = normalizePhone(decryptTextField(row.phone, { fieldName: 'phone' }) || '');
            const plainEmail = normalizeEmail(decryptTextField(row.email, { fieldName: 'email' }) || '');
            const plainCnp = normalizeCnp(decryptTextField(row.cnp, { fieldName: 'cnp' }) || '');

            if (plainName && !isEncryptedPayload(row.name)) {
                updates.name = encryptTextField(plainName);
            }
            if (plainFirstName && !isEncryptedPayload(row.first_name)) {
                updates.first_name = encryptTextField(plainFirstName);
            }
            if (plainLastName && !isEncryptedPayload(row.last_name)) {
                updates.last_name = encryptTextField(plainLastName);
            }
            if (plainPhone && !isEncryptedPayload(row.phone)) {
                updates.phone = encryptTextField(plainPhone);
            }
            if (plainEmail && !isEncryptedPayload(row.email)) {
                updates.email = encryptTextField(plainEmail);
            }
            if (plainCnp && !isEncryptedPayload(row.cnp)) {
                updates.cnp = encryptTextField(plainCnp);
            }

            if (plainPhone) {
                const phoneIndex = computeBlindIndex(plainPhone, BLIND_INDEX_KIND.PHONE);
                if (row.phone_index !== phoneIndex) {
                    updates.phone_index = phoneIndex;
                }
            } else if (row.phone_index !== null) {
                updates.phone_index = null;
            }
            if (plainEmail) {
                const emailIndex = computeBlindIndex(plainEmail, BLIND_INDEX_KIND.EMAIL);
                if (row.email_index !== emailIndex) {
                    updates.email_index = emailIndex;
                }
            } else if (row.email_index !== null) {
                updates.email_index = null;
            }
            if (plainCnp) {
                const cnpIndex = computeBlindIndex(plainCnp, BLIND_INDEX_KIND.CNP);
                if (row.cnp_index !== cnpIndex) {
                    updates.cnp_index = cnpIndex;
                }
            } else if (row.cnp_index !== null) {
                updates.cnp_index = null;
            }

            const statement = buildUpdateStatement(row.id, updates);
            if (!statement) continue;

            await client.query(statement.sql, statement.params);
            updated += 1;
            console.log(`[patient-text-migrate] updated appointment ${rowLabel}`);
        }

        console.log(`[patient-text-migrate] done scanned=${scanned} updated=${updated}`);
    } finally {
        client.release();
        await closePostgresPool();
    }
}

run().catch(async (error) => {
    console.error(`[patient-text-migrate] failed: ${redactPostgresUrlInText(error?.message || String(error))}`);
    try {
        await closePostgresPool();
    } catch (_) {
        // no-op
    }
    process.exit(1);
});
