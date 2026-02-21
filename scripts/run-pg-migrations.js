#!/usr/bin/env node
require('dotenv').config();

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
    getPostgresPool,
    closePostgresPool,
    getPostgresTargetSummary,
    redactPostgresUrlInText
} = require('../db/postgres');

const MIGRATIONS_DIR = path.join(__dirname, '..', 'db', 'migrations');

function readMigrationFiles(dir) {
    if (!fs.existsSync(dir)) {
        return [];
    }

    return fs.readdirSync(dir)
        .filter((fileName) => fileName.toLowerCase().endsWith('.sql'))
        .sort((a, b) => a.localeCompare(b))
        .map((fileName) => path.join(dir, fileName));
}

function computeChecksum(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
}

async function ensureMigrationsTable(client) {
    await client.query(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id BIGSERIAL PRIMARY KEY,
            filename TEXT NOT NULL UNIQUE,
            checksum TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);
}

async function runMigration(client, migrationPath, fileName, checksum) {
    const sql = fs.readFileSync(migrationPath, 'utf8');
    await client.query('BEGIN');
    try {
        await client.query(sql);
        await client.query(
            `INSERT INTO schema_migrations (filename, checksum)
             VALUES ($1, $2)`,
            [fileName, checksum]
        );
        await client.query('COMMIT');
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    }
}

async function run() {
    const migrationPaths = readMigrationFiles(MIGRATIONS_DIR);
    if (!migrationPaths.length) {
        console.log(`[db:migrate] No SQL migrations found in ${MIGRATIONS_DIR}.`);
        return;
    }

    const target = getPostgresTargetSummary();
    console.log(`[db:migrate] Target: ${target}`);

    const pool = getPostgresPool();
    const client = await pool.connect();

    try {
        await ensureMigrationsTable(client);
        const appliedRows = await client.query('SELECT filename, checksum FROM schema_migrations');
        const appliedByFilename = new Map(appliedRows.rows.map((row) => [row.filename, row.checksum]));

        let appliedCount = 0;
        let skippedCount = 0;

        for (const migrationPath of migrationPaths) {
            const fileName = path.basename(migrationPath);
            const sql = fs.readFileSync(migrationPath, 'utf8');
            const checksum = computeChecksum(sql);
            const existingChecksum = appliedByFilename.get(fileName);

            if (existingChecksum) {
                if (existingChecksum !== checksum) {
                    throw new Error(
                        `Checksum mismatch for already-applied migration ${fileName}. `
                        + 'Create a new migration file instead of modifying existing migrations.'
                    );
                }
                skippedCount += 1;
                console.log(`[db:migrate] Skip ${fileName} (already applied).`);
                continue;
            }

            console.log(`[db:migrate] Apply ${fileName}...`);
            await runMigration(client, migrationPath, fileName, checksum);
            appliedCount += 1;
            console.log(`[db:migrate] Applied ${fileName}.`);
        }

        console.log(`[db:migrate] Complete. Applied=${appliedCount}, Skipped=${skippedCount}.`);
    } finally {
        client.release();
        await closePostgresPool();
    }
}

run().catch(async (error) => {
    console.error(`[db:migrate] Failed: ${redactPostgresUrlInText(error?.message || String(error))}`);
    try {
        await closePostgresPool();
    } catch (_) {
        // no-op
    }
    process.exit(1);
});
