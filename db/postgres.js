const { Pool } = require('pg');
const { normalizeDbProvider, isPostgresProvider, validateDatabaseUrl } = require('../scripts/env-utils');

const DEFAULT_POOL_MAX = 10;
const DEFAULT_IDLE_TIMEOUT_MS = 30000;
const DEFAULT_CONNECTION_TIMEOUT_MS = 5000;
const POSTGRES_URI_REGEX = /postgres(?:ql)?:\/\/[^\s'"]+/gi;

let poolInstance = null;

function redactPostgresUrlInText(text) {
    return String(text || '').replace(POSTGRES_URI_REGEX, '<redacted-postgres-uri>');
}

function toPositiveInt(value, fallback) {
    const parsed = Number.parseInt(String(value || ''), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        return fallback;
    }
    return parsed;
}

function getPostgresConfig(connectionString = process.env.DATABASE_URL) {
    const validation = validateDatabaseUrl(connectionString);
    if (!validation.ok) {
        const error = new Error(validation.errors.join(' '));
        error.name = 'PostgresConfigError';
        throw error;
    }

    return {
        connectionString: String(connectionString).trim(),
        max: toPositiveInt(process.env.PG_POOL_MAX, DEFAULT_POOL_MAX),
        idleTimeoutMillis: toPositiveInt(process.env.PG_IDLE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS),
        connectionTimeoutMillis: toPositiveInt(process.env.PG_CONNECTION_TIMEOUT_MS, DEFAULT_CONNECTION_TIMEOUT_MS)
    };
}

function getPostgresTargetSummary(connectionString = process.env.DATABASE_URL) {
    const validation = validateDatabaseUrl(connectionString);
    if (!validation.ok || !validation.parsed) {
        return 'invalid DATABASE_URL';
    }
    const { hostname, port, database } = validation.parsed;
    return `${hostname}:${port}/${database}`;
}

function getPostgresPool() {
    if (poolInstance) {
        return poolInstance;
    }

    const config = getPostgresConfig();
    poolInstance = new Pool(config);
    poolInstance.on('error', (error) => {
        console.error(`[POSTGRES] Pool error: ${redactPostgresUrlInText(error?.message || String(error))}`);
    });
    return poolInstance;
}

async function closePostgresPool() {
    if (!poolInstance) return;
    const targetSummary = getPostgresTargetSummary();
    const current = poolInstance;
    poolInstance = null;
    await current.end();
    console.log(`[POSTGRES] Pool closed (${targetSummary}).`);
}

async function runPostgresHealthCheck({ force = false } = {}) {
    const dbProvider = normalizeDbProvider(process.env.DB_PROVIDER) || 'mongo';
    if (!force && !isPostgresProvider(dbProvider)) {
        return {
            ok: true,
            skipped: true,
            reason: `DB_PROVIDER=${dbProvider} does not enable postgres`
        };
    }

    const validation = validateDatabaseUrl(process.env.DATABASE_URL);
    if (!validation.ok) {
        const error = new Error(validation.errors.join(' '));
        error.name = 'PostgresConfigError';
        throw error;
    }

    const pool = getPostgresPool();
    const start = Date.now();
    const client = await pool.connect();
    try {
        await client.query('SELECT 1');
    } finally {
        client.release();
    }

    return {
        ok: true,
        skipped: false,
        provider: dbProvider,
        latencyMs: Date.now() - start,
        target: getPostgresTargetSummary(process.env.DATABASE_URL)
    };
}

module.exports = {
    redactPostgresUrlInText,
    getPostgresConfig,
    getPostgresTargetSummary,
    getPostgresPool,
    closePostgresPool,
    runPostgresHealthCheck
};
