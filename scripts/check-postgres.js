#!/usr/bin/env node
require('dotenv').config();

const {
    runPostgresHealthCheck,
    closePostgresPool,
    redactPostgresUrlInText
} = require('../db/postgres');

async function run() {
    const result = await runPostgresHealthCheck({ force: true });
    if (result.ok) {
        console.log(
            `[POSTGRES] Health check OK `
            + `(target=${result.target}, latencyMs=${result.latencyMs}).`
        );
        return;
    }
    throw new Error('Unexpected Postgres health check result.');
}

run()
    .catch(async (error) => {
        console.error(`[POSTGRES] Health check FAILED: ${redactPostgresUrlInText(error?.message || String(error))}`);
        try {
            await closePostgresPool();
        } catch (_) {
            // no-op
        }
        process.exit(1);
    })
    .finally(async () => {
        try {
            await closePostgresPool();
        } catch (_) {
            // no-op
        }
    });
