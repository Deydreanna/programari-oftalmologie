#!/usr/bin/env node
require('dotenv').config();

const bcrypt = require('bcrypt');
const { validateBaseEnv } = require('./env-utils');
const pgUsers = require('../db/users-postgres');
const { closePostgresPool } = require('../db/postgres');

const SALT_ROUNDS = 12;

function isStrongPassword(password) {
    if (typeof password !== 'string') return false;
    if (password.length < 12) return false;
    if (!/[a-z]/.test(password)) return false;
    if (!/[A-Z]/.test(password)) return false;
    if (!/[0-9]/.test(password)) return false;
    if (!/[^A-Za-z0-9]/.test(password)) return false;
    return true;
}

function validateSeedEnv(env) {
    const errors = [];

    const baseValidation = validateBaseEnv(env);
    errors.push(...baseValidation.errors);

    if (!env.SUPERADMIN_EMAIL || !String(env.SUPERADMIN_EMAIL).trim()) {
        errors.push('SUPERADMIN_EMAIL is required for seeding.');
    }

    if (!isStrongPassword(env.SUPERADMIN_PASSWORD || '')) {
        errors.push('SUPERADMIN_PASSWORD must be at least 12 chars and include uppercase, lowercase, number, and symbol.');
    }

    return errors;
}

async function seedPostgresSuperadmin({ email, hashedPassword }) {
    return pgUsers.withTransaction(async (client) => {
        const existing = await pgUsers.findUserByEmail(email, client);
        if (existing) {
            const updated = await pgUsers.updateUserByPublicId(existing._id, {
                passwordHash: hashedPassword,
                role: 'superadmin',
                displayName: 'Super Admin'
            }, client);
            return { provider: 'postgres', publicId: String(updated._id), email: updated.email };
        }

        const created = await pgUsers.createUser({
            email,
            phone: null,
            passwordHash: hashedPassword,
            displayName: 'Super Admin',
            role: 'superadmin',
            managedDoctorIds: []
        }, client);
        return { provider: 'postgres', publicId: String(created._id), email: created.email };
    });
}

async function run() {
    const errors = validateSeedEnv(process.env);
    if (errors.length) {
        console.error('Cannot seed superadmin:');
        for (const error of errors) {
            console.error(`- ${error}`);
        }
        process.exit(1);
    }

    const email = process.env.SUPERADMIN_EMAIL.toLowerCase().trim();
    const password = process.env.SUPERADMIN_PASSWORD;
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await seedPostgresSuperadmin({ email, hashedPassword });
    console.log(`Superadmin ready (${result.provider}): ${result.email}`);
}

run()
    .catch(async (error) => {
        console.error('Failed to seed superadmin:', error.message);
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
