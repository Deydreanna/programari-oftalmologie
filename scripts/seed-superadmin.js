#!/usr/bin/env node
require('dotenv').config();

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { validateBaseEnv, normalizeDbProvider, isPostgresProvider } = require('./env-utils');
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

const userSchema = new mongoose.Schema({
    email: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
    phone: { type: String, unique: true, sparse: true, trim: true },
    password: String,
    googleId: String,
    displayName: String,
    role: { type: String, enum: ['viewer', 'scheduler', 'superadmin'], default: 'viewer' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

async function seedMongoSuperadmin({ mongodbUri, email, hashedPassword }) {
    await mongoose.connect(mongodbUri);
    const update = {
        email,
        password: hashedPassword,
        role: 'superadmin',
        displayName: 'Super Admin'
    };
    const user = await User.findOneAndUpdate(
        { email },
        { $set: update, $setOnInsert: { createdAt: new Date() } },
        { new: true, upsert: true }
    );
    return { provider: 'mongo', publicId: String(user?._id || ''), email: user.email };
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

    const mongodbUri = process.env.MONGODB_URI;
    const email = process.env.SUPERADMIN_EMAIL.toLowerCase().trim();
    const password = process.env.SUPERADMIN_PASSWORD;
    const dbProvider = normalizeDbProvider(process.env.DB_PROVIDER) || 'mongo';

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    let result;

    if (isPostgresProvider(dbProvider)) {
        result = await seedPostgresSuperadmin({ email, hashedPassword });
    } else {
        result = await seedMongoSuperadmin({ mongodbUri, email, hashedPassword });
    }

    console.log(`Superadmin ready (${result.provider}): ${result.email}`);
}

run().catch(async (error) => {
    console.error('Failed to seed superadmin:', error.message);
    try {
        await mongoose.disconnect();
    } catch (_) {
        // no-op
    }
    try {
        await closePostgresPool();
    } catch (_) {
        // no-op
    }
    process.exit(1);
}).finally(async () => {
    try {
        await mongoose.disconnect();
    } catch (_) {
        // no-op
    }
    try {
        await closePostgresPool();
    } catch (_) {
        // no-op
    }
});
