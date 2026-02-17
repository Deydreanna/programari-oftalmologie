#!/usr/bin/env node
require('dotenv').config();

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { validateBaseEnv } = require('./env-utils');

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

    await mongoose.connect(mongodbUri);

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

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

    console.log(`Superadmin ready: ${user.email}`);

    await mongoose.disconnect();
}

run().catch(async (error) => {
    console.error('Failed to seed superadmin:', error.message);
    try {
        await mongoose.disconnect();
    } catch (_) {
        // no-op
    }
    process.exit(1);
});
