#!/usr/bin/env node

const crypto = require('crypto');

const BASE_URL = String(process.env.BASE_URL || 'http://localhost:3000').replace(/\/$/, '');
const SUPERADMIN_IDENTIFIER = String(process.env.SUPERADMIN_IDENTIFIER || '').trim();
const SUPERADMIN_PASSWORD = String(process.env.SUPERADMIN_PASSWORD || '').trim();

function requireEnv(value, key) {
    if (!value) throw new Error(`Missing required env: ${key}`);
}

function randomSuffix() {
    return crypto.randomBytes(4).toString('hex');
}

function parseSetCookie(rawValue) {
    if (!rawValue) return null;
    const parts = String(rawValue).split(';')[0].split('=');
    if (parts.length < 2) return null;
    const key = parts.shift().trim();
    const value = parts.join('=').trim();
    if (!key) return null;
    return { key, value };
}

class Session {
    constructor(name) {
        this.name = name;
        this.cookies = new Map();
    }

    _cookieHeader() {
        return Array.from(this.cookies.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
    }

    _captureSetCookies(response) {
        const setCookieHeaders = typeof response.headers.getSetCookie === 'function'
            ? response.headers.getSetCookie()
            : (response.headers.get('set-cookie') ? [response.headers.get('set-cookie')] : []);
        for (const raw of setCookieHeaders) {
            const parsed = parseSetCookie(raw);
            if (!parsed) continue;
            this.cookies.set(parsed.key, parsed.value);
        }
    }

    csrfToken() {
        return this.cookies.get('__Host-csrf') || '';
    }

    async request(path, { method = 'GET', body, includeCsrf = true, headers: extraHeaders = {} } = {}) {
        const headers = {
            'Content-Type': 'application/json'
        };
        Object.assign(headers, extraHeaders || {});
        const cookieHeader = this._cookieHeader();
        if (cookieHeader) {
            headers.Cookie = cookieHeader;
        }
        if (includeCsrf && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) {
            const token = this.csrfToken();
            if (token) {
                headers['X-CSRF-Token'] = token;
            }
        }

        const response = await fetch(`${BASE_URL}${path}`, {
            method,
            headers,
            body: body === undefined ? undefined : JSON.stringify(body)
        });
        this._captureSetCookies(response);
        const text = await response.text();
        let parsed = null;
        try {
            parsed = text ? JSON.parse(text) : null;
        } catch (_) {
            parsed = text;
        }
        return { response, body: parsed, raw: text };
    }

    async login(identifier, password) {
        const { response, body } = await this.request('/api/auth/login', {
            method: 'POST',
            includeCsrf: false,
            body: { identifier, password }
        });
        if (!response.ok) {
            throw new Error(`${this.name} login failed: ${response.status} ${JSON.stringify(body)}`);
        }
    }

    async stepUp(action, password) {
        const { response, body } = await this.request('/api/auth/step-up', {
            method: 'POST',
            body: { action, password }
        });
        if (!response.ok || !body?.stepUpToken) {
            throw new Error(`Step-up failed (${action}): ${response.status} ${JSON.stringify(body)}`);
        }
        return body.stepUpToken;
    }
}

function assertCondition(condition, message) {
    if (!condition) throw new Error(message);
}

async function run() {
    requireEnv(SUPERADMIN_IDENTIFIER, 'SUPERADMIN_IDENTIFIER');
    requireEnv(SUPERADMIN_PASSWORD, 'SUPERADMIN_PASSWORD');

    const superadmin = new Session('superadmin');
    await superadmin.login(SUPERADMIN_IDENTIFIER, SUPERADMIN_PASSWORD);
    console.log('[verify-auth-rbac] Superadmin login OK');

    const schedulerEmail = `phase2a-${randomSuffix()}@example.com`;
    const schedulerPhone = `07${String(Date.now()).slice(-8)}`;
    const schedulerPassword = `Sched${randomSuffix()}A1`;
    const schedulerDisplayName = `Phase2A Scheduler ${randomSuffix()}`;

    const create = await superadmin.request('/api/admin/users', {
        method: 'POST',
        body: {
            displayName: schedulerDisplayName,
            email: schedulerEmail,
            phone: schedulerPhone,
            password: schedulerPassword,
            role: 'scheduler',
            managedDoctorIds: []
        }
    });
    assertCondition(create.response.status === 201, `Superadmin user create failed: ${create.response.status} ${JSON.stringify(create.body)}`);
    const createdUserId = create.body?.user?._id;
    assertCondition(!!createdUserId, 'Created user id missing.');
    console.log('[verify-auth-rbac] Superadmin user create OK');

    const scheduler = new Session('scheduler');
    await scheduler.login(schedulerEmail, schedulerPassword);
    console.log('[verify-auth-rbac] Scheduler login OK');

    const forbiddenUserList = await scheduler.request('/api/admin/users');
    assertCondition(forbiddenUserList.response.status === 403, `Scheduler must not list users: ${forbiddenUserList.response.status}`);

    const forbiddenDoctorCreate = await scheduler.request('/api/admin/doctors', {
        method: 'POST',
        body: {
            slug: `forbidden-${randomSuffix()}`,
            displayName: `Forbidden ${randomSuffix()}`,
            specialty: 'Oftalmologie',
            isActive: true,
            bookingSettings: {
                consultationDurationMinutes: 20,
                workdayStart: '09:00',
                workdayEnd: '12:00',
                monthsToShow: 2,
                timezone: 'Europe/Bucharest'
            },
            availabilityRules: { weekdays: [3] },
            blockedDates: []
        }
    });
    assertCondition(forbiddenDoctorCreate.response.status === 403, `Scheduler must not create doctors: ${forbiddenDoctorCreate.response.status}`);
    console.log('[verify-auth-rbac] RBAC denies verified');

    const deleteToken = await superadmin.stepUp('user_delete', SUPERADMIN_PASSWORD);
    const deleted = await superadmin.request(`/api/admin/users/${createdUserId}`, {
        method: 'DELETE',
        body: {},
        includeCsrf: true,
        headers: { 'X-Step-Up-Token': deleteToken }
    });
    if (!deleted.response.ok) {
        throw new Error(`Cleanup failed: ${deleted.response.status} ${JSON.stringify(deleted.body)}`);
    }
    console.log('[verify-auth-rbac] Cleanup user deletion OK');
}

run().then(() => {
    console.log('verify-auth-rbac passed.');
}).catch((error) => {
    console.error(`verify-auth-rbac failed: ${error.message}`);
    process.exit(1);
});
