#!/usr/bin/env node

const crypto = require('crypto');

const BASE_URL = String(process.env.BASE_URL || 'http://localhost:3000').replace(/\/$/, '');
const SUPERADMIN_IDENTIFIER = String(process.env.SUPERADMIN_IDENTIFIER || '').trim();
const SUPERADMIN_PASSWORD = String(process.env.SUPERADMIN_PASSWORD || '').trim();

function requireEnv(value, name) {
    if (!value) {
        throw new Error(`Missing required env: ${name}`);
    }
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

    async request(path, { method = 'GET', body, json = true, includeCsrf = true, headers = {} } = {}) {
        const reqHeaders = { ...headers };
        if (json) {
            reqHeaders['Content-Type'] = reqHeaders['Content-Type'] || 'application/json';
        }

        const cookieHeader = this._cookieHeader();
        if (cookieHeader) {
            reqHeaders.Cookie = cookieHeader;
        }

        const upperMethod = method.toUpperCase();
        if (includeCsrf && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(upperMethod)) {
            const token = this.csrfToken();
            if (token) {
                reqHeaders['X-CSRF-Token'] = token;
            }
        }

        const response = await fetch(`${BASE_URL}${path}`, {
            method: upperMethod,
            headers: reqHeaders,
            body: body === undefined ? undefined : (json ? JSON.stringify(body) : body)
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
            throw new Error(`Login failed for ${this.name}: ${response.status} ${JSON.stringify(body)}`);
        }
        return body;
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
    if (!condition) {
        throw new Error(message);
    }
}

function minutesToHHmm(value) {
    const h = Math.floor(value / 60);
    const m = value % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`;
}

function parseHHmm(value) {
    const [h, m] = String(value || '').split(':').map(Number);
    if (!Number.isInteger(h) || !Number.isInteger(m)) return NaN;
    return (h * 60) + m;
}

function buildSlots(doctor) {
    const settings = doctor.bookingSettings || {};
    const start = parseHHmm(settings.workdayStart);
    const end = parseHHmm(settings.workdayEnd);
    const duration = Number(settings.consultationDurationMinutes || 20);
    if (!Number.isFinite(start) || !Number.isFinite(end) || !Number.isInteger(duration) || duration <= 0 || end <= start) {
        return [];
    }
    const out = [];
    for (let t = start; t + duration <= end; t += duration) {
        out.push(minutesToHHmm(t));
    }
    return out;
}

function toISO(date) {
    const y = date.getUTCFullYear();
    const m = String(date.getUTCMonth() + 1).padStart(2, '0');
    const d = String(date.getUTCDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
}

function pickDateForDoctor(doctor) {
    const weekdays = Array.isArray(doctor?.availabilityRules?.weekdays) ? doctor.availabilityRules.weekdays : [3];
    const blocked = new Set(Array.isArray(doctor?.blockedDates) ? doctor.blockedDates : []);
    const monthsToShow = Number(doctor?.bookingSettings?.monthsToShow || 1);

    const now = new Date();
    const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    const end = new Date(date);
    end.setUTCMonth(end.getUTCMonth() + monthsToShow);

    while (date <= end) {
        const dateStr = toISO(date);
        if (weekdays.includes(date.getUTCDay()) && !blocked.has(dateStr)) {
            return dateStr;
        }
        date.setUTCDate(date.getUTCDate() + 1);
    }
    return null;
}

async function run() {
    requireEnv(SUPERADMIN_IDENTIFIER, 'SUPERADMIN_IDENTIFIER');
    requireEnv(SUPERADMIN_PASSWORD, 'SUPERADMIN_PASSWORD');

    console.log(`[verify-multidoctor] Base URL: ${BASE_URL}`);

    const superadmin = new Session('superadmin');
    await superadmin.login(SUPERADMIN_IDENTIFIER, SUPERADMIN_PASSWORD);
    console.log('[verify-multidoctor] Superadmin login OK');

    // CSRF guard still active.
    {
        const rawRes = await fetch(`${BASE_URL}/api/admin/doctors`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Cookie: superadmin._cookieHeader()
            },
            body: JSON.stringify({ slug: `csrf-check-${randomSuffix()}`, displayName: 'CSRF Check' })
        });
        assertCondition(rawRes.status === 403, `Expected 403 for missing CSRF, got ${rawRes.status}`);
        console.log('[verify-multidoctor] CSRF protection check OK');
    }

    const doctorA = await (async () => {
        const suffix = randomSuffix();
        const payload = {
            slug: `doctor-a-${suffix}`,
            displayName: `Doctor A ${suffix}`,
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
        };
        const { response, body } = await superadmin.request('/api/admin/doctors', {
            method: 'POST',
            body: payload
        });
        assertCondition(response.status === 201, `Superadmin create doctor A failed: ${response.status} ${JSON.stringify(body)}`);
        return body.doctor;
    })();

    const doctorB = await (async () => {
        const suffix = randomSuffix();
        const payload = {
            slug: `doctor-b-${suffix}`,
            displayName: `Doctor B ${suffix}`,
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
        };
        const { response, body } = await superadmin.request('/api/admin/doctors', {
            method: 'POST',
            body: payload
        });
        assertCondition(response.status === 201, `Superadmin create doctor B failed: ${response.status} ${JSON.stringify(body)}`);
        return body.doctor;
    })();

    console.log('[verify-multidoctor] Superadmin doctor creation OK');

    const schedulerPassword = `Sched${randomSuffix()}A1`;
    const schedulerEmail = `scheduler-${randomSuffix()}@example.com`;
    const schedulerPhone = `07${String(Date.now()).slice(-8)}`;
    const schedulerDisplayName = `Scheduler ${randomSuffix()}`;

    const createScheduler = await superadmin.request('/api/admin/users', {
        method: 'POST',
        body: {
            displayName: schedulerDisplayName,
            email: schedulerEmail,
            phone: schedulerPhone,
            password: schedulerPassword,
            role: 'scheduler',
            managedDoctorIds: [doctorA._id]
        }
    });
    assertCondition(createScheduler.response.status === 201, `Scheduler creation failed: ${createScheduler.response.status} ${JSON.stringify(createScheduler.body)}`);
    const schedulerUser = createScheduler.body.user;
    console.log('[verify-multidoctor] Scheduler scoped creation OK');

    const date = pickDateForDoctor(doctorA);
    assertCondition(!!date, 'Could not pick an available date for doctor A');

    const slotsA = buildSlots(doctorA);
    const slotsB = buildSlots(doctorB);
    assertCondition(slotsA.length > 0, 'Doctor A slots generation failed');
    assertCondition(slotsB.length > 0, 'Doctor B slots generation failed');
    const slot = slotsA[0];

    // Public slots must require doctor.
    {
        const res = await fetch(`${BASE_URL}/api/slots?date=${date}`);
        assertCondition(res.status === 400, `Expected /api/slots without doctor to fail 400, got ${res.status}`);
    }
    console.log('[verify-multidoctor] Public slots doctor requirement OK');

    // Book same slot twice for doctor A -> one must fail.
    const patientPayloadBase = {
        name: `Test Patient ${randomSuffix()}`,
        phone: '0712345678',
        type: 'Control',
        date,
        time: slot
    };

    const firstA = await fetch(`${BASE_URL}/api/book`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            ...patientPayloadBase,
            email: `a1-${randomSuffix()}@example.com`,
            doctorId: doctorA._id,
            doctorSlug: doctorA.slug
        })
    });
    const secondA = await fetch(`${BASE_URL}/api/book`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            ...patientPayloadBase,
            email: `a2-${randomSuffix()}@example.com`,
            doctorId: doctorA._id,
            doctorSlug: doctorA.slug
        })
    });

    const statusesA = [firstA.status, secondA.status].sort((a, b) => a - b);
    assertCondition(statusesA[0] === 200 && statusesA[1] === 409, `Expected duplicate slot block for same doctor. Got ${statusesA.join(', ')}`);
    console.log('[verify-multidoctor] Duplicate slot blocked per doctor OK');

    // Same slot, different doctor -> allowed.
    const sameSlotOtherDoctor = await fetch(`${BASE_URL}/api/book`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            ...patientPayloadBase,
            email: `b1-${randomSuffix()}@example.com`,
            doctorId: doctorB._id,
            doctorSlug: doctorB.slug
        })
    });
    assertCondition(sameSlotOtherDoctor.status === 200, `Expected same slot on different doctor to succeed, got ${sameSlotOtherDoctor.status}`);
    console.log('[verify-multidoctor] Same slot allowed across different doctors OK');

    // Block date for doctor A and ensure doctor B not blocked.
    const blockDateRes = await superadmin.request(`/api/admin/doctors/${doctorA._id}/block-date`, {
        method: 'POST',
        body: { date }
    });
    assertCondition(blockDateRes.response.ok, `Failed blocking doctor date: ${blockDateRes.response.status} ${JSON.stringify(blockDateRes.body)}`);

    const slotsAfterBlockA = await fetch(`${BASE_URL}/api/slots?doctor=${encodeURIComponent(doctorA.slug)}&date=${date}`);
    const payloadAfterBlockA = await slotsAfterBlockA.json();
    assertCondition(Array.isArray(payloadAfterBlockA.slots), 'Unexpected slots payload for doctor A after block');
    assertCondition(payloadAfterBlockA.slots.every((s) => s.available === false), 'Blocked date should disable all slots for doctor A');

    const slotsAfterBlockB = await fetch(`${BASE_URL}/api/slots?doctor=${encodeURIComponent(doctorB.slug)}&date=${date}`);
    const payloadAfterBlockB = await slotsAfterBlockB.json();
    assertCondition(Array.isArray(payloadAfterBlockB.slots), 'Unexpected slots payload for doctor B after doctor A block');
    assertCondition(payloadAfterBlockB.slots.some((s) => s.available === true), 'Blocking doctor A should not block doctor B');
    console.log('[verify-multidoctor] Blocked date scoped per doctor OK');

    // Reactivate date.
    const unblockDateRes = await superadmin.request(`/api/admin/doctors/${doctorA._id}/block-date/${date}`, {
        method: 'DELETE'
    });
    assertCondition(unblockDateRes.response.ok, `Failed reactivating doctor date: ${unblockDateRes.response.status} ${JSON.stringify(unblockDateRes.body)}`);

    const slotsAfterUnblockA = await fetch(`${BASE_URL}/api/slots?doctor=${encodeURIComponent(doctorA.slug)}&date=${date}`);
    const payloadAfterUnblockA = await slotsAfterUnblockA.json();
    assertCondition(payloadAfterUnblockA.slots.some((s) => s.available === true), 'Reactivated date should restore availability for doctor A');
    console.log('[verify-multidoctor] Date reactivation restores availability OK');

    // Scheduler login + scope enforcement.
    const scheduler = new Session('scheduler');
    await scheduler.login(schedulerEmail, schedulerPassword);

    const schedulerDoctorCreate = await scheduler.request('/api/admin/doctors', {
        method: 'POST',
        body: {
            slug: `forbidden-${randomSuffix()}`,
            displayName: 'Forbidden Doctor',
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
    assertCondition(schedulerDoctorCreate.response.status === 403, `Scheduler should not create doctor. Got ${schedulerDoctorCreate.response.status}`);

    const schedulerAppointments = await scheduler.request('/api/admin/appointments');
    assertCondition(schedulerAppointments.response.ok, 'Scheduler appointments list failed unexpectedly');
    const schedulerList = Array.isArray(schedulerAppointments.body) ? schedulerAppointments.body : [];
    assertCondition(schedulerList.every((appt) => String(appt.doctorId) === String(doctorA._id)), 'Scheduler received appointments outside assigned doctor scope');
    console.log('[verify-multidoctor] Scheduler scope listing enforcement OK');

    // Superadmin updates scheduler scope to include doctor B.
    const userUpdateToken = await superadmin.stepUp('user_update', SUPERADMIN_PASSWORD);
    const scopeUpdate = await superadmin.request(`/api/admin/users/${schedulerUser._id}`, {
        method: 'PATCH',
        headers: { 'X-Step-Up-Token': userUpdateToken },
        body: {
            managedDoctorIds: [doctorA._id, doctorB._id]
        }
    });
    assertCondition(scopeUpdate.response.ok, `Superadmin user scope update failed: ${scopeUpdate.response.status} ${JSON.stringify(scopeUpdate.body)}`);

    // Non-superadmin cannot assign doctor scope.
    const schedulerUpdateAttempt = await scheduler.request(`/api/admin/users/${schedulerUser._id}`, {
        method: 'PATCH',
        body: { managedDoctorIds: [doctorB._id] }
    });
    assertCondition(schedulerUpdateAttempt.response.status === 403, `Scheduler should not update user scopes. Got ${schedulerUpdateAttempt.response.status}`);
    console.log('[verify-multidoctor] User scope assignment RBAC enforcement OK');

    // Scheduler cannot export.
    const schedulerExport = await scheduler.request('/api/admin/export');
    assertCondition(schedulerExport.response.status === 403, `Scheduler should not export. Got ${schedulerExport.response.status}`);
    console.log('[verify-multidoctor] RBAC export restriction OK');

    // Superadmin delete scheduler user.
    const userDeleteToken = await superadmin.stepUp('user_delete', SUPERADMIN_PASSWORD);
    const deleteScheduler = await superadmin.request(`/api/admin/users/${schedulerUser._id}`, {
        method: 'DELETE',
        headers: { 'X-Step-Up-Token': userDeleteToken }
    });
    assertCondition(deleteScheduler.response.ok, `Superadmin delete user failed: ${deleteScheduler.response.status} ${JSON.stringify(deleteScheduler.body)}`);
    console.log('[verify-multidoctor] Superadmin user deletion OK');

    console.log('All multi-doctor verification checks passed.');
}

run().catch((error) => {
    console.error(`verify-multidoctor failed: ${error.message}`);
    process.exit(1);
});
