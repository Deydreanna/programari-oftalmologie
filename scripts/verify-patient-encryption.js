#!/usr/bin/env node
require('dotenv').config();

const crypto = require('crypto');

if (!process.env.PATIENT_DATA_ENC_KEY) {
    process.env.PATIENT_DATA_ENC_KEY = crypto.randomBytes(32).toString('base64');
}
if (!process.env.PATIENT_INDEX_KEY) {
    process.env.PATIENT_INDEX_KEY = crypto.randomBytes(32).toString('base64');
}

const {
    PatientCryptoError,
    BLIND_INDEX_KIND,
    normalizePhone,
    normalizeEmail,
    normalizeCnp,
    validateCnp,
    isEncryptedPayload,
    encryptTextField,
    decryptTextField,
    computeBlindIndex
} = require('../db/patient-crypto');

const BASE_URL = String(process.env.BASE_URL || '').trim().replace(/\/$/, '');
const SUPERADMIN_IDENTIFIER = String(process.env.SUPERADMIN_IDENTIFIER || '').trim();
const SUPERADMIN_PASSWORD = String(process.env.SUPERADMIN_PASSWORD || '').trim();

function assertCondition(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function generateValidCnp(seed = Date.now()) {
    const control = '279146358279';
    const numericSeed = String(seed).replace(/[^\d]/g, '');
    const body = `1${numericSeed.padStart(11, '0').slice(-11)}`;
    let sum = 0;
    for (let index = 0; index < 12; index += 1) {
        sum += Number(body[index]) * Number(control[index]);
    }
    let checksum = sum % 11;
    if (checksum === 10) checksum = 1;
    return `${body}${checksum}`;
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
            'Content-Type': 'application/json',
            ...extraHeaders
        };

        const cookieHeader = this._cookieHeader();
        if (cookieHeader) {
            headers.Cookie = cookieHeader;
        }
        if (includeCsrf && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) {
            const token = this.csrfToken();
            if (token) headers['X-CSRF-Token'] = token;
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
        return { response, body: parsed };
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
}

function toISODate(date) {
    const y = date.getUTCFullYear();
    const m = String(date.getUTCMonth() + 1).padStart(2, '0');
    const d = String(date.getUTCDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
}

function pickBookableDate(doctor) {
    const weekdays = Array.isArray(doctor?.availabilityRules?.weekdays) ? doctor.availabilityRules.weekdays : [3];
    const blocked = new Set(Array.isArray(doctor?.blockedDates) ? doctor.blockedDates : []);
    const monthsToShow = Number(doctor?.bookingSettings?.monthsToShow || 1);

    const now = new Date();
    const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    const end = new Date(date);
    end.setUTCMonth(end.getUTCMonth() + monthsToShow);

    while (date <= end) {
        const dateStr = toISODate(date);
        if (weekdays.includes(date.getUTCDay()) && !blocked.has(dateStr)) {
            return dateStr;
        }
        date.setUTCDate(date.getUTCDate() + 1);
    }
    return null;
}

function getCsrfCookie(response) {
    const setCookieHeaders = typeof response.headers.getSetCookie === 'function'
        ? response.headers.getSetCookie()
        : (response.headers.get('set-cookie') ? [response.headers.get('set-cookie')] : []);

    for (const raw of setCookieHeaders) {
        const value = String(raw || '');
        if (!value.startsWith('__Host-csrf=')) continue;
        return value.split(';')[0].split('=').slice(1).join('=');
    }
    return '';
}

async function runUnitChecks() {
    const sample = {
        firstName: 'Ion',
        lastName: 'Popescu',
        phone: '07 12-34-56-78',
        email: '  PATIENT@Example.com ',
        cnp: generateValidCnp(12345678901)
    };

    const encrypted = {
        firstName: encryptTextField(sample.firstName),
        lastName: encryptTextField(sample.lastName),
        phone: encryptTextField(normalizePhone(sample.phone)),
        email: encryptTextField(normalizeEmail(sample.email)),
        cnp: encryptTextField(normalizeCnp(sample.cnp))
    };

    assertCondition(isEncryptedPayload(encrypted.firstName), 'firstName should be encrypted payload.');
    assertCondition(decryptTextField(encrypted.firstName) === sample.firstName, 'firstName decrypt mismatch.');
    assertCondition(decryptTextField(encrypted.lastName) === sample.lastName, 'lastName decrypt mismatch.');
    assertCondition(decryptTextField(encrypted.phone) === normalizePhone(sample.phone), 'phone decrypt mismatch.');
    assertCondition(decryptTextField(encrypted.email) === normalizeEmail(sample.email), 'email decrypt mismatch.');
    assertCondition(decryptTextField(encrypted.cnp) === normalizeCnp(sample.cnp), 'cnp decrypt mismatch.');

    const tampered = JSON.parse(encrypted.email);
    tampered.tag = `${tampered.tag.slice(0, -2)}AA`;
    let tamperFailed = false;
    try {
        decryptTextField(JSON.stringify(tampered), { fieldName: 'email' });
    } catch (error) {
        tamperFailed = error instanceof PatientCryptoError;
    }
    assertCondition(tamperFailed, 'Corrupted auth tag must fail decryption.');

    const malformedPayload = JSON.stringify({
        v: 1,
        k: 'patient-text',
        alg: 'aes-256-gcm',
        iv: tampered.iv,
        tag: tampered.tag
    });
    let malformedFailed = false;
    try {
        decryptTextField(malformedPayload, { fieldName: 'email' });
    } catch (error) {
        malformedFailed = error instanceof PatientCryptoError;
    }
    assertCondition(malformedFailed, 'Malformed encrypted payload metadata must fail decryption.');

    const modulePath = require.resolve('../db/patient-crypto');
    const originalEncKey = process.env.PATIENT_DATA_ENC_KEY;
    const originalIndexKey = process.env.PATIENT_INDEX_KEY;
    const testIndexKey = crypto.randomBytes(32).toString('base64');
    const keyA = crypto.randomBytes(32).toString('base64');
    const keyB = crypto.randomBytes(32).toString('base64');

    delete require.cache[modulePath];
    process.env.PATIENT_DATA_ENC_KEY = keyA;
    process.env.PATIENT_INDEX_KEY = testIndexKey;
    const cryptoWithKeyA = require('../db/patient-crypto');
    const wrongKeyCiphertext = cryptoWithKeyA.encryptTextField('wrong-key-check');

    delete require.cache[modulePath];
    process.env.PATIENT_DATA_ENC_KEY = keyB;
    process.env.PATIENT_INDEX_KEY = testIndexKey;
    const cryptoWithKeyB = require('../db/patient-crypto');
    let wrongKeyFailed = false;
    try {
        cryptoWithKeyB.decryptTextField(wrongKeyCiphertext, { fieldName: 'phone' });
    } catch (error) {
        wrongKeyFailed = String(error?.code || '') === 'decrypt_auth_failed';
    }
    assertCondition(wrongKeyFailed, 'Wrong key must fail decryption.');

    delete require.cache[modulePath];
    process.env.PATIENT_DATA_ENC_KEY = originalEncKey;
    process.env.PATIENT_INDEX_KEY = originalIndexKey;
    require('../db/patient-crypto');

    const phoneIndexA = computeBlindIndex('07 12-34-56-78', BLIND_INDEX_KIND.PHONE);
    const phoneIndexB = computeBlindIndex('0712345678', BLIND_INDEX_KIND.PHONE);
    const phoneIndexC = computeBlindIndex('0799999999', BLIND_INDEX_KIND.PHONE);
    assertCondition(phoneIndexA === phoneIndexB, 'Phone blind index should normalize consistently.');
    assertCondition(phoneIndexA !== phoneIndexC, 'Different phone should produce different blind index.');

    const legacyPlain = 'legacy-plain-value';
    assertCondition(decryptTextField(legacyPlain) === legacyPlain, 'Legacy plaintext fallback should pass.');

    const validCnp = generateValidCnp(98765432101);
    assertCondition(validateCnp(validCnp), 'Valid CNP should pass checksum.');
    assertCondition(!validateCnp(`${validCnp.slice(0, 12)}0`), 'Invalid CNP checksum should fail.');
}

async function runIntegrationChecks() {
    if (!BASE_URL) {
        console.log('[verify-patient-encryption] integration skipped: BASE_URL not provided.');
        return;
    }

    const publicDoctorsRes = await fetch(`${BASE_URL}/api/public/doctors`);
    const publicDoctorsBody = await publicDoctorsRes.json().catch(() => ({}));
    assertCondition(publicDoctorsRes.ok, 'Public doctors endpoint failed.');
    assertCondition(Array.isArray(publicDoctorsBody.doctors), 'Public doctors payload invalid.');
    const publicRaw = JSON.stringify(publicDoctorsBody);
    assertCondition(!publicRaw.includes('patientPhone'), 'Public endpoint leaked patient phone-like field.');
    assertCondition(!publicRaw.includes('patientEmail'), 'Public endpoint leaked patient email-like field.');
    assertCondition(!publicRaw.includes('patientCnp'), 'Public endpoint leaked patient cnp-like field.');

    const doctor = publicDoctorsBody.doctors[0];
    assertCondition(!!doctor, 'No active doctor available for integration check.');

    const date = pickBookableDate(doctor);
    assertCondition(!!date, 'No bookable date found for integration check.');

    const slotsRes = await fetch(`${BASE_URL}/api/slots?doctor=${encodeURIComponent(doctor.slug)}&date=${date}`);
    const slotsBody = await slotsRes.json().catch(() => ({}));
    assertCondition(slotsRes.ok, 'Slots endpoint failed.');
    const available = (Array.isArray(slotsBody.slots) ? slotsBody.slots : []).find((slot) => slot.available);
    assertCondition(!!available?.time, 'No available slot for integration check.');

    const csrfToken = getCsrfCookie(publicDoctorsRes);
    assertCondition(!!csrfToken, 'Missing CSRF token for booking integration check.');

    const suffix = Date.now();
    const firstName = 'Verif';
    const lastName = `Pacient${suffix}`;
    const payload = {
        firstName,
        lastName,
        name: `${lastName} ${firstName}`,
        phone: '0712345678',
        email: `verify-patient-${suffix}@example.com`,
        cnp: generateValidCnp(suffix),
        type: 'Control',
        date,
        time: available.time,
        doctorId: doctor._id,
        doctorSlug: doctor.slug
    };

    const bookingRes = await fetch(`${BASE_URL}/api/book`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
            'Cookie': `__Host-csrf=${csrfToken}`
        },
        body: JSON.stringify(payload)
    });
    const bookingBody = await bookingRes.json().catch(() => ({}));
    assertCondition(bookingRes.ok, `Booking integration failed: ${bookingRes.status}`);
    const bookingRaw = JSON.stringify(bookingBody);
    assertCondition(!bookingRaw.includes(payload.email), 'Booking response leaked plaintext email.');
    assertCondition(!bookingRaw.includes(payload.phone), 'Booking response leaked plaintext phone.');
    assertCondition(!bookingRaw.includes(payload.cnp), 'Booking response leaked plaintext cnp.');

    if (!SUPERADMIN_IDENTIFIER || !SUPERADMIN_PASSWORD) {
        console.log('[verify-patient-encryption] admin decryption check skipped: SUPERADMIN_IDENTIFIER/PASSWORD not provided.');
        return;
    }

    const session = new Session('superadmin');
    await session.login(SUPERADMIN_IDENTIFIER, SUPERADMIN_PASSWORD);
    const adminRes = await session.request(`/api/admin/appointments?date=${date}&doctorId=${doctor._id}`);
    assertCondition(adminRes.response.ok, `Admin appointments failed: ${adminRes.response.status}`);
    const appointments = Array.isArray(adminRes.body) ? adminRes.body : [];
    const matched = appointments.find((entry) => String(entry.patientEmail || '') === normalizeEmail(payload.email));
    assertCondition(!!matched, 'Booked appointment not present in admin scheduler payload.');
    assertCondition(String(matched.patientPhone || '') === normalizePhone(payload.phone), 'Admin payload phone mismatch.');
    assertCondition(String(matched.patientCnp || '') === normalizeCnp(payload.cnp), 'Admin payload CNP mismatch.');
}

async function run() {
    await runUnitChecks();
    await runIntegrationChecks();
    console.log('verify-patient-encryption passed.');
}

run().catch((error) => {
    console.error(`verify-patient-encryption failed: ${error.message}`);
    process.exit(1);
});
