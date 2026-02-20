#!/usr/bin/env node

function parseTimeToMinutes(value) {
    const [hours, minutes] = String(value || '').split(':').map(Number);
    if (!Number.isInteger(hours) || !Number.isInteger(minutes)) return NaN;
    return (hours * 60) + minutes;
}

function minutesToTime(value) {
    const hours = Math.floor(value / 60);
    const minutes = value % 60;
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
}

function generateDoctorSlots(doctor) {
    const settings = doctor?.bookingSettings || {};
    const start = parseTimeToMinutes(settings.workdayStart || '09:00');
    const end = parseTimeToMinutes(settings.workdayEnd || '14:00');
    const duration = Number(settings.consultationDurationMinutes || 20);

    if (!Number.isFinite(start) || !Number.isFinite(end) || !Number.isInteger(duration) || duration <= 0 || end <= start) {
        return [];
    }

    const slots = [];
    for (let minute = start; minute + duration <= end; minute += duration) {
        slots.push(minutesToTime(minute));
    }
    return slots;
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

    const today = new Date();
    const date = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
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

function readCsrfCookie(response) {
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

async function run() {
    const baseUrl = (process.env.BASE_URL || 'http://localhost:3000').replace(/\/$/, '');

    const doctorsRes = await fetch(`${baseUrl}/api/public/doctors`);
    const doctorsPayload = await doctorsRes.json().catch(() => ({}));
    if (!doctorsRes.ok || !Array.isArray(doctorsPayload.doctors) || doctorsPayload.doctors.length === 0) {
        throw new Error('No active doctors available for race test.');
    }

    const doctor = doctorsPayload.doctors[0];
    const date = pickBookableDate(doctor);
    if (!date) {
        throw new Error(`Could not find a bookable date for doctor ${doctor.slug}.`);
    }
    const csrfToken = readCsrfCookie(doctorsRes);
    if (!csrfToken) {
        throw new Error('Could not obtain CSRF cookie token for race test.');
    }

    const slots = generateDoctorSlots(doctor);
    if (slots.length === 0) {
        throw new Error(`Doctor ${doctor.slug} has no generated slots.`);
    }

    const time = slots[Math.floor(Math.random() * slots.length)];

    const payload = {
        name: 'Race Test Patient',
        phone: '0712345678',
        email: `race-${Date.now()}@example.com`,
        type: 'Control',
        date,
        time,
        doctorId: doctor._id,
        doctorSlug: doctor.slug
    };

    const request = () => fetch(`${baseUrl}/api/book`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
            'Cookie': `__Host-csrf=${csrfToken}`
        },
        body: JSON.stringify(payload)
    });

    const [r1, r2] = await Promise.all([request(), request()]);
    const statuses = [r1.status, r2.status].sort((a, b) => a - b);

    console.log(`Race test doctor ${doctor.slug}, slot ${date} ${time}`);
    console.log(`Statuses: ${statuses.join(', ')}`);

    if (statuses[0] === 200 && statuses[1] === 409) {
        console.log('PASS: exactly one booking succeeded for the same doctor/time slot.');
        return;
    }

    const b1 = await r1.text();
    const b2 = await r2.text();
    console.error('FAIL: unexpected race result.');
    console.error(`Response1: ${r1.status} ${b1}`);
    console.error(`Response2: ${r2.status} ${b2}`);
    process.exit(1);
}

run().catch((error) => {
    console.error('Race test failed:', error.message);
    process.exit(1);
});
