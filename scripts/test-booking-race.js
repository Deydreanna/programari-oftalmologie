#!/usr/bin/env node

const SLOT_TIMES = ['09:00', '09:20', '09:40', '10:00', '10:20', '10:40', '11:00', '11:20', '11:40', '12:00', '12:20', '12:40', '13:00', '13:20', '13:40'];

function pickFutureWednesday() {
    const now = new Date();
    const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));

    while (date.getUTCDay() !== 3) {
        date.setUTCDate(date.getUTCDate() + 1);
    }

    const offsetWeeks = 8 + Math.floor(Math.random() * 24);
    date.setUTCDate(date.getUTCDate() + offsetWeeks * 7);

    const y = date.getUTCFullYear();
    const m = String(date.getUTCMonth() + 1).padStart(2, '0');
    const d = String(date.getUTCDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
}

async function run() {
    const baseUrl = (process.env.BASE_URL || 'http://localhost:3000').replace(/\/$/, '');
    const date = pickFutureWednesday();
    const time = SLOT_TIMES[Math.floor(Math.random() * SLOT_TIMES.length)];

    const payload = {
        name: 'Race Test Patient',
        phone: '0712345678',
        email: `race-${Date.now()}@example.com`,
        type: 'Control',
        date,
        time,
        cnp: '0000000000000'
    };

    const request = () => fetch(`${baseUrl}/api/book`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    const [r1, r2] = await Promise.all([request(), request()]);
    const statuses = [r1.status, r2.status].sort((a, b) => a - b);

    console.log(`Race test slot ${date} ${time}`);
    console.log(`Statuses: ${statuses.join(', ')}`);

    if (statuses[0] === 200 && statuses[1] === 409) {
        console.log('PASS: exactly one booking succeeded.');
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
