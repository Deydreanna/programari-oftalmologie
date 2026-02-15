require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const xlsx = require('xlsx');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
// NOTE: This is a placeholder. User must set MONGODB_URI env var in Vercel.
// For local testing: 'mongodb://localhost:27017/appointments' or use the Atlas URI directly.
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/appointments';

mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// Appointment Schema
const appointmentSchema = new mongoose.Schema({
    name: String,
    phone: String,
    cnp: String,
    type: String,
    date: String, // String for simplicity (YYYY-MM-DD)
    time: String,
    hasDiagnosis: { type: Boolean, default: false },
    diagnosticFile: String, // Base64 data
    fileType: String,
    createdAt: { type: Date, default: Date.now }
});

const Appointment = mongoose.model('Appointment', appointmentSchema);

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static('public'));

// Generate slots: 09:00 - 14:00 (5h), 20-min intervals = 15 slots
const generateSlots = () => {
    const slots = [];
    let start = 9 * 60;  // 09:00
    const end = 14 * 60; // 14:00 (last slot starts at 13:40)

    while (start < end) {
        const hours = Math.floor(start / 60);
        const mins = start % 60;
        const timeStr = `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}`;
        slots.push(timeStr);
        start += 20; // 20-minute intervals
    }
    return slots;
};

// --- API Endpoints ---

// Get available slots
app.get('/api/slots', async (req, res) => {
    const { date } = req.query;
    if (!date) return res.status(400).json({ error: 'Date is required' });

    const day = new Date(date).getDay();
    if (day !== 3) return res.status(400).json({ error: 'Appointments are only available on Wednesdays.' });

    const allSlots = generateSlots();

    try {
        const existingAppointments = await Appointment.find({ date });
        const bookedTimes = existingAppointments.map(a => a.time);

        const availableSlots = allSlots.map(time => ({
            time,
            available: !bookedTimes.includes(time)
        }));

        res.json(availableSlots);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

// Book appointment
app.post('/api/book', async (req, res) => {
    const { name, phone, cnp, type, date, time } = req.body;

    if (!name || !phone || !cnp || !type || !date || !time) {
        return res.status(400).json({ error: 'Toate câmpurile sunt obligatorii.' });
    }

    if (!/^\d{13}$/.test(cnp)) {
        return res.status(400).json({ error: 'CNP invalid (13 cifre).' });
    }

    try {
        const existing = await Appointment.findOne({ date, time });
        if (existing) {
            return res.status(409).json({ error: 'Interval deja rezervat.' });
        }

        const { hasDiagnosis, diagnosticFile, fileType } = req.body;

        const newAppointment = new Appointment({
            name, phone, cnp, type, date, time,
            hasDiagnosis: !!hasDiagnosis,
            diagnosticFile,
            fileType
        });
        await newAppointment.save();

        res.json({ success: true, message: 'Programare confirmată!' });
    } catch (err) {
        console.error('Booking error:', err);
        res.status(500).json({ error: 'Eroare la salvare.' });
    }
});


// --- Admin API ---

const ADMIN_PASSWORD = process.env.ADMIN_PASS || 'admin123';
const ADMIN_TOKEN = 'secret-admin-token-123';

app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        res.json({ success: true, token: ADMIN_TOKEN });
    } else {
        res.status(401).json({ error: 'Parolă incorectă' });
    }
});

app.get('/api/admin/appointments', async (req, res) => {
    const token = req.headers['x-admin-token'];
    if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'Unauthorized' });

    try {
        const appointments = await Appointment.find()
            .sort({ date: 1, time: 1 });
        res.json(appointments);
    } catch (err) {
        console.error('Fetch appointments error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/stats', async (req, res) => {
    const token = req.headers['x-admin-token'];
    if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'Unauthorized' });

    try {
        const stats = await mongoose.connection.db.command({ dbStats: 1 });
        // storageSize is what Atlas usually shows in the dashboard
        const usedSize = stats.storageSize || stats.dataSize;

        res.json({
            usedSizeMB: (usedSize / (1024 * 1024)).toFixed(3),
            totalSizeMB: 512,
            percentUsed: ((usedSize / (512 * 1024 * 1024)) * 100).toFixed(2)
        });
    } catch (err) {
        console.error('Stats error:', err);
        res.status(500).json({ error: 'Could not fetch stats' });
    }
});

app.post('/api/admin/reset', async (req, res) => {
    const token = req.headers['x-admin-token'];
    if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'Unauthorized' });

    try {
        await Appointment.deleteMany({});
        res.json({ success: true, message: 'Baza de date a fost resetată.' });
    } catch (err) {
        console.error('Reset error:', err);
        res.status(500).json({ error: 'Eroare la resetarea bazei de date.' });
    }
});

// Export Excel (Manual)
app.get('/api/admin/export', async (req, res) => {
    // Basic protection (can be improved with token query param if needed)
    // const token = req.query.token;
    // if (token !== ADMIN_TOKEN) return res.status(403).send('Unauthorized');

    try {
        const appointments = await Appointment.find().sort({ date: 1, time: 1 }).lean();

        const data = appointments.map(a => ({
            Data: a.date,
            Ora: a.time,
            Nume: a.name,
            Telefon: a.phone,
            CNP: a.cnp,
            Tip: a.type,
            Creat: a.createdAt ? a.createdAt.toISOString().split('T')[0] : ''
        }));

        const wb = xlsx.utils.book_new();
        const ws = xlsx.utils.json_to_sheet(data);
        xlsx.utils.book_append_sheet(wb, ws, "Programari");

        const buf = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });

        res.setHeader('Content-Disposition', 'attachment; filename="programari.xlsx"');
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.send(buf);

    } catch (err) {
        console.error(err);
        res.status(500).send('Eroare la generarea Excel.');
    }
});


app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT} (MongoDB Enabled)`);
});
