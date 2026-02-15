require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-dev-secret';
const SALT_ROUNDS = 12;

// Connect to MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/appointments';

mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// =====================
//  SCHEMAS
// =====================

// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
    phone: { type: String, unique: true, sparse: true, trim: true },
    password: String,
    googleId: String,
    displayName: String,
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Appointment Schema
const appointmentSchema = new mongoose.Schema({
    name: String,
    phone: String,
    cnp: String,
    type: String,
    date: String,
    time: String,
    hasDiagnosis: { type: Boolean, default: false },
    diagnosticFile: String,
    fileType: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    createdAt: { type: Date, default: Date.now }
});

const Appointment = mongoose.model('Appointment', appointmentSchema);

// =====================
//  MIDDLEWARE
// =====================

app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static('public'));

// =====================
//  VALIDATION HELPERS
// =====================

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^(\+?40|0)7\d{8}$/;

function validateEmail(email) {
    return EMAIL_REGEX.test(email);
}

function validatePhone(phone) {
    // Strip spaces and dashes for validation
    const cleaned = phone.replace(/[\s\-]/g, '');
    return PHONE_REGEX.test(cleaned);
}

function cleanPhone(phone) {
    return phone.replace(/[\s\-]/g, '');
}

function isEmail(identifier) {
    return identifier.includes('@');
}

function generateToken(user) {
    return jwt.sign(
        { id: user._id, email: user.email, displayName: user.displayName },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
}

// Optional auth middleware — attaches user if token present, but doesn't block
function optionalAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
        } catch (err) {
            // Token invalid/expired — continue without user
        }
    }
    next();
}

// =====================
//  AUTH API
// =====================

// POST /api/auth/signup — Register with email + phone + password
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, phone, password, displayName } = req.body;

        // Validate required fields
        if (!email || !phone || !password) {
            return res.status(400).json({ error: 'Email, telefon și parola sunt obligatorii.' });
        }

        if (!displayName || displayName.trim().length < 2) {
            return res.status(400).json({ error: 'Numele trebuie să aibă cel puțin 2 caractere.' });
        }

        // Validate email format
        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Format email invalid.' });
        }

        // Validate phone format
        if (!validatePhone(phone)) {
            return res.status(400).json({ error: 'Format telefon invalid. Folosiți formatul 07xx xxx xxx.' });
        }

        // Validate password strength
        if (password.length < 6) {
            return res.status(400).json({ error: 'Parola trebuie să aibă minim 6 caractere.' });
        }

        const cleanedPhone = cleanPhone(phone);

        // Check if email already exists
        const existingEmail = await User.findOne({ email: email.toLowerCase() });
        if (existingEmail) {
            return res.status(409).json({ error: 'Acest email este deja înregistrat.' });
        }

        // Check if phone already exists
        const existingPhone = await User.findOne({ phone: cleanedPhone });
        if (existingPhone) {
            return res.status(409).json({ error: 'Acest număr de telefon este deja înregistrat.' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // Create user
        const user = new User({
            email: email.toLowerCase(),
            phone: cleanedPhone,
            password: hashedPassword,
            displayName: displayName.trim()
        });

        await user.save();

        // Generate JWT
        const token = generateToken(user);

        res.status(201).json({
            success: true,
            message: 'Cont creat cu succes!',
            token,
            user: {
                id: user._id,
                email: user.email,
                phone: user.phone,
                displayName: user.displayName
            }
        });

    } catch (err) {
        console.error('Signup error:', err);
        if (err.code === 11000) {
            return res.status(409).json({ error: 'Email sau telefon deja înregistrat.' });
        }
        res.status(500).json({ error: 'Eroare la înregistrare.' });
    }
});

// POST /api/auth/login — Login with email OR phone + password
app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;

        if (!identifier || !password) {
            return res.status(400).json({ error: 'Introduceți email/telefon și parola.' });
        }

        // Determine if identifier is email or phone
        let user;
        if (isEmail(identifier)) {
            user = await User.findOne({ email: identifier.toLowerCase().trim() });
        } else {
            const cleanedPhone = cleanPhone(identifier);
            user = await User.findOne({ phone: cleanedPhone });
        }

        if (!user) {
            return res.status(401).json({ error: 'Email/telefon sau parolă incorectă.' });
        }

        if (!user.password) {
            return res.status(401).json({ error: 'Acest cont folosește autentificare Google. Folosiți butonul Google.' });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Email/telefon sau parolă incorectă.' });
        }

        // Generate JWT
        const token = generateToken(user);

        res.json({
            success: true,
            message: 'Autentificare reușită!',
            token,
            user: {
                id: user._id,
                email: user.email,
                phone: user.phone,
                displayName: user.displayName
            }
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Eroare la autentificare.' });
    }
});

// GET /api/auth/me — Get current user profile
app.get('/api/auth/me', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token lipsă.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'Utilizator negăsit.' });
        }

        res.json({
            id: user._id,
            email: user.email,
            phone: user.phone,
            displayName: user.displayName,
            createdAt: user.createdAt
        });

    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Sesiune expirată. Autentificați-vă din nou.' });
        }
        return res.status(401).json({ error: 'Token invalid.' });
    }
});


// =====================
//  SLOTS API
// =====================

const generateSlots = () => {
    const slots = [];
    let start = 9 * 60;
    const end = 14 * 60;

    while (start < end) {
        const hours = Math.floor(start / 60);
        const mins = start % 60;
        const timeStr = `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}`;
        slots.push(timeStr);
        start += 20;
    }
    return slots;
};

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

// Book appointment (auth optional)
app.post('/api/book', optionalAuth, async (req, res) => {
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
            fileType,
            userId: req.user ? req.user.id : null
        });
        await newAppointment.save();

        res.json({ success: true, message: 'Programare confirmată!' });
    } catch (err) {
        console.error('Booking error:', err);
        res.status(500).json({ error: 'Eroare la salvare.' });
    }
});


// =====================
//  ADMIN API
// =====================

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

app.get('/api/admin/export', async (req, res) => {
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
    console.log(`Server running on http://localhost:${PORT} (MongoDB + Auth Enabled)`);
});
