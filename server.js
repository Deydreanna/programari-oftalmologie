require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-dev-secret';
const SALT_ROUNDS = 12;
const execFileAsync = promisify(execFile);

// The Super Admin Email
const SUPER_ADMIN_EMAIL = 'alexynho2009@gmail.com';

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
    role: { type: String, enum: ['user', 'admin', 'superadmin'], default: 'user' },
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
    email: String,
    emailSent: { type: Boolean, default: false },
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
        { id: user._id, email: user.email, displayName: user.displayName, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
}

async function executeEmailScript(base64Data) {
    const scriptPath = path.resolve(__dirname, 'scripts', 'email_service.py');
    const configuredPython = process.env.EMAIL_PYTHON_PATH || process.env.PYTHON_PATH;
    const defaultCandidates = process.platform === 'win32'
        ? ['py', 'python', 'python3']
        : ['python3', 'python'];
    const pythonCandidates = configuredPython
        ? [configuredPython, ...defaultCandidates]
        : defaultCandidates;

    let lastError = null;

    for (const pythonCmd of [...new Set(pythonCandidates)]) {
        try {
            const result = await execFileAsync(pythonCmd, [scriptPath, '--json', base64Data], {
                windowsHide: true,
                timeout: 30000,
                maxBuffer: 1024 * 1024
            });

            return { ...result, pythonCmd };
        } catch (err) {
            lastError = err;
            const stderr = err?.stderr ? String(err.stderr).trim() : '';
            const reason = stderr || err.message;
            console.error(`[EMAIL] Failed with interpreter "${pythonCmd}": ${reason}`);
        }
    }

    throw lastError || new Error('No compatible Python interpreter found.');
}

// Optional auth middleware
function optionalAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
        } catch (err) {
            // Token invalid
        }
    }
    next();
}

// Required Admin middleware
async function requireAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Autentificare necesară.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);

        const isSuperEmail = decoded.email && decoded.email.toLowerCase() === SUPER_ADMIN_EMAIL.toLowerCase();

        if (user && (user.role === 'admin' || user.role === 'superadmin' || isSuperEmail)) {
            req.user = user || decoded; // Fallback to decoded if user find fails but email matches
            next();
        } else {
            res.status(403).json({ error: 'Acces interzis. Drepturi de administrator necesare.' });
        }
    } catch (err) {
        res.status(401).json({ error: 'Sesiune invalidă sau expirată.' });
    }
}

// Required Super Admin middleware
async function requireSuperAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Autentificare necesară.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);

        const isSuperEmail = decoded.email && decoded.email.toLowerCase() === SUPER_ADMIN_EMAIL.toLowerCase();

        if ((user && user.role === 'superadmin') || isSuperEmail) {
            req.user = user || decoded;
            next();
        } else {
            res.status(403).json({ error: 'Acces interzis. Doar Super Admin are acces aici.' });
        }
    } catch (err) {
        res.status(401).json({ error: 'Sesiune invalidă sau expirată.' });
    }
}

// =====================
//  AUTH API
// =====================

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, phone, password, displayName } = req.body;

        if (!email || !phone || !password) {
            return res.status(400).json({ error: 'Email, telefon și parola sunt obligatorii.' });
        }

        if (!displayName || displayName.trim().length < 2) {
            return res.status(400).json({ error: 'Numele trebuie să aibă cel puțin 2 caractere.' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Format email invalid.' });
        }

        if (!validatePhone(phone)) {
            return res.status(400).json({ error: 'Format telefon invalid. Folosiți formatul 07xx xxx xxx.' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Parola trebuie să aibă minim 6 caractere.' });
        }

        const cleanedPhone = cleanPhone(phone);

        const existingEmail = await User.findOne({ email: email.toLowerCase() });
        if (existingEmail) {
            return res.status(409).json({ error: 'Acest email este deja înregistrat.' });
        }

        const existingPhone = await User.findOne({ phone: cleanedPhone });
        if (existingPhone) {
            return res.status(409).json({ error: 'Acest număr de telefon este deja înregistrat.' });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // Assign superadmin role if it's the target email
        const role = email.toLowerCase() === SUPER_ADMIN_EMAIL.toLowerCase() ? 'superadmin' : 'user';

        const user = new User({
            email: email.toLowerCase(),
            phone: cleanedPhone,
            password: hashedPassword,
            displayName: displayName.trim(),
            role: role
        });

        await user.save();
        const token = generateToken(user);

        res.status(201).json({
            success: true,
            message: 'Cont creat cu succes!',
            token,
            user: {
                id: user._id,
                email: user.email,
                phone: user.phone,
                displayName: user.displayName,
                role: user.role
            }
        });

    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ error: 'Eroare la înregistrare.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;

        if (!identifier || !password) {
            return res.status(400).json({ error: 'Introduceți email/telefon și parola.' });
        }

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

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Email/telefon sau parolă incorectă.' });
        }

        const token = generateToken(user);

        res.json({
            success: true,
            message: 'Autentificare reușită!',
            token,
            user: {
                id: user._id,
                email: user.email,
                phone: user.phone,
                displayName: user.displayName,
                role: user.role
            }
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Eroare la autentificare.' });
    }
});

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

        // Return a fresh token too, in case role changed
        const newToken = generateToken(user);

        res.json({
            token: newToken,
            user: {
                id: user._id,
                email: user.email,
                phone: user.phone,
                displayName: user.displayName,
                role: user.role,
                createdAt: user.createdAt
            }
        });

    } catch (err) {
        return res.status(401).json({ error: 'Sesiune invalidă.' });
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

app.post('/api/book', optionalAuth, async (req, res) => {
    const { name, phone, email, cnp, type, date, time } = req.body;
    if (!name || !phone || !email || !cnp || !type || !date || !time) {
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
            name, phone, email, cnp, type, date, time,
            hasDiagnosis: !!hasDiagnosis,
            diagnosticFile,
            fileType,
            userId: req.user ? req.user.id : null
        });
        await newAppointment.save();

        // Send Email Invitation (Async)
        const appointmentData = {
            name,
            email,
            type,
            time: `${date} ${time}`,
            location: "Piața Alexandru Lahovari nr. 1, Sector 1, București"
        };

        const base64Data = Buffer.from(JSON.stringify(appointmentData)).toString('base64');

        console.log(`[EMAIL] Dispatching invitation for ${email}...`);

        executeEmailScript(base64Data).then(async ({ stdout, stderr, pythonCmd }) => {
            if (stdout) console.log(`[EMAIL STDOUT]: ${stdout}`);
            if (stderr) console.error(`[EMAIL STDERR]: ${stderr}`);
            console.log(`[EMAIL] Sent using interpreter: ${pythonCmd}`);

            try {
                await Appointment.findByIdAndUpdate(newAppointment._id, { emailSent: true });
                console.log(`[EMAIL SUCCESS] Status updated for ${email}`);
            } catch (updateErr) {
                console.error('[EMAIL DB UPDATE ERROR]:', updateErr);
            }
        }).catch(error => {
            console.error(`[EMAIL FAILURE] Process error for ${email}:`, error?.stderr || error.message);
        });

        res.json({ success: true, message: 'Programare confirmată! Verificați e-mail-ul pentru invitație.' });
    } catch (err) {
        res.status(500).json({ error: 'Eroare la salvare.' });
    }
});


// =====================
//  ADMIN API
// =====================

// List appointments - Use JWT auth now
app.get('/api/admin/appointments', requireAdmin, async (req, res) => {
    try {
        const appointments = await Appointment.find().sort({ date: 1, time: 1 });
        res.json(appointments);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/admin/resend-email/:id', requireAdmin, async (req, res) => {
    try {
        const appointment = await Appointment.findById(req.params.id);
        if (!appointment) return res.status(404).json({ error: 'Programare negăsită.' });
        if (!appointment.email) return res.status(400).json({ error: 'Clientul nu are e-mail.' });

        const { name, email, type, date, time } = appointment;
        const appointmentData = {
            name,
            email,
            type,
            time: `${date} ${time}`,
            location: "Piața Alexandru Lahovari nr. 1, Sector 1, București"
        };

        const base64Data = Buffer.from(JSON.stringify(appointmentData)).toString('base64');
        console.log(`[MANUAL EMAIL] Executing manual invitation for ${email}...`);

        try {
            const { stdout, stderr, pythonCmd } = await executeEmailScript(base64Data);
            if (stdout) console.log(`[MANUAL EMAIL STDOUT]: ${stdout}`);
            if (stderr) console.error(`[MANUAL EMAIL STDERR]: ${stderr}`);
            console.log(`[MANUAL EMAIL] Sent using interpreter: ${pythonCmd}`);
            await Appointment.findByIdAndUpdate(appointment._id, { emailSent: true });
            res.json({ success: true, message: 'Email trimis cu succes!' });
        } catch (err) {
            console.error(`[MANUAL EMAIL CRITICAL] Execution failed:`, err?.stderr || err.message || err);
            res.status(500).json({
                error: 'Trimiterea a eșuat.',
                details: err?.stderr || err.message || 'Eroare necunoscută'
            });
        }
    } catch (err) {
        res.status(500).json({ error: 'Eroare de sistem.' });
    }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try {
        const stats = await mongoose.connection.db.command({ dbStats: 1 });
        const usedSize = stats.storageSize || stats.dataSize;
        res.json({
            usedSizeMB: (usedSize / (1024 * 1024)).toFixed(3),
            totalSizeMB: 512,
            percentUsed: ((usedSize / (512 * 1024 * 1024)) * 100).toFixed(2)
        });
    } catch (err) {
        res.status(500).json({ error: 'Could not fetch stats' });
    }
});

app.post('/api/admin/reset', requireAdmin, async (req, res) => {
    try {
        await Appointment.deleteMany({});
        res.json({ success: true, message: 'Baza de date a fost resetată.' });
    } catch (err) {
        res.status(500).json({ error: 'Eroare la resetarea bazei de date.' });
    }
});

app.get('/api/admin/export', async (req, res) => {
    try {
        const token = req.query.token;
        if (!token) return res.status(401).send('Token lipsă.');

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.role !== 'admin' && decoded.role !== 'superadmin') {
                return res.status(403).send('Acces interzis.');
            }
        } catch (err) {
            return res.status(401).send('Token invalid sau expirat.');
        }

        const appointments = await Appointment.find().sort({ date: 1, time: 1 }).lean();
        const data = appointments.map(a => ({
            Data: a.date, Ora: a.time, Nume: a.name, Email: a.email || '', Telefon: a.phone, CNP: a.cnp, Tip: a.type,
            Email_Trimis: a.emailSent ? 'DA' : 'NU',
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
        res.status(500).send('Eroare la generarea Excel.');
    }
});

// =====================
//  USER MANAGEMENT (SUPER ADMIN)
// =====================

// List all users
app.get('/api/admin/users', requireSuperAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

// Toggle Admin role
app.post('/api/admin/users/role', requireSuperAdmin, async (req, res) => {
    try {
        const { userId, role } = req.body;

        if (!userId || !role) {
            return res.status(400).json({ error: 'UserId și Rolul sunt necesare.' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'Utilizator negăsit.' });
        }

        // Prevent changing superadmin role via this endpoint
        if (user.role === 'superadmin' || user.email === SUPER_ADMIN_EMAIL) {
            return res.status(403).json({ error: 'Rolul de Super Admin nu poate fi schimbat.' });
        }

        if (!['user', 'admin'].includes(role)) {
            return res.status(400).json({ error: 'Rol invalid.' });
        }

        user.role = role;
        await user.save();

        res.json({ success: true, message: `Rolul utilizatorului ${user.displayName} a fost actualizat la ${role}.` });
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});


app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT} (MongoDB + Auth + RBAC Enabled)`);
});
