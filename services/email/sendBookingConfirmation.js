const crypto = require('crypto');
const { getEmailTransporter, getEmailSender } = require('./transporter');
const { buildBookingConfirmationDefaultTemplate } = require('./templates/bookingConfirmationDefault');
const {
    normalizeDoctorTemplateConfig,
    hasDoctorCustomTemplateConfig,
    buildDoctorGeneratedTemplate,
    buildDoctorCustomTemplate
} = require('./templates/bookingConfirmationByDoctor');
const { sanitizeEmailHeaderValue } = require('./templates/templateTokens');

const ISO_DATE_REGEX = /^(\d{4})-(\d{2})-(\d{2})$/;
const HHMM_REGEX = /^([01]\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?$/;
const LEGACY_OBJECT_ID_REGEX = /^[a-f0-9]{24}$/i;
const SIMPLE_EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

let cachedDoctorTemplateMapRaw = null;
let cachedDoctorTemplateMap = new Map();
let didLogDoctorTemplateMapError = false;

function toTrimmedString(value) {
    return String(value || '').replace(/\0/g, '').trim();
}

function normalizeNullableString(value, maxLength = 20000) {
    const normalized = toTrimmedString(value);
    if (!normalized) return null;
    return normalized.slice(0, maxLength);
}

function normalizeReplyTo(value) {
    const normalized = normalizeNullableString(value, 254);
    if (!normalized) return null;
    if (!SIMPLE_EMAIL_REGEX.test(normalized)) return null;
    return normalized.toLowerCase();
}

function resolvePatientName(appointment = {}) {
    const firstName = toTrimmedString(appointment.firstName);
    const lastName = toTrimmedString(appointment.lastName);
    const joined = [firstName, lastName].filter(Boolean).join(' ');
    return joined || toTrimmedString(appointment.name) || 'Pacient';
}

function resolveDoctorName(doctor = null, appointment = {}) {
    const fromDoctor = toTrimmedString(doctor?.displayName);
    if (fromDoctor) return fromDoctor;
    const fromSnapshot = toTrimmedString(appointment?.doctorSnapshotName);
    if (fromSnapshot) return fromSnapshot;
    return '';
}

function resolveDoctorSpecialty(doctor = null) {
    return toTrimmedString(doctor?.specialty) || 'Oftalmologie';
}

function hasDoctorIdentity(doctor = null, appointment = {}) {
    return Boolean(resolveDoctorName(doctor, appointment));
}

function parseAppointmentDateTime(appointment = {}) {
    let date = toTrimmedString(appointment.date);
    let time = toTrimmedString(appointment.time);

    if ((!date || !HHMM_REGEX.test(time)) && time.includes(' ')) {
        const [datePart, timePart] = time.split(/\s+/, 2);
        if (!date && datePart) {
            date = datePart;
        }
        if (timePart) {
            time = timePart;
        }
    }

    const dateMatch = date.match(ISO_DATE_REGEX);
    const timeMatch = time.match(HHMM_REGEX);
    if (!dateMatch || !timeMatch) {
        throw new Error('Invalid appointment date/time for email.');
    }

    const year = Number(dateMatch[1]);
    const month = Number(dateMatch[2]);
    const day = Number(dateMatch[3]);
    const hour = Number(timeMatch[1]);
    const minute = Number(timeMatch[2]);

    return {
        year,
        month,
        day,
        hour,
        minute,
        isoDate: `${dateMatch[1]}-${dateMatch[2]}-${dateMatch[3]}`,
        hhmm: `${timeMatch[1]}:${timeMatch[2]}`
    };
}

function formatDateRo(parts) {
    return `${String(parts.day).padStart(2, '0')}.${String(parts.month).padStart(2, '0')}.${parts.year}`;
}

function formatTimeRo(parts) {
    return `${String(parts.hour).padStart(2, '0')}:${String(parts.minute).padStart(2, '0')}`;
}

function buildDefaultDoctorSignature(doctorName, clinicName) {
    const normalizedDoctorName = toTrimmedString(doctorName);
    const normalizedClinic = toTrimmedString(clinicName) || 'clinicii';
    if (!normalizedDoctorName || normalizedDoctorName === normalizedClinic) {
        return `Echipa ${normalizedClinic}`;
    }
    if (/^dr\.?\s/i.test(normalizedDoctorName.toLowerCase())) {
        return normalizedDoctorName;
    }
    return `Dr. ${normalizedDoctorName}`;
}

function normalizeDoctorEmailSettingsFromDoctor(doctor = null) {
    const settings = doctor?.emailSettings;
    if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
        return null;
    }
    return {
        emailEnabled: settings.emailEnabled !== false,
        emailFromName: normalizeNullableString(settings.emailFromName, 120),
        emailReplyTo: normalizeReplyTo(settings.emailReplyTo),
        emailSubjectTemplate: normalizeNullableString(settings.emailSubjectTemplate, 240),
        emailHtmlTemplate: normalizeNullableString(settings.emailHtmlTemplate, 20000),
        emailTextTemplate: normalizeNullableString(settings.emailTextTemplate, 20000),
        emailSignature: normalizeNullableString(settings.emailSignature, 400),
        emailClinicNameOverride: normalizeNullableString(settings.emailClinicNameOverride, 240),
        emailLocationOverride: normalizeNullableString(settings.emailLocationOverride, 320),
        emailContactPhoneOverride: normalizeNullableString(settings.emailContactPhoneOverride, 64)
    };
}

function parseDoctorTemplateMapFromEnv(rawValue) {
    const raw = toTrimmedString(rawValue);
    if (!raw) {
        return new Map();
    }

    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (error) {
        if (!didLogDoctorTemplateMapError) {
            didLogDoctorTemplateMapError = true;
            console.error('EMAIL_DOCTOR_TEMPLATES_JSON parse failed:', error?.message || error);
        }
        return new Map();
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return new Map();
    }

    const out = new Map();
    for (const [key, value] of Object.entries(parsed)) {
        const normalizedKey = toTrimmedString(key).toLowerCase();
        if (!normalizedKey) continue;
        const normalizedConfig = normalizeDoctorTemplateConfig(value);
        if (!normalizedConfig) continue;
        out.set(normalizedKey, normalizedConfig);
    }
    return out;
}

function getDoctorTemplateMap() {
    const raw = toTrimmedString(process.env.EMAIL_DOCTOR_TEMPLATES_JSON || '');
    if (raw === cachedDoctorTemplateMapRaw) {
        return cachedDoctorTemplateMap;
    }
    cachedDoctorTemplateMapRaw = raw;
    cachedDoctorTemplateMap = parseDoctorTemplateMapFromEnv(raw);
    return cachedDoctorTemplateMap;
}

function buildDoctorTemplateLookupKeys(doctor = null, appointment = {}) {
    const keys = new Set();

    const doctorSlug = toTrimmedString(doctor?.slug).toLowerCase();
    const doctorId = toTrimmedString(doctor?._id).toLowerCase();
    const appointmentDoctorId = toTrimmedString(appointment?.doctorId).toLowerCase();

    if (doctorSlug) keys.add(doctorSlug);
    if (doctorId) keys.add(doctorId);
    if (appointmentDoctorId && LEGACY_OBJECT_ID_REGEX.test(appointmentDoctorId)) keys.add(appointmentDoctorId);

    return Array.from(keys);
}

function mapDoctorEmailSettingsToTemplateConfig(doctorEmailSettings) {
    if (!doctorEmailSettings) return null;
    return normalizeDoctorTemplateConfig({
        subject: doctorEmailSettings.emailSubjectTemplate,
        html: doctorEmailSettings.emailHtmlTemplate,
        text: doctorEmailSettings.emailTextTemplate,
        signature: doctorEmailSettings.emailSignature,
        clinicName: doctorEmailSettings.emailClinicNameOverride,
        location: doctorEmailSettings.emailLocationOverride,
        contactPhone: doctorEmailSettings.emailContactPhoneOverride,
        fromName: doctorEmailSettings.emailFromName,
        replyTo: doctorEmailSettings.emailReplyTo
    });
}

function resolveDoctorCustomTemplateConfig(doctor = null, appointment = {}, doctorEmailSettings = null) {
    if (doctorEmailSettings && doctorEmailSettings.emailEnabled === false) {
        return null;
    }

    const inlineCandidates = [
        mapDoctorEmailSettingsToTemplateConfig(doctorEmailSettings),
        normalizeDoctorTemplateConfig(doctor?.emailTemplate),
        normalizeDoctorTemplateConfig(doctor?.emailConfig),
        normalizeDoctorTemplateConfig(doctor?.emailBranding),
        normalizeDoctorTemplateConfig(doctor?.emailConfirmation)
    ];

    for (const candidate of inlineCandidates) {
        if (candidate) {
            return candidate;
        }
    }

    const templateMap = getDoctorTemplateMap();
    if (!templateMap.size) {
        return null;
    }

    const keys = buildDoctorTemplateLookupKeys(doctor, appointment);
    for (const key of keys) {
        const config = templateMap.get(key);
        if (config) {
            return config;
        }
    }

    return null;
}

function escapeIcs(value) {
    return String(value || '')
        .replace(/\\/g, '\\\\')
        .replace(/\n/g, '\\n')
        .replace(/;/g, '\\;')
        .replace(/,/g, '\\,');
}

function addMinutesUtc(parts, deltaMinutes) {
    const dt = new Date(Date.UTC(
        parts.year,
        parts.month - 1,
        parts.day,
        parts.hour,
        parts.minute + deltaMinutes,
        0
    ));
    return {
        year: dt.getUTCFullYear(),
        month: dt.getUTCMonth() + 1,
        day: dt.getUTCDate(),
        hour: dt.getUTCHours(),
        minute: dt.getUTCMinutes()
    };
}

function toIcsLocal(parts) {
    const pad2 = (value) => String(value).padStart(2, '0');
    return `${parts.year}${pad2(parts.month)}${pad2(parts.day)}T${pad2(parts.hour)}${pad2(parts.minute)}00`;
}

function toUtcStamp(date = new Date()) {
    const pad2 = (value) => String(value).padStart(2, '0');
    return `${date.getUTCFullYear()}${pad2(date.getUTCMonth() + 1)}${pad2(date.getUTCDate())}T${pad2(date.getUTCHours())}${pad2(date.getUTCMinutes())}${pad2(date.getUTCSeconds())}Z`;
}

function resolveConsultationDurationMinutes(doctor = null) {
    const duration = Number(doctor?.bookingSettings?.consultationDurationMinutes);
    if (!Number.isInteger(duration) || duration < 5 || duration > 240) {
        return 30;
    }
    return duration;
}

function buildCalendarInviteAttachment({
    dateTimeParts,
    durationMinutes,
    clinicName,
    location,
    doctorName,
    patientName,
    appointmentType
}) {
    const start = {
        year: dateTimeParts.year,
        month: dateTimeParts.month,
        day: dateTimeParts.day,
        hour: dateTimeParts.hour,
        minute: dateTimeParts.minute
    };
    const end = addMinutesUtc(start, durationMinutes);
    const summary = doctorName
        ? `Programare ${clinicName} - ${doctorName}`
        : `Programare ${clinicName}`;
    const descriptionLines = [
        `Pacient: ${patientName || 'Pacient'}`,
        doctorName ? `Medic: ${doctorName}` : null,
        `Tip: ${appointmentType || 'Consultatie'}`
    ].filter(Boolean);
    const uid = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}@antigravity`;

    const icsContent = [
        'BEGIN:VCALENDAR',
        'PRODID:-//Antigravity Appointments//RO',
        'VERSION:2.0',
        'CALSCALE:GREGORIAN',
        'METHOD:REQUEST',
        'BEGIN:VTIMEZONE',
        'TZID:Europe/Bucharest',
        'BEGIN:STANDARD',
        'TZOFFSETFROM:+0300',
        'TZOFFSETTO:+0200',
        'TZNAME:EET',
        'DTSTART:19701025T040000',
        'RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU',
        'END:STANDARD',
        'BEGIN:DAYLIGHT',
        'TZOFFSETFROM:+0200',
        'TZOFFSETTO:+0300',
        'TZNAME:EEST',
        'DTSTART:19700329T030000',
        'RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU',
        'END:DAYLIGHT',
        'END:VTIMEZONE',
        'BEGIN:VEVENT',
        `UID:${uid}`,
        `DTSTAMP:${toUtcStamp()}`,
        `DTSTART;TZID=Europe/Bucharest:${toIcsLocal(start)}`,
        `DTEND;TZID=Europe/Bucharest:${toIcsLocal(end)}`,
        `SUMMARY:${escapeIcs(summary)}`,
        `DESCRIPTION:${escapeIcs(descriptionLines.join('\n'))}`,
        `LOCATION:${escapeIcs(location || '')}`,
        'STATUS:CONFIRMED',
        'BEGIN:VALARM',
        'ACTION:DISPLAY',
        'DESCRIPTION:Reminder',
        'TRIGGER:-PT60M',
        'END:VALARM',
        'END:VEVENT',
        'END:VCALENDAR'
    ].join('\r\n');

    return {
        filename: 'invite.ics',
        content: icsContent,
        contentType: 'text/calendar; charset=UTF-8; method=REQUEST'
    };
}

function tryBuildTemplate(builder, fallback, contextLabel) {
    try {
        return builder();
    } catch (error) {
        console.error(`[EMAIL TEMPLATE FALLBACK] ${contextLabel}:`, error?.message || 'template_error');
        return fallback();
    }
}

async function sendBookingConfirmation({
    appointment,
    doctor = null,
    clinicName = '',
    clinicLocation = '',
    contactPhone = ''
} = {}) {
    if (!appointment || typeof appointment !== 'object') {
        throw new Error('Appointment payload is required.');
    }

    const recipientEmail = toTrimmedString(appointment.email).toLowerCase();
    if (!recipientEmail) {
        throw new Error('Appointment email is missing.');
    }

    const dateTimeParts = parseAppointmentDateTime(appointment);
    const doctorEmailSettings = normalizeDoctorEmailSettingsFromDoctor(doctor);
    const customEmailActive = doctorEmailSettings?.emailEnabled !== false;
    const resolvedClinicName = (customEmailActive ? doctorEmailSettings?.emailClinicNameOverride : null)
        || toTrimmedString(clinicName)
        || 'Clinica';
    const resolvedLocation = (customEmailActive ? doctorEmailSettings?.emailLocationOverride : null)
        || toTrimmedString(clinicLocation)
        || 'Nespecificata';
    const resolvedContactPhone = (customEmailActive ? doctorEmailSettings?.emailContactPhoneOverride : null)
        || toTrimmedString(contactPhone)
        || 'Nespecificat';
    const resolvedPatientName = resolvePatientName(appointment);
    const resolvedDoctorName = resolveDoctorName(doctor, appointment) || 'Medic specialist';
    const resolvedDoctorSpecialty = resolveDoctorSpecialty(doctor);
    const resolvedType = toTrimmedString(appointment.type) || 'Consultatie';

    const templateContext = {
        patientName: resolvedPatientName,
        doctorName: resolvedDoctorName,
        doctorSpecialty: resolvedDoctorSpecialty,
        appointmentDate: formatDateRo(dateTimeParts),
        appointmentTime: formatTimeRo(dateTimeParts),
        appointmentType: resolvedType,
        clinicName: resolvedClinicName,
        location: resolvedLocation,
        contactPhone: resolvedContactPhone,
        doctorSignature: (customEmailActive ? doctorEmailSettings?.emailSignature : null)
            || buildDefaultDoctorSignature(resolvedDoctorName, resolvedClinicName),
        doctorNote: 'Pentru modificari sau anulari, va rugam sa ne contactati in timp util.'
    };

    const customTemplateConfig = resolveDoctorCustomTemplateConfig(doctor, appointment, doctorEmailSettings);
    let templateSource = 'default';
    let templatePayload = null;

    if (hasDoctorCustomTemplateConfig(customTemplateConfig)) {
        templatePayload = tryBuildTemplate(
            () => buildDoctorCustomTemplate(templateContext, customTemplateConfig),
            () => null,
            'doctor_custom'
        );
        if (templatePayload) {
            templateSource = 'doctor_custom';
        }
    }

    if (!templatePayload && hasDoctorIdentity(doctor, appointment)) {
        templatePayload = tryBuildTemplate(
            () => buildDoctorGeneratedTemplate(templateContext),
            () => null,
            'doctor_generated'
        );
        if (templatePayload) {
            templateSource = 'doctor_generated';
        }
    }

    if (!templatePayload) {
        templatePayload = buildBookingConfirmationDefaultTemplate(templateContext);
        templateSource = 'default';
    }

    const sender = getEmailSender((customEmailActive ? customTemplateConfig?.fromName : null) || resolvedClinicName);
    const senderAddress = toTrimmedString(sender.fromEmail);
    const senderName = sanitizeEmailHeaderValue(sender.fromName || '').replace(/"/g, '\'');
    const transporter = getEmailTransporter();
    const replyTo = normalizeReplyTo(
        (customEmailActive ? customTemplateConfig?.replyTo : null)
        || (customEmailActive ? doctorEmailSettings?.emailReplyTo : null)
    );

    const info = await transporter.sendMail({
        from: {
            name: senderName || senderAddress,
            address: senderAddress
        },
        to: recipientEmail,
        ...(replyTo ? { replyTo } : {}),
        subject: templatePayload.subject,
        html: templatePayload.html,
        text: templatePayload.text,
        attachments: [
            buildCalendarInviteAttachment({
                dateTimeParts,
                durationMinutes: resolveConsultationDurationMinutes(doctor),
                clinicName: resolvedClinicName,
                location: resolvedLocation,
                doctorName: resolvedDoctorName,
                patientName: resolvedPatientName,
                appointmentType: resolvedType
            })
        ]
    });

    return {
        messageId: info?.messageId || null,
        envelope: info?.envelope || null,
        templateSource
    };
}

module.exports = {
    sendBookingConfirmation
};
