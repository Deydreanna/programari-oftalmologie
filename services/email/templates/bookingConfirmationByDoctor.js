const { replaceTemplateTokens, sanitizeEmailHeaderValue } = require('./templateTokens');

const DOCTOR_SUBJECT_TEMPLATE = 'Confirmare programare - {{doctorName}} - {{appointmentDate}}';
const ALLOWED_TEMPLATE_PLACEHOLDERS = Object.freeze([
    'doctorName',
    'appointmentDate',
    'appointmentTime',
    'patientName',
    'clinicName',
    'doctorSignature',
    'contactPhone',
    'location',
    'doctorSpecialty',
    'appointmentType',
    'doctorNote'
]);

const DOCTOR_HTML_TEMPLATE = `
<div style="font-family: Arial, sans-serif; line-height: 1.58; color: #111111;">
  <h2 style="margin: 0 0 12px;">Bun\u0103 ziua, {{patientName}}!</h2>
  <p style="margin: 0 0 12px;">
    Programarea dumneavoastr\u0103 la {{clinicName}} a fost confirmat\u0103 pentru
    <strong>{{doctorName}}</strong>.
  </p>
  <ul style="margin: 0 0 12px; padding-left: 18px;">
    <li><strong>Data:</strong> {{appointmentDate}}</li>
    <li><strong>Ora:</strong> {{appointmentTime}}</li>
    <li><strong>Medic:</strong> {{doctorName}}</li>
    <li><strong>Specialitate:</strong> {{doctorSpecialty}}</li>
    <li><strong>Tip consulta\u021bie:</strong> {{appointmentType}}</li>
    <li><strong>Loca\u021bie:</strong> {{location}}</li>
    <li><strong>Telefon contact:</strong> {{contactPhone}}</li>
  </ul>
  <p style="margin: 0 0 8px;">{{doctorNote}}</p>
  <p style="margin: 0;">Cu stim\u0103,<br>{{doctorSignature}}</p>
</div>
`;

const DOCTOR_TEXT_TEMPLATE = `
Bun\u0103 ziua, {{patientName}}!

Programarea dumneavoastr\u0103 la {{clinicName}} a fost confirmat\u0103 pentru {{doctorName}}.

Data: {{appointmentDate}}
Ora: {{appointmentTime}}
Medic: {{doctorName}}
Specialitate: {{doctorSpecialty}}
Tip consulta\u021bie: {{appointmentType}}
Loca\u021bie: {{location}}
Telefon contact: {{contactPhone}}

{{doctorNote}}

Cu stim\u0103,
{{doctorSignature}}
`;

function normalizeOptionalString(value, maxLength = 4000) {
    if (value === undefined || value === null) return null;
    const normalized = String(value).trim();
    if (!normalized) return null;
    return normalized.slice(0, maxLength);
}

function normalizeDoctorTemplateConfig(rawConfig) {
    if (!rawConfig || typeof rawConfig !== 'object' || Array.isArray(rawConfig)) {
        return null;
    }

    const out = {};
    const mappings = [
        ['subject', 240],
        ['html', 20000],
        ['text', 20000],
        ['signature', 200],
        ['doctorSignature', 200],
        ['doctorNote', 400],
        ['clinicName', 240],
        ['location', 320],
        ['contactPhone', 64],
        ['fromName', 120],
        ['replyTo', 254]
    ];

    for (const [key, maxLength] of mappings) {
        const value = normalizeOptionalString(rawConfig[key], maxLength);
        if (value !== null) {
            out[key] = value;
        }
    }

    return Object.keys(out).length ? out : null;
}

function hasDoctorCustomTemplateConfig(config) {
    if (!config || typeof config !== 'object') return false;
    return Boolean(
        config.subject
        || config.html
        || config.text
        || config.signature
        || config.doctorSignature
        || config.doctorNote
        || config.clinicName
        || config.location
        || config.contactPhone
        || config.fromName
        || config.replyTo
    );
}

function buildDoctorGeneratedTemplate(context = {}, overrides = null) {
    const safeOverrides = (overrides && typeof overrides === 'object') ? overrides : {};
    const templateContext = {
        ...context,
        clinicName: safeOverrides.clinicName || context.clinicName || 'Clinica',
        location: safeOverrides.location || context.location || 'Nespecificata',
        contactPhone: safeOverrides.contactPhone || context.contactPhone || 'Nespecificat',
        doctorSignature: safeOverrides.signature
            || safeOverrides.doctorSignature
            || context.doctorSignature
            || `Echipa ${context.clinicName || 'clinicii'}`,
        doctorNote: safeOverrides.doctorNote
            || context.doctorNote
            || 'In cazul in care nu mai puteti ajunge, va rugam sa ne anuntati telefonic.',
        doctorName: context.doctorName || 'Medic specialist',
        doctorSpecialty: context.doctorSpecialty || 'Oftalmologie',
        patientName: context.patientName || 'Pacient',
        appointmentDate: context.appointmentDate || '-',
        appointmentTime: context.appointmentTime || '-',
        appointmentType: context.appointmentType || 'Consultatie'
    };

    const subjectTemplate = safeOverrides.subject || DOCTOR_SUBJECT_TEMPLATE;
    const htmlTemplate = safeOverrides.html || DOCTOR_HTML_TEMPLATE;
    const textTemplate = safeOverrides.text || DOCTOR_TEXT_TEMPLATE;

    return {
        subject: sanitizeEmailHeaderValue(replaceTemplateTokens(subjectTemplate, templateContext, {
            allowedPlaceholders: ALLOWED_TEMPLATE_PLACEHOLDERS
        })),
        html: replaceTemplateTokens(htmlTemplate, templateContext, {
            html: true,
            allowedPlaceholders: ALLOWED_TEMPLATE_PLACEHOLDERS
        }),
        text: replaceTemplateTokens(textTemplate, templateContext, {
            allowedPlaceholders: ALLOWED_TEMPLATE_PLACEHOLDERS
        })
    };
}

function buildDoctorCustomTemplate(context = {}, customConfig = null) {
    const normalizedConfig = normalizeDoctorTemplateConfig(customConfig);
    if (!hasDoctorCustomTemplateConfig(normalizedConfig)) {
        return null;
    }
    return buildDoctorGeneratedTemplate(context, normalizedConfig);
}

module.exports = {
    ALLOWED_TEMPLATE_PLACEHOLDERS,
    normalizeDoctorTemplateConfig,
    hasDoctorCustomTemplateConfig,
    buildDoctorGeneratedTemplate,
    buildDoctorCustomTemplate
};
