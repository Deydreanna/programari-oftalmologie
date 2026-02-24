const { replaceTemplateTokens, sanitizeEmailHeaderValue } = require('./templateTokens');
const { ALLOWED_TEMPLATE_PLACEHOLDERS } = require('./bookingConfirmationByDoctor');

const DEFAULT_SUBJECT_TEMPLATE = 'Confirmare programare - {{clinicName}} - {{appointmentDate}}';

const DEFAULT_HTML_TEMPLATE = `
<div style="font-family: Arial, sans-serif; line-height: 1.55; color: #111111;">
  <h2 style="margin: 0 0 12px;">Bun\u0103 ziua, {{patientName}}!</h2>
  <p style="margin: 0 0 12px;">Programarea dumneavoastr\u0103 a fost inregistrat\u0103 cu succes.</p>
  <ul style="margin: 0 0 12px; padding-left: 18px;">
    <li><strong>Data:</strong> {{appointmentDate}}</li>
    <li><strong>Ora:</strong> {{appointmentTime}}</li>
    <li><strong>Medic:</strong> {{doctorName}}</li>
    <li><strong>Tip consulta\u021bie:</strong> {{appointmentType}}</li>
    <li><strong>Loca\u021bie:</strong> {{location}}</li>
  </ul>
  <p style="margin: 0 0 8px;">V\u0103 rug\u0103m s\u0103 v\u0103 prezentati cu 10-15 minute inainte.</p>
  <p style="margin: 0;">Cu stim\u0103,<br>{{doctorSignature}}</p>
</div>
`;

const DEFAULT_TEXT_TEMPLATE = `
Bun\u0103 ziua, {{patientName}}!

Programarea dumneavoastr\u0103 a fost inregistrat\u0103 cu succes.

Data: {{appointmentDate}}
Ora: {{appointmentTime}}
Medic: {{doctorName}}
Tip consulta\u021bie: {{appointmentType}}
Loca\u021bie: {{location}}

V\u0103 rug\u0103m s\u0103 v\u0103 prezentati cu 10-15 minute inainte.

Cu stim\u0103,
{{doctorSignature}}
`;

function buildBookingConfirmationDefaultTemplate(context = {}) {
    const templateContext = {
        patientName: context.patientName || 'Pacient',
        doctorName: context.doctorName || 'Medic specialist',
        appointmentDate: context.appointmentDate || '-',
        appointmentTime: context.appointmentTime || '-',
        appointmentType: context.appointmentType || 'Consultatie',
        clinicName: context.clinicName || 'Clinica',
        location: context.location || 'Nespecificata',
        doctorSignature: context.doctorSignature || `Echipa ${context.clinicName || 'clinicii'}`
    };

    const subject = sanitizeEmailHeaderValue(
        replaceTemplateTokens(DEFAULT_SUBJECT_TEMPLATE, templateContext, {
            allowedPlaceholders: ALLOWED_TEMPLATE_PLACEHOLDERS
        })
    );

    return {
        subject,
        html: replaceTemplateTokens(DEFAULT_HTML_TEMPLATE, templateContext, {
            html: true,
            allowedPlaceholders: ALLOWED_TEMPLATE_PLACEHOLDERS
        }),
        text: replaceTemplateTokens(DEFAULT_TEXT_TEMPLATE, templateContext, {
            allowedPlaceholders: ALLOWED_TEMPLATE_PLACEHOLDERS
        })
    };
}

module.exports = {
    buildBookingConfirmationDefaultTemplate
};
