// Shared email template presets for doctor confirmation emails (superadmin UI only).
(function registerEmailTemplatePresets(globalScope) {
    const presets = [
        {
            id: 'minimalist',
            label: 'Minimalist',
            subject: 'Confirmare programare – {{doctorName}} – {{appointmentDate}}, {{appointmentTime}}',
            text: `Confirmare programare

Bună ziua, {{patientName}}.

Programarea dumneavoastră a fost înregistrată cu succes.

Medic: {{doctorName}}
Data: {{appointmentDate}}
Ora: {{appointmentTime}}
Clinică: {{clinicName}}
Locație: {{location}}
Contact: {{contactPhone}}

Dacă nu mai puteți ajunge, vă rugăm să anunțați din timp.

{{doctorSignature}}`,
            html: `<!doctype html><html lang="ro"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background:#ffffff;color:#111">
<div style="max-width:640px;margin:24px auto;border:1px solid #e6e6e6;border-radius:12px;overflow:hidden">
<div style="padding:20px 22px">
<h1 style="margin:0 0 10px 0;font-size:20px">Confirmare programare</h1>
<p style="margin:0 0 10px 0;color:#333;line-height:1.6">Bună ziua, {{patientName}}.</p>
<p style="margin:0 0 14px 0;color:#333;line-height:1.6">Programarea dumneavoastră a fost înregistrată cu succes.</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">
<tr><td style="padding:8px 0;color:#666;width:180px">Medic</td><td style="padding:8px 0;font-weight:bold">{{doctorName}}</td></tr>
<tr><td style="padding:8px 0;color:#666">Data</td><td style="padding:8px 0">{{appointmentDate}}</td></tr>
<tr><td style="padding:8px 0;color:#666">Ora</td><td style="padding:8px 0">{{appointmentTime}}</td></tr>
<tr><td style="padding:8px 0;color:#666">Clinică</td><td style="padding:8px 0">{{clinicName}}</td></tr>
<tr><td style="padding:8px 0;color:#666">Locație</td><td style="padding:8px 0">{{location}}</td></tr>
<tr><td style="padding:8px 0;color:#666">Contact</td><td style="padding:8px 0">{{contactPhone}}</td></tr>
</table>
<p style="margin:14px 0 0 0;color:#333;line-height:1.6">{{doctorSignature}}</p>
</div></div></body></html>`,
            signature: `Cu respect,
{{doctorName}}
{{clinicName}}`
        },
        {
            id: 'formal',
            label: 'Formal',
            subject: 'Confirmare programare pacient – {{doctorName}} – {{appointmentDate}} – {{appointmentTime}}',
            text: `{{clinicName}}

Confirmare programare

Stimat(ă) pacient(ă) {{patientName}},

Vă confirmăm înregistrarea programării:

Medic: {{doctorName}}
Data: {{appointmentDate}}
Ora: {{appointmentTime}}
Locație: {{location}}
Telefon contact: {{contactPhone}}

Vă rugăm să vă prezentați la data și ora stabilite. În cazul în care nu mai puteți ajunge, vă rugăm să anunțați în prealabil.

{{doctorSignature}}`,
            html: `<!doctype html><html lang="ro"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background:#ffffff;color:#111">
<div style="max-width:680px;margin:24px auto;border:1px solid #d9d9d9">
<div style="padding:16px 18px;border-bottom:2px solid #111">
<div style="font-size:12px;color:#444">{{clinicName}}</div>
<h1 style="margin:8px 0 0 0;font-size:18px">Confirmare programare</h1>
</div>
<div style="padding:16px 18px;font-size:14px;line-height:1.6">
<p style="margin:0 0 10px 0">Stimat(ă) pacient(ă) {{patientName}},</p>
<p style="margin:0 0 12px 0">Vă confirmăm înregistrarea programării, conform detaliilor:</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="8" style="border-collapse:collapse;border:1px solid #d9d9d9">
<tr><td style="border:1px solid #d9d9d9;background:#f6f6f6;width:200px"><b>Medic</b></td><td style="border:1px solid #d9d9d9">{{doctorName}}</td></tr>
<tr><td style="border:1px solid #d9d9d9;background:#f6f6f6"><b>Data</b></td><td style="border:1px solid #d9d9d9">{{appointmentDate}}</td></tr>
<tr><td style="border:1px solid #d9d9d9;background:#f6f6f6"><b>Ora</b></td><td style="border:1px solid #d9d9d9">{{appointmentTime}}</td></tr>
<tr><td style="border:1px solid #d9d9d9;background:#f6f6f6"><b>Locație</b></td><td style="border:1px solid #d9d9d9">{{location}}</td></tr>
<tr><td style="border:1px solid #d9d9d9;background:#f6f6f6"><b>Telefon</b></td><td style="border:1px solid #d9d9d9">{{contactPhone}}</td></tr>
</table>
<p style="margin:12px 0 0 0">{{doctorSignature}}</p>
</div></div></body></html>`,
            signature: `Cu stimă,
{{doctorName}}
{{clinicName}}
Contact: {{contactPhone}}`
        },
        {
            id: 'sofisticat',
            label: 'Sofisticat',
            subject: 'Programarea dumneavoastră este confirmată | {{doctorName}} | {{appointmentDate}} · {{appointmentTime}}',
            text: `Confirmare programare

Bună ziua, {{patientName}},

Vă mulțumim. Programarea dumneavoastră a fost confirmată.

Medic: {{doctorName}}
Data și ora: {{appointmentDate}} · {{appointmentTime}}
Locație: {{location}}
Clinică: {{clinicName}}
Contact: {{contactPhone}}

Dacă aveți nevoie să modificați sau să anulați programarea, vă rugăm să ne contactați din timp.

{{doctorSignature}}`,
            html: `<!doctype html><html lang="ro"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background:#f4f1eb;color:#111">
<div style="max-width:640px;margin:26px auto;border:1px solid #e6dccb;border-radius:14px;overflow:hidden;background:#fff">
<div style="height:6px;background:linear-gradient(90deg,#111 0%,#c9b79b 55%,#b8863b 100%)"></div>
<div style="padding:20px 22px">
<div style="font-size:12px;letter-spacing:1px;text-transform:uppercase;color:#7a6a52">Confirmare programare</div>
<h1 style="margin:10px 0 10px 0;font-size:22px">Bună ziua, {{patientName}}</h1>
<p style="margin:0 0 14px 0;color:#333;line-height:1.7">Vă mulțumim. Programarea dumneavoastră a fost confirmată.</p>
<div style="border:1px solid #eee3d3;border-radius:12px;background:#faf8f3;padding:14px 14px">
<div style="color:#777;font-size:13px">Medic</div><div style="font-weight:bold;margin:4px 0 10px 0">{{doctorName}}</div>
<div style="color:#777;font-size:13px">Data și ora</div><div style="margin:4px 0 10px 0">{{appointmentDate}} · {{appointmentTime}}</div>
<div style="color:#777;font-size:13px">Locație</div><div style="margin:4px 0 0 0">{{location}}</div>
</div>
<p style="margin:12px 0 0 0;color:#333;line-height:1.7">{{clinicName}} · {{contactPhone}}</p>
<p style="margin:12px 0 0 0;color:#333;line-height:1.7">{{doctorSignature}}</p>
</div></div></body></html>`,
            signature: `Cu considerație,
{{doctorName}}
{{clinicName}}
{{location}}
Telefon: {{contactPhone}}`
        }
    ];

    globalScope.EMAIL_TEMPLATE_PRESETS = Object.freeze(
        presets.map((preset) => Object.freeze({ ...preset }))
    );
})(typeof window !== 'undefined' ? window : globalThis);

