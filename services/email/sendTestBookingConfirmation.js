const { sendBookingConfirmation, renderBookingConfirmationEmail } = require('./sendBookingConfirmation');

function sanitizeInlineString(value) {
    return String(value || '').replace(/\0/g, '').trim();
}

function buildMockAppointment({ toEmail, doctorName = 'Medic Test' } = {}) {
    const normalizedDoctorName = sanitizeInlineString(doctorName) || 'Medic Test';
    return {
        firstName: 'Pacient',
        lastName: 'Test',
        name: 'Pacient Test',
        email: sanitizeInlineString(toEmail).toLowerCase(),
        phone: '0700000000',
        type: 'Consultatie',
        date: '2026-03-20',
        time: '10:30',
        doctorSnapshotName: normalizedDoctorName
    };
}

async function sendTestBookingConfirmationEmail({
    doctor = null,
    toEmail = '',
    clinicName = '',
    clinicLocation = '',
    contactPhone = '07xx xxx xxx'
} = {}) {
    const normalizedToEmail = sanitizeInlineString(toEmail).toLowerCase();
    if (!normalizedToEmail) {
        throw new Error('Recipient email is required.');
    }

    const safeDoctor = (doctor && typeof doctor === 'object' && !Array.isArray(doctor))
        ? doctor
        : {};
    const doctorName = sanitizeInlineString(safeDoctor.displayName) || 'Medic Test';
    const appointment = buildMockAppointment({ toEmail: normalizedToEmail, doctorName });

    return sendBookingConfirmation({
        appointment,
        doctor: safeDoctor,
        clinicName: sanitizeInlineString(clinicName),
        clinicLocation: sanitizeInlineString(clinicLocation) || 'Adresa/Locatie',
        contactPhone: sanitizeInlineString(contactPhone) || '07xx xxx xxx'
    });
}

function renderTestBookingConfirmationPreview({
    doctor = null,
    clinicName = '',
    clinicLocation = '',
    contactPhone = '07xx xxx xxx'
} = {}) {
    const safeDoctor = (doctor && typeof doctor === 'object' && !Array.isArray(doctor))
        ? doctor
        : {};
    const doctorName = sanitizeInlineString(safeDoctor.displayName) || 'Medic Test';
    const appointment = buildMockAppointment({
        toEmail: 'preview@example.invalid',
        doctorName
    });

    return renderBookingConfirmationEmail({
        appointment,
        doctor: safeDoctor,
        clinicName: sanitizeInlineString(clinicName),
        clinicLocation: sanitizeInlineString(clinicLocation) || 'Adresa/Locatie',
        contactPhone: sanitizeInlineString(contactPhone) || '07xx xxx xxx'
    });
}

module.exports = {
    sendTestBookingConfirmationEmail,
    renderTestBookingConfirmationPreview
};
