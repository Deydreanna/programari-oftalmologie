const nodemailer = require('nodemailer');

let cachedTransporter = null;
let cachedSignature = '';

function readMailerConfigFromEnv() {
    const host = String(process.env.EMAIL_SMTP_HOST || 'smtp.gmail.com').trim();
    const port = Number(process.env.EMAIL_SMTP_PORT || 587);
    const secure = String(process.env.EMAIL_SMTP_SECURE || '').trim().toLowerCase() === 'true';
    const user = String(process.env.EMAIL_USER || '').trim();
    const pass = String(process.env.EMAIL_PASS || '');
    const fromName = String(process.env.EMAIL_FROM_NAME || '').trim();

    if (!user || !pass) {
        throw new Error('EMAIL_USER and EMAIL_PASS are required.');
    }
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
        throw new Error('EMAIL_SMTP_PORT is invalid.');
    }

    return {
        host,
        port,
        secure,
        user,
        pass,
        fromName
    };
}

function buildTransportSignature(config) {
    return `${config.host}:${config.port}:${config.secure ? '1' : '0'}:${config.user}`;
}

function getEmailTransporter() {
    const config = readMailerConfigFromEnv();
    const signature = buildTransportSignature(config);

    if (!cachedTransporter || cachedSignature !== signature) {
        cachedTransporter = nodemailer.createTransport({
            host: config.host,
            port: config.port,
            secure: config.secure,
            auth: {
                user: config.user,
                pass: config.pass
            }
        });
        cachedSignature = signature;
    }

    return cachedTransporter;
}

function getEmailSender(defaultFromName = '') {
    const config = readMailerConfigFromEnv();
    const fallbackName = String(defaultFromName || '').trim();
    return {
        fromEmail: config.user,
        fromName: config.fromName || fallbackName || config.user
    };
}

module.exports = {
    getEmailTransporter,
    getEmailSender
};
