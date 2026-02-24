const crypto = require('crypto');

const ENC_ALG = 'aes-256-gcm';
const ENC_VERSION = 1;
const ENC_KIND = 'patient-text';
const ENC_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const CNP_CONTROL_KEY = '279146358279';
const PAYLOAD_REQUIRED_KEYS = Object.freeze(['v', 'k', 'alg', 'iv', 'tag', 'ct']);
const PAYLOAD_CIPHERTEXT_KEYS = Object.freeze(['iv', 'tag', 'ct']);
const PAYLOAD_METADATA_KEYS = Object.freeze(['v', 'k', 'alg']);
const BLIND_INDEX_KIND = Object.freeze({
    CNP: 'cnp',
    PHONE: 'phone',
    EMAIL: 'email'
});

class PatientCryptoError extends Error {
    constructor(message, { code = 'patient_crypto_error', field = '' } = {}) {
        super(message);
        this.name = 'PatientCryptoError';
        this.code = code;
        this.field = field || '';
    }
}

let cachedKeys = null;

function parseBase64Key(rawValue, envName) {
    const normalized = String(rawValue || '').trim();
    if (!normalized) {
        throw new PatientCryptoError(`${envName} is required.`, {
            code: 'missing_key',
            field: envName
        });
    }

    const base64Pattern = /^[A-Za-z0-9+/]+={0,2}$/;
    if ((normalized.length % 4) !== 0 || !base64Pattern.test(normalized)) {
        throw new PatientCryptoError(`${envName} must be valid base64.`, {
            code: 'invalid_key_format',
            field: envName
        });
    }

    let decoded;
    try {
        decoded = Buffer.from(normalized, 'base64');
    } catch (_) {
        throw new PatientCryptoError(`${envName} must be valid base64.`, {
            code: 'invalid_key_format',
            field: envName
        });
    }

    if (decoded.toString('base64') !== normalized) {
        throw new PatientCryptoError(`${envName} must be valid base64.`, {
            code: 'invalid_key_format',
            field: envName
        });
    }

    if (!decoded || decoded.length !== ENC_KEY_BYTES) {
        throw new PatientCryptoError(`${envName} must decode to exactly 32 bytes.`, {
            code: 'invalid_key_length',
            field: envName
        });
    }

    return decoded;
}

function validatePatientCryptoEnv(env = process.env) {
    const errors = [];

    try {
        parseBase64Key(env.PATIENT_DATA_ENC_KEY, 'PATIENT_DATA_ENC_KEY');
    } catch (error) {
        errors.push(error.message || 'PATIENT_DATA_ENC_KEY is invalid.');
    }

    try {
        parseBase64Key(env.PATIENT_INDEX_KEY, 'PATIENT_INDEX_KEY');
    } catch (error) {
        errors.push(error.message || 'PATIENT_INDEX_KEY is invalid.');
    }

    return {
        ok: errors.length === 0,
        errors
    };
}

function getKeys() {
    if (cachedKeys) {
        return cachedKeys;
    }

    const encKey = parseBase64Key(process.env.PATIENT_DATA_ENC_KEY, 'PATIENT_DATA_ENC_KEY');
    const indexKey = parseBase64Key(process.env.PATIENT_INDEX_KEY, 'PATIENT_INDEX_KEY');
    cachedKeys = Object.freeze({ encKey, indexKey });
    return cachedKeys;
}

function normalizeEmail(value) {
    return String(value || '').trim().toLowerCase();
}

function normalizePhone(value) {
    return String(value || '').trim().replace(/[^\d]/g, '');
}

function normalizeCnp(value) {
    return String(value || '').trim().replace(/[^\d]/g, '');
}

function validateCnp(rawValue) {
    const cnp = normalizeCnp(rawValue);
    if (!/^\d{13}$/.test(cnp)) {
        return false;
    }

    const firstDigit = Number(cnp[0]);
    if (!Number.isInteger(firstDigit) || firstDigit < 1 || firstDigit > 9) {
        return false;
    }

    let sum = 0;
    for (let index = 0; index < 12; index += 1) {
        sum += Number(cnp[index]) * Number(CNP_CONTROL_KEY[index]);
    }

    let expected = sum % 11;
    if (expected === 10) {
        expected = 1;
    }
    return Number(cnp[12]) === expected;
}

function maskCnp(rawValue) {
    const cnp = normalizeCnp(rawValue);
    if (!cnp) return '';
    if (cnp.length <= 4) return cnp;
    return `${cnp.slice(0, 2)}********${cnp.slice(-3)}`;
}

function hasOwnProperty(object, key) {
    return Object.prototype.hasOwnProperty.call(object, key);
}

function looksLikeEncryptedPayloadObject(payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        return false;
    }
    const hasCiphertext = PAYLOAD_CIPHERTEXT_KEYS.some((key) => hasOwnProperty(payload, key));
    const hasMetadata = PAYLOAD_METADATA_KEYS.some((key) => hasOwnProperty(payload, key));
    return hasCiphertext && hasMetadata;
}

function parseEncryptedPayload(rawValue, { strict = false, fieldName = '' } = {}) {
    if (typeof rawValue !== 'string') {
        return null;
    }
    const trimmed = rawValue.trim();
    if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) {
        return null;
    }

    let payload;
    try {
        payload = JSON.parse(trimmed);
    } catch (_) {
        return null;
    }

    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        return null;
    }

    const encryptedCandidate = looksLikeEncryptedPayloadObject(payload);
    if (!encryptedCandidate) {
        return null;
    }

    const hasAllRequiredKeys = PAYLOAD_REQUIRED_KEYS.every((key) => hasOwnProperty(payload, key));
    if (!hasAllRequiredKeys) {
        if (strict) {
            throw new PatientCryptoError('Encrypted patient field payload metadata is invalid.', {
                code: 'invalid_encrypted_payload',
                field: fieldName
            });
        }
        return null;
    }

    const version = Number(payload.v);
    const kind = String(payload.k || '').trim().toLowerCase();
    const algorithm = String(payload.alg || '').trim().toLowerCase();
    const iv = String(payload.iv || '').trim();
    const tag = String(payload.tag || '').trim();
    const ct = String(payload.ct || '').trim();

    if (version !== ENC_VERSION || kind !== ENC_KIND || algorithm !== ENC_ALG || !iv || !tag || !ct) {
        if (strict) {
            throw new PatientCryptoError('Encrypted patient field payload metadata is invalid.', {
                code: 'invalid_encrypted_payload',
                field: fieldName
            });
        }
        return null;
    }

    return { v: version, k: kind, alg: algorithm, iv, tag, ct };
}

function isEncryptedPayload(rawValue) {
    return !!parseEncryptedPayload(rawValue);
}

function encryptTextField(value) {
    if (value === null || value === undefined) {
        return null;
    }

    const normalized = String(value);
    if (!normalized.length) {
        return '';
    }

    const { encKey } = getKeys();
    const iv = crypto.randomBytes(GCM_IV_BYTES);
    const cipher = crypto.createCipheriv(ENC_ALG, encKey, iv);
    const ciphertext = Buffer.concat([
        cipher.update(normalized, 'utf8'),
        cipher.final()
    ]);
    const tag = cipher.getAuthTag();

    return JSON.stringify({
        v: ENC_VERSION,
        k: ENC_KIND,
        alg: ENC_ALG,
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ct: ciphertext.toString('base64')
    });
}

function decryptEncryptedPayload(payload, fieldName = '') {
    const { encKey } = getKeys();

    let iv;
    let tag;
    let ct;
    try {
        iv = Buffer.from(payload.iv, 'base64');
        tag = Buffer.from(payload.tag, 'base64');
        ct = Buffer.from(payload.ct, 'base64');
    } catch (_) {
        throw new PatientCryptoError('Encrypted patient field payload is invalid.', {
            code: 'invalid_encrypted_payload',
            field: fieldName
        });
    }

    if (iv.length !== GCM_IV_BYTES || tag.length !== GCM_TAG_BYTES || !ct.length) {
        throw new PatientCryptoError('Encrypted patient field payload has invalid lengths.', {
            code: 'invalid_encrypted_payload',
            field: fieldName
        });
    }

    try {
        const decipher = crypto.createDecipheriv(ENC_ALG, encKey, iv);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([
            decipher.update(ct),
            decipher.final()
        ]);
        return plaintext.toString('utf8');
    } catch (_) {
        throw new PatientCryptoError('Encrypted patient field failed authentication.', {
            code: 'decrypt_auth_failed',
            field: fieldName
        });
    }
}

function decryptTextField(value, { fieldName = '' } = {}) {
    if (value === null || value === undefined) {
        return null;
    }

    const normalized = String(value);
    if (!normalized.length) {
        return '';
    }

    const payload = parseEncryptedPayload(normalized, { strict: true, fieldName });
    if (!payload) {
        return normalized;
    }

    return decryptEncryptedPayload(payload, fieldName);
}

function normalizeBlindIndexValue(value, kind) {
    switch (kind) {
    case BLIND_INDEX_KIND.CNP:
        return normalizeCnp(value);
    case BLIND_INDEX_KIND.PHONE:
        return normalizePhone(value);
    case BLIND_INDEX_KIND.EMAIL:
        return normalizeEmail(value);
    default:
        throw new PatientCryptoError(`Blind index kind is invalid: ${kind}`, {
            code: 'invalid_blind_index_kind'
        });
    }
}

function computeBlindIndex(value, kind) {
    const normalized = normalizeBlindIndexValue(value, kind);
    if (!normalized) {
        return null;
    }
    const { indexKey } = getKeys();
    const hmac = crypto.createHmac('sha256', indexKey);
    hmac.update(`patient:${kind}:v1:${normalized}`, 'utf8');
    return hmac.digest('hex');
}

module.exports = {
    PatientCryptoError,
    BLIND_INDEX_KIND,
    validatePatientCryptoEnv,
    normalizeEmail,
    normalizePhone,
    normalizeCnp,
    validateCnp,
    maskCnp,
    isEncryptedPayload,
    encryptTextField,
    decryptTextField,
    computeBlindIndex
};
