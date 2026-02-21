const tls = require('tls');

const DEFAULT_MONGO_TLS_MIN_VERSION = 'TLSv1.3';
const FALLBACK_MONGO_TLS_MIN_VERSION = 'TLSv1.2';
const INSECURE_QUERY_OPTION_MESSAGES = Object.freeze({
    tls: 'MONGODB_URI must not contain tls=false. Remove insecure TLS overrides from the URI.',
    ssl: 'MONGODB_URI must not contain ssl=false. Remove insecure TLS overrides from the URI.',
    tlsallowinvalidcertificates: 'MONGODB_URI must not contain tlsAllowInvalidCertificates=true.',
    tlsallowinvalidhostnames: 'MONGODB_URI must not contain tlsAllowInvalidHostnames=true.',
    tlsinsecure: 'MONGODB_URI must not contain tlsInsecure=true.'
});

const TRUE_LIKE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const FALSE_LIKE_VALUES = new Set(['0', 'false', 'no', 'off']);

function parseBooleanEnv(rawValue, defaultValue = false) {
    if (rawValue === undefined || rawValue === null || String(rawValue).trim() === '') {
        return defaultValue;
    }

    const normalized = String(rawValue).trim().toLowerCase();
    if (TRUE_LIKE_VALUES.has(normalized)) return true;
    if (FALSE_LIKE_VALUES.has(normalized)) return false;
    return defaultValue;
}

function normalizeMongoTlsMinVersion(rawValue) {
    if (rawValue === undefined || rawValue === null || String(rawValue).trim() === '') {
        return DEFAULT_MONGO_TLS_MIN_VERSION;
    }

    const normalized = String(rawValue).trim().toLowerCase();
    if (normalized === 'tlsv1.3') return 'TLSv1.3';
    if (normalized === 'tlsv1.2') return 'TLSv1.2';
    throw new Error('MONGO_TLS_MIN_VERSION must be TLSv1.3 or TLSv1.2.');
}

function parseMongoUriScheme(uri) {
    const match = String(uri || '').trim().match(/^(mongodb(?:\+srv)?):\/\//i);
    if (!match) return '';
    return String(match[1] || '').toLowerCase();
}

function getHostSection(uri) {
    const withoutScheme = String(uri || '').trim().replace(/^mongodb(?:\+srv)?:\/\//i, '');
    const authority = withoutScheme.split(/[/?#]/, 1)[0] || '';
    const atIndex = authority.lastIndexOf('@');
    return atIndex >= 0 ? authority.slice(atIndex + 1) : authority;
}

function parseMongoUriHostCount(uri) {
    const hostSection = getHostSection(uri);
    if (!hostSection) return 0;
    return hostSection
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean)
        .length;
}

function buildRedactedHostLabels(hostCount) {
    const labels = [];
    for (let index = 0; index < hostCount; index += 1) {
        labels.push(`host-${index + 1}`);
    }
    return labels;
}

function safeDecodeURIComponent(value) {
    try {
        return decodeURIComponent(value);
    } catch (_) {
        return value;
    }
}

function parseMongoUriQueryOptions(uri) {
    const queryIndex = String(uri || '').indexOf('?');
    if (queryIndex < 0) return new Map();

    const queryString = String(uri).slice(queryIndex + 1).split('#')[0];
    const options = new Map();

    for (const pair of queryString.split('&')) {
        if (!pair) continue;
        const [rawKey, ...rawValueParts] = pair.split('=');
        const key = safeDecodeURIComponent(String(rawKey || '').trim()).toLowerCase();
        if (!key) continue;
        const value = safeDecodeURIComponent(rawValueParts.join('=')).trim().toLowerCase();
        if (!options.has(key)) {
            options.set(key, []);
        }
        options.get(key).push(value);
    }

    return options;
}

function containsFalseLikeValue(values = []) {
    return values.some((value) => FALSE_LIKE_VALUES.has(String(value || '').trim().toLowerCase()));
}

function containsTrueLikeValue(values = []) {
    return values.some((value) => TRUE_LIKE_VALUES.has(String(value || '').trim().toLowerCase()));
}

function validateMongoUri(uri) {
    const errors = [];
    const normalizedUri = String(uri || '').trim();

    if (!normalizedUri) {
        errors.push('MONGODB_URI is required.');
        return {
            ok: false,
            errors,
            scheme: '',
            hostCount: 0
        };
    }

    const scheme = parseMongoUriScheme(normalizedUri);
    if (!scheme) {
        errors.push('MONGODB_URI must start with mongodb:// or mongodb+srv://');
        return {
            ok: false,
            errors,
            scheme: '',
            hostCount: 0
        };
    }

    const queryOptions = parseMongoUriQueryOptions(normalizedUri);
    if (containsFalseLikeValue(queryOptions.get('tls'))) {
        errors.push(INSECURE_QUERY_OPTION_MESSAGES.tls);
    }
    if (containsFalseLikeValue(queryOptions.get('ssl'))) {
        errors.push(INSECURE_QUERY_OPTION_MESSAGES.ssl);
    }
    if (containsTrueLikeValue(queryOptions.get('tlsallowinvalidcertificates'))) {
        errors.push(INSECURE_QUERY_OPTION_MESSAGES.tlsallowinvalidcertificates);
    }
    if (containsTrueLikeValue(queryOptions.get('tlsallowinvalidhostnames'))) {
        errors.push(INSECURE_QUERY_OPTION_MESSAGES.tlsallowinvalidhostnames);
    }
    if (containsTrueLikeValue(queryOptions.get('tlsinsecure'))) {
        errors.push(INSECURE_QUERY_OPTION_MESSAGES.tlsinsecure);
    }

    return {
        ok: errors.length === 0,
        errors,
        scheme,
        hostCount: parseMongoUriHostCount(normalizedUri)
    };
}

function trimEnvValue(value) {
    if (value === undefined || value === null) return '';
    return String(value).trim();
}

function buildMongoTlsPolicy(env = process.env) {
    const mongodbUri = trimEnvValue(env.MONGODB_URI);
    const uriValidation = validateMongoUri(mongodbUri);
    const errors = [...uriValidation.errors];
    let configuredMinVersion = DEFAULT_MONGO_TLS_MIN_VERSION;

    try {
        configuredMinVersion = normalizeMongoTlsMinVersion(env.MONGO_TLS_MIN_VERSION);
    } catch (error) {
        errors.push(error.message);
    }

    const allowFallbackTo12 = parseBooleanEnv(env.MONGO_TLS_ALLOW_FALLBACK_TO_1_2, false);
    const tlsCAFile = trimEnvValue(env.MONGO_TLS_CA_FILE);
    const tlsCertificateKeyFile = trimEnvValue(env.MONGO_TLS_CERT_KEY_FILE);
    const tlsCertificateKeyFilePassword = trimEnvValue(env.MONGO_TLS_CERT_KEY_PASSWORD);

    const connectOptions = {
        tls: true
    };
    if (tlsCAFile) {
        connectOptions.tlsCAFile = tlsCAFile;
    }
    if (tlsCertificateKeyFile) {
        connectOptions.tlsCertificateKeyFile = tlsCertificateKeyFile;
    }
    if (tlsCertificateKeyFilePassword) {
        connectOptions.tlsCertificateKeyFilePassword = tlsCertificateKeyFilePassword;
    }

    return {
        mongodbUri,
        validationErrors: errors,
        uriScheme: uriValidation.scheme || 'unknown',
        hostCount: uriValidation.hostCount,
        redactedHosts: buildRedactedHostLabels(uriValidation.hostCount),
        configuredMinVersion,
        allowFallbackTo12,
        connectOptions,
        tlsCAFileConfigured: Boolean(tlsCAFile),
        tlsCertificateKeyFileConfigured: Boolean(tlsCertificateKeyFile),
        tlsCertificateKeyPasswordConfigured: Boolean(tlsCertificateKeyFilePassword)
    };
}

function buildMongoDriverTlsOptions(policy, minVersion) {
    const options = {
        ...(policy?.connectOptions || {}),
        tls: true
    };

    try {
        options.secureContext = tls.createSecureContext({ minVersion });
    } catch (error) {
        const wrapped = new Error(
            `MongoDB TLS protocol configuration failed while requiring ${minVersion}.`
        );
        wrapped.cause = error;
        throw wrapped;
    }

    return options;
}

function collectErrorParts(error) {
    const queue = [error];
    const visited = new Set();
    const parts = [];

    while (queue.length) {
        const current = queue.shift();
        if (!current) continue;

        if (typeof current === 'string') {
            parts.push(current);
            continue;
        }

        if (typeof current !== 'object') {
            parts.push(String(current));
            continue;
        }

        if (visited.has(current)) {
            continue;
        }
        visited.add(current);

        if (typeof current.name === 'string') parts.push(current.name);
        if (typeof current.code === 'string' || typeof current.code === 'number') parts.push(String(current.code));
        if (typeof current.message === 'string') parts.push(current.message);
        if (typeof current.errmsg === 'string') parts.push(current.errmsg);
        if (typeof current.reason === 'string') parts.push(current.reason);

        if (Array.isArray(current.errors)) {
            queue.push(...current.errors);
        }

        if (current.cause) queue.push(current.cause);
        if (current.reason && typeof current.reason === 'object') queue.push(current.reason);
        if (current.err && typeof current.err === 'object') queue.push(current.err);
        if (current.error && typeof current.error === 'object') queue.push(current.error);
        if (current.originalError && typeof current.originalError === 'object') queue.push(current.originalError);
    }

    return parts.join(' | ').toLowerCase();
}

const TLS_COMPATIBILITY_HINTS = Object.freeze([
    'err_ssl_wrong_version_number',
    'err_ssl_unsupported_protocol',
    'wrong version number',
    'unsupported protocol',
    'tlsv1 alert protocol version',
    'alert protocol version',
    'protocol version',
    'version too low',
    'no protocols available'
]);

const NON_FALLBACK_HINTS = Object.freeze([
    'authentication failed',
    'auth failed',
    'auth error',
    'bad auth',
    'sasl',
    'no such host',
    'getaddrinfo',
    'enotfound',
    'eai_again',
    'connection string',
    'invalid uri',
    'parse error',
    'certificate',
    'self signed',
    'unable to verify',
    'hostname/ip does not match certificate',
    'depth_zero_self_signed_cert'
]);

function isLikelyTlsCompatibilityError(error) {
    const errorText = collectErrorParts(error);
    if (!errorText) return false;

    if (NON_FALLBACK_HINTS.some((hint) => errorText.includes(hint))) {
        return false;
    }

    if (TLS_COMPATIBILITY_HINTS.some((hint) => errorText.includes(hint))) {
        return true;
    }

    return (errorText.includes('tls') || errorText.includes('ssl')) && errorText.includes('protocol');
}

function redactMongoUriInText(text) {
    return String(text || '')
        .replace(/mongodb(\+srv)?:\/\/[^\s'"]+/gi, '<redacted-mongodb-uri>')
        .trim();
}

function getSafeMongoErrorSummary(error) {
    const name = typeof error?.name === 'string' ? error.name : 'Error';
    const code = (typeof error?.code === 'string' || typeof error?.code === 'number')
        ? String(error.code)
        : '';
    const message = redactMongoUriInText(error?.message || String(error || 'Unknown error')) || 'Unknown error';
    return { name, code, message };
}

module.exports = {
    DEFAULT_MONGO_TLS_MIN_VERSION,
    FALLBACK_MONGO_TLS_MIN_VERSION,
    buildMongoTlsPolicy,
    buildMongoDriverTlsOptions,
    getSafeMongoErrorSummary,
    isLikelyTlsCompatibilityError
};
