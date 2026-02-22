const REQUIRED_ENV_VARS = ['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET', 'JWT_STEPUP_SECRET', 'ALLOWED_ORIGINS'];
const SECURE_SSL_MODES = new Set(['require', 'verify-ca', 'verify-full']);
const INSECURE_SSL_MODES = new Set(['disable', 'allow', 'prefer']);
const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off']);

function parseAllowedOrigins(raw) {
    if (!raw) return [];

    return raw
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean);
}

function hasFalseLikeValue(rawValue) {
    const normalized = String(rawValue || '').trim().toLowerCase();
    return normalized && FALSE_VALUES.has(normalized);
}

function hasTrueLikeValue(rawValue) {
    const normalized = String(rawValue || '').trim().toLowerCase();
    return normalized && TRUE_VALUES.has(normalized);
}

function validateDatabaseUrl(value) {
    const errors = [];
    const trimmed = String(value || '').trim();

    if (!trimmed) {
        errors.push('DATABASE_URL is required.');
        return {
            ok: false,
            errors,
            parsed: null
        };
    }

    let parsedUrl;
    try {
        parsedUrl = new URL(trimmed);
    } catch (_) {
        errors.push('DATABASE_URL must be a valid URL.');
        return {
            ok: false,
            errors,
            parsed: null
        };
    }

    const protocol = String(parsedUrl.protocol || '').toLowerCase();
    if (!['postgres:', 'postgresql:'].includes(protocol)) {
        errors.push('DATABASE_URL must start with postgres:// or postgresql://');
    }

    if (!parsedUrl.hostname) {
        errors.push('DATABASE_URL must include a hostname.');
    }

    const database = String(parsedUrl.pathname || '').replace(/^\/+/, '').trim();
    if (!database) {
        errors.push('DATABASE_URL must include a database name in the path.');
    }

    const sslMode = String(parsedUrl.searchParams.get('sslmode') || '').trim().toLowerCase();
    if (sslMode) {
        if (INSECURE_SSL_MODES.has(sslMode)) {
            errors.push('DATABASE_URL must not use insecure sslmode values (disable/allow/prefer).');
        } else if (!SECURE_SSL_MODES.has(sslMode)) {
            errors.push('DATABASE_URL sslmode must be one of: require, verify-ca, verify-full.');
        }
    }

    const sslParam = parsedUrl.searchParams.get('ssl');
    if (sslParam !== null && hasFalseLikeValue(sslParam)) {
        errors.push('DATABASE_URL must not set ssl=false.');
    }
    if (sslParam !== null && !hasFalseLikeValue(sslParam) && !hasTrueLikeValue(sslParam)) {
        errors.push('DATABASE_URL ssl query value must be true/false when provided.');
    }

    return {
        ok: errors.length === 0,
        errors,
        parsed: {
            protocol,
            hostname: parsedUrl.hostname || '',
            port: parsedUrl.port || '5432',
            database,
            sslMode: sslMode || null
        }
    };
}

function validateBaseEnv(env = process.env) {
    const errors = [];

    for (const key of REQUIRED_ENV_VARS) {
        if (!env[key] || !String(env[key]).trim()) {
            errors.push(`${key} is required.`);
        }
    }

    const accessSecret = env.JWT_ACCESS_SECRET || '';
    if (accessSecret && accessSecret.length < 32) {
        errors.push('JWT_ACCESS_SECRET must be at least 32 characters.');
    }

    const refreshSecret = env.JWT_REFRESH_SECRET || '';
    if (refreshSecret && refreshSecret.length < 32) {
        errors.push('JWT_REFRESH_SECRET must be at least 32 characters.');
    }

    const stepupSecret = env.JWT_STEPUP_SECRET || '';
    if (stepupSecret && stepupSecret.length < 32) {
        errors.push('JWT_STEPUP_SECRET must be at least 32 characters.');
    }

    const origins = parseAllowedOrigins(env.ALLOWED_ORIGINS || '');
    if (!origins.length) {
        errors.push('ALLOWED_ORIGINS must include at least one origin.');
    }

    const databaseUrlValidation = validateDatabaseUrl(env.DATABASE_URL);
    if (!databaseUrlValidation.ok) {
        errors.push(...databaseUrlValidation.errors);
    }

    return {
        ok: errors.length === 0,
        errors,
        parsed: {
            allowedOrigins: origins
        }
    };
}

module.exports = {
    REQUIRED_ENV_VARS,
    validateDatabaseUrl,
    parseAllowedOrigins,
    validateBaseEnv
};
