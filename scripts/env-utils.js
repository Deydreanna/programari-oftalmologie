const DB_PROVIDER = Object.freeze({
    MONGO: 'mongo',
    POSTGRES: 'postgres',
    DUAL: 'dual'
});
const DEFAULT_DB_PROVIDER = DB_PROVIDER.POSTGRES;
const VALID_DB_PROVIDERS = new Set(Object.values(DB_PROVIDER));
const REQUIRED_ENV_VARS = ['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET', 'JWT_STEPUP_SECRET', 'ALLOWED_ORIGINS'];

function parseAllowedOrigins(raw) {
    if (!raw) return [];

    return raw
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean);
}

function normalizeDbProvider(rawValue = DEFAULT_DB_PROVIDER) {
    const normalized = String(rawValue || DEFAULT_DB_PROVIDER).trim().toLowerCase();
    if (!VALID_DB_PROVIDERS.has(normalized)) {
        return null;
    }
    return normalized;
}

function isPostgresProvider(provider = DEFAULT_DB_PROVIDER) {
    return provider === DB_PROVIDER.POSTGRES || provider === DB_PROVIDER.DUAL;
}

function isMongoRuntimeProvider(provider = DEFAULT_DB_PROVIDER) {
    return provider === DB_PROVIDER.MONGO || provider === DB_PROVIDER.DUAL;
}

function validateDatabaseUrl(value) {
    const errors = [];
    const trimmed = String(value || '').trim();

    if (!trimmed) {
        errors.push('DATABASE_URL is required when DB_PROVIDER is postgres or dual.');
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

    return {
        ok: errors.length === 0,
        errors,
        parsed: {
            protocol,
            hostname: parsedUrl.hostname || '',
            port: parsedUrl.port || '5432',
            database
        }
    };
}

function validateBaseEnv(env = process.env) {
    const errors = [];
    const rawDbProvider = String(env.DB_PROVIDER || DEFAULT_DB_PROVIDER).trim().toLowerCase();
    const dbProvider = normalizeDbProvider(rawDbProvider);

    if (!dbProvider) {
        errors.push(`DB_PROVIDER must be one of: ${Array.from(VALID_DB_PROVIDERS).join(', ')}.`);
    }

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

    const normalizedProvider = dbProvider || DEFAULT_DB_PROVIDER;
    if (isMongoRuntimeProvider(normalizedProvider)) {
        if (!env.MONGODB_URI || !String(env.MONGODB_URI).trim()) {
            errors.push('MONGODB_URI is required when DB_PROVIDER is mongo or dual.');
        }
    }

    if (isPostgresProvider(normalizedProvider)) {
        const databaseUrlValidation = validateDatabaseUrl(env.DATABASE_URL);
        if (!databaseUrlValidation.ok) {
            errors.push(...databaseUrlValidation.errors);
        }
    }

    return {
        ok: errors.length === 0,
        errors,
        parsed: {
            allowedOrigins: origins,
            dbProvider: normalizedProvider
        }
    };
}

module.exports = {
    DB_PROVIDER,
    DEFAULT_DB_PROVIDER,
    VALID_DB_PROVIDERS,
    REQUIRED_ENV_VARS,
    normalizeDbProvider,
    isPostgresProvider,
    isMongoRuntimeProvider,
    validateDatabaseUrl,
    parseAllowedOrigins,
    validateBaseEnv
};
