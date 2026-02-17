const REQUIRED_ENV_VARS = ['MONGODB_URI', 'JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET', 'ALLOWED_ORIGINS'];

function parseAllowedOrigins(raw) {
    if (!raw) return [];

    return raw
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean);
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

    const origins = parseAllowedOrigins(env.ALLOWED_ORIGINS || '');
    if (!origins.length) {
        errors.push('ALLOWED_ORIGINS must include at least one origin.');
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
    parseAllowedOrigins,
    validateBaseEnv
};
