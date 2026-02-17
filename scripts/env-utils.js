const REQUIRED_ENV_VARS = ['MONGODB_URI', 'JWT_SECRET', 'ALLOWED_ORIGINS'];

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

    const jwtSecret = env.JWT_SECRET || '';
    if (jwtSecret && jwtSecret.length < 32) {
        errors.push('JWT_SECRET must be at least 32 characters.');
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
