const TOKEN_PATTERN = /{{\s*([a-zA-Z0-9_]+)\s*}}/g;

function toTokenString(value) {
    if (value === null || value === undefined) return '';
    return String(value);
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function sanitizeTextToken(value) {
    return String(value)
        .replace(/\0/g, '')
        .replace(/\r/g, '');
}

function replaceTemplateTokens(template, tokens = {}, { html = false, allowedPlaceholders = null } = {}) {
    const allowedSet = allowedPlaceholders
        ? new Set(Array.isArray(allowedPlaceholders) ? allowedPlaceholders : [])
        : null;
    const source = typeof template === 'string' ? template : '';
    return source.replace(TOKEN_PATTERN, (match, rawKey) => {
        const key = String(rawKey || '').trim();
        if (allowedSet && !allowedSet.has(key)) {
            return match;
        }
        const tokenValue = Object.prototype.hasOwnProperty.call(tokens, key)
            ? toTokenString(tokens[key])
            : '';
        return html ? escapeHtml(tokenValue) : sanitizeTextToken(tokenValue);
    });
}

function sanitizeEmailHeaderValue(value) {
    return String(value || '')
        .replace(/[\r\n]+/g, ' ')
        .replace(/\0/g, '')
        .trim();
}

module.exports = {
    escapeHtml,
    replaceTemplateTokens,
    sanitizeEmailHeaderValue
};
