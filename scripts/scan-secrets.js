#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const ROOT = process.cwd();
const EXCLUDED_DIRS = new Set(['.git', 'node_modules', '.vscode']);
const EXCLUDED_FILES = new Set(['package-lock.json', '.env']);

const patterns = [
    {
        id: 'mongo-uri',
        regex: /mongodb(?:\+srv)?:\/\/(?!localhost)(?!127\.0\.0\.1)[^\s'"`]+/gi,
        description: 'Potential non-local MongoDB URI'
    },
    {
        id: 'jwt-secret-value',
        regex: /JWT_(?:ACCESS|REFRESH|STEPUP)_SECRET\s*=\s*(?!process\.env\.)(?!<)(?!\$\{)[^\s#]{16,}/g,
        description: 'Potential hardcoded JWT secret value'
    },
    {
        id: 'private-key',
        regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
        description: 'Private key material'
    }
];

function listFilesRecursive(dir) {
    const out = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        const rel = path.relative(ROOT, full);

        if (entry.isDirectory()) {
            if (EXCLUDED_DIRS.has(entry.name)) continue;
            out.push(...listFilesRecursive(full));
            continue;
        }

        if (!entry.isFile()) continue;
        if (EXCLUDED_FILES.has(entry.name)) continue;
        out.push(rel);
    }
    return out;
}

function toLine(text, index) {
    return text.slice(0, index).split(/\r?\n/).length;
}

const findings = [];
for (const relFile of listFilesRecursive(ROOT)) {
    const absFile = path.join(ROOT, relFile);
    let text;
    try {
        text = fs.readFileSync(absFile, 'utf8');
    } catch {
        continue;
    }

    for (const pattern of patterns) {
        pattern.regex.lastIndex = 0;
        let match;
        while ((match = pattern.regex.exec(text)) !== null) {
            findings.push({
                id: pattern.id,
                description: pattern.description,
                file: relFile,
                line: toLine(text, match.index),
                value: String(match[0]).slice(0, 100)
            });
        }
    }
}

if (findings.length) {
    console.error('Potential secret leaks found:');
    for (const item of findings) {
        console.error(`- [${item.id}] ${item.file}:${item.line} ${item.description} -> ${item.value}`);
    }
    process.exit(1);
}

console.log('No obvious leaked secrets found.');
