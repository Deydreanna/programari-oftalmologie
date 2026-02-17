#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const ROOT = process.cwd();
const TARGET_DIRS = [path.join(ROOT, 'public')];

const checks = [
    {
        id: 'no-innerhtml',
        description: 'Unsafe innerHTML assignment in frontend',
        regex: /\binnerHTML\s*=/g
    },
    {
        id: 'no-auth-token-storage',
        description: 'authToken persistence in browser storage',
        regex: /(?:localStorage|sessionStorage)\.(?:setItem|getItem|removeItem)\(\s*['"]authToken['"]/g
    },
    {
        id: 'no-authorization-header',
        description: 'Frontend Authorization header usage for browser auth',
        regex: /Authorization\s*[:=]/g
    },
    {
        id: 'no-html-template-interpolation',
        description: 'Potential dynamic HTML template interpolation in frontend',
        regex: /`[^`]*<[^`]*\$\{[^`]*\}[^`]*>/g
    }
];

function listFilesRecursive(dir) {
    const out = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            out.push(...listFilesRecursive(full));
        } else if (entry.isFile() && /\.(js|html|css)$/i.test(entry.name)) {
            out.push(full);
        }
    }
    return out;
}

function toLineCol(text, index) {
    const before = text.slice(0, index);
    const lines = before.split(/\r?\n/);
    return { line: lines.length, col: lines[lines.length - 1].length + 1 };
}

const findings = [];
for (const dir of TARGET_DIRS) {
    if (!fs.existsSync(dir)) continue;
    const files = listFilesRecursive(dir);
    for (const file of files) {
        const text = fs.readFileSync(file, 'utf8');
        for (const check of checks) {
            check.regex.lastIndex = 0;
            let match;
            while ((match = check.regex.exec(text)) !== null) {
                const loc = toLineCol(text, match.index);
                findings.push({
                    check: check.id,
                    description: check.description,
                    file: path.relative(ROOT, file),
                    line: loc.line,
                    col: loc.col,
                    snippet: match[0]
                });
            }
        }
    }
}

if (findings.length) {
    console.error('Security checks failed:');
    for (const item of findings) {
        console.error(`- [${item.check}] ${item.file}:${item.line}:${item.col} ${item.description} -> ${item.snippet}`);
    }
    process.exit(1);
}

console.log('Security checks passed.');
