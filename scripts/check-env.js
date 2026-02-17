#!/usr/bin/env node
require('dotenv').config();

const { validateBaseEnv } = require('./env-utils');

const result = validateBaseEnv(process.env);

if (!result.ok) {
    console.error('Environment validation failed:');
    for (const error of result.errors) {
        console.error(`- ${error}`);
    }
    process.exit(1);
}

console.log('Environment validation passed.');
