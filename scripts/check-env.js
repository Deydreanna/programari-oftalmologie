#!/usr/bin/env node
require('dotenv').config();

const { validateBaseEnv } = require('./env-utils');
const { buildMongoTlsPolicy } = require('../utils/mongo-tls-config');

const result = validateBaseEnv(process.env);
const mongoTlsPolicy = buildMongoTlsPolicy(process.env);
const errors = Array.from(new Set([
    ...result.errors,
    ...mongoTlsPolicy.validationErrors
]));

if (errors.length) {
    console.error('Environment validation failed:');
    for (const error of errors) {
        console.error(`- ${error}`);
    }
    process.exit(1);
}

console.log('Environment validation passed.');
