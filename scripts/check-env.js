#!/usr/bin/env node
require('dotenv').config();

const { validateBaseEnv, isMongoRuntimeProvider } = require('./env-utils');
const { buildMongoTlsPolicy } = require('../utils/mongo-tls-config');

const result = validateBaseEnv(process.env);
const shouldValidateMongoTls = isMongoRuntimeProvider(result.parsed.dbProvider);
const mongoTlsPolicy = shouldValidateMongoTls
    ? buildMongoTlsPolicy(process.env)
    : { validationErrors: [] };
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
