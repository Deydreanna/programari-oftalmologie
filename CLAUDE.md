# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install                          # Install dependencies
npm run check:env                    # Validate all required env vars
npm run db:migrate                   # Run PostgreSQL migrations
npm start                            # Start Express server

# Database
npm run db:check:postgres            # Health-check database connection
npm run seed:superadmin              # Bootstrap/update superadmin credentials

# Verification & testing
npm run test:security                # Frontend security checks
npm run test:race                    # Slot booking race condition test
npm run test:multidoctor             # Multi-doctor scoping verification
npm run test:auth-rbac               # Auth + RBAC verification
npm run test:patient-encryption      # Patient encryption + blind index check
npm run scan:secrets                 # Scan source for hardcoded secrets
```

## Architecture

**server.js** (~3900 lines) is the monolithic Express app — all route handlers, middleware (Helmet, CORS, rate-limiting, CSRF), and business logic live here. There is no build step; the server runs directly with Node.js 24.

**db/** — database layer:
- `postgres.js` — connection pool (Neon PostgreSQL, TLS required)
- `appointments-postgres.js`, `doctors-postgres.js`, `users-postgres.js` — per-entity query modules
- `patient-crypto.js` — AES-256-GCM encryption/decryption for patient fields and HMAC-SHA256 blind indexes
- `migrations/` — 8 numbered SQL migration files run by `scripts/run-pg-migrations.js`

**public/** — vanilla JS frontend (no framework, no build):
- `index.html` + `script.js` — public booking form
- `adminpanel.html` + `adminpanel.js` (~3600 lines) — admin dashboard with timeline scheduler
- `auth.js` — frontend JWT/cookie helpers

**services/email/** — Nodemailer transporter + per-doctor email templates with token substitution (`templateTokens.js`).

**scripts/** — utility and verification scripts (not application code).

## Key Patterns

**Authentication:** JWT access/refresh/step-up tokens stored in `__Host-*` secure cookies. CSRF double-submit pattern. Login lockout: 5 attempts → 15-minute window with exponential backoff.

**RBAC:** Three roles — `viewer` (read-only), `scheduler` (manage appointments), `superadmin` (full access including user/doctor management and step-up operations).

**Patient data encryption:** Sensitive text fields encrypted at the application layer (AES-256-GCM) before storage. Searchable fields have a companion HMAC-SHA256 blind index column. Keys come from `PATIENT_DATA_ENC_KEY` and `PATIENT_INDEX_KEY` env vars (base64-encoded 32-byte keys).

**Legacy ID compatibility:** PostgreSQL UUID primary keys coexist with a `legacy_mongo_id` column (24-char hex) to preserve backwards API compatibility from a previous MongoDB backend.

**Multi-doctor scheduling:** Each doctor has independent booking settings, availability rules, blocked dates, and per-doctor email templates stored in dedicated tables.
