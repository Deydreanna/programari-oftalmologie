# Ophthalmology Appointments

Secure booking and admin dashboard for ophthalmology appointments.

## Security hardening summary

This repository now enforces:
- fail-closed environment validation (`JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `MONGODB_URI`, `ALLOWED_ORIGINS`)
- no superadmin escalation by email
- superadmin bootstrap only through seed script
- CORS allowlist from environment
- rate limiting + login lockout/backoff
- helmet security headers
- unique `(date, time)` booking index to prevent double booking
- redacted admin appointment responses + audit logs
- no CNP persistence and no base64 file content persistence

## Prerequisites

- Node.js 18+
- MongoDB (local or hosted)

## Install

```bash
npm install
```

## Required environment variables

Create `.env` in project root.

```bash
MONGODB_URI=mongodb://localhost:27017/appointments
JWT_ACCESS_SECRET=<at least 32 chars>
JWT_REFRESH_SECRET=<at least 32 chars>
ALLOWED_ORIGINS=https://drbaltaprog.vercel.app,http://localhost:3000
```

Optional:

```bash
PORT=3000
ACCESS_TOKEN_TTL_MINUTES=15
REFRESH_TOKEN_TTL_DAYS=30
EMAIL_USER=...
EMAIL_PASS=...
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_SECURE=false
EMAIL_FROM_NAME=Prof. Dr. Florian Balta
ENABLE_DIAGNOSTIC_UPLOAD=false
```

## Generate strong JWT secrets

Node:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

OpenSSL:

```bash
openssl rand -base64 48
```

Generate one secret for `JWT_ACCESS_SECRET` and a different one for `JWT_REFRESH_SECRET`.

## Validate env before start

```bash
npm run check:env
```

The server also validates env at startup and exits if invalid.

## Superadmin bootstrap (one-time safe flow)

Normal signup always creates role `user`.

To create/update the first superadmin:

```bash
# in .env
SUPERADMIN_EMAIL=admin@example.com
SUPERADMIN_PASSWORD=<strong password, min 12 chars, upper/lower/number/symbol>

# run seed
npm run seed:superadmin
```

## Run locally

```bash
npm start
```

## Auth + CSRF curl checks

Use your deployed HTTPS URL (required for `__Host-*` secure cookies).

```bash
export BASE_URL="https://your-app.vercel.app"
rm -f cookies.txt

# 1) Login should set __Host-access, __Host-refresh, __Host-csrf
curl -i -c cookies.txt -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"identifier":"admin@example.com","password":"your-password"}'

# 2) /me should return 200 with user profile
curl -i -b cookies.txt "$BASE_URL/api/auth/me"

# 3) Capture csrf token from cookie jar
CSRF=$(awk '$6=="__Host-csrf"{print $7}' cookies.txt | tail -n 1)

# 4) POST without CSRF should fail with 403
curl -i -b cookies.txt -X POST "$BASE_URL/api/auth/logout"

# 5) Refresh with CSRF should return 200 and renew access cookie
curl -i -b cookies.txt -c cookies.txt -X POST "$BASE_URL/api/auth/refresh" \
  -H "X-CSRF-Token: $CSRF"

# 6) CSRF rotates on refresh, read the latest value
CSRF=$(awk '$6=="__Host-csrf"{print $7}' cookies.txt | tail -n 1)

# 7) Logout with CSRF should return 200 and clear auth cookies
curl -i -b cookies.txt -c cookies.txt -X POST "$BASE_URL/api/auth/logout" \
  -H "X-CSRF-Token: $CSRF"

# 8) /me should now return 401
curl -i -b cookies.txt "$BASE_URL/api/auth/me"
```

## Race-condition test for booking

With the server running:

```bash
npm run test:race
```

Expected: one booking succeeds and one returns `409` (slot already booked).

## Booking data minimization

- `CNP` is no longer persisted in MongoDB.
- Diagnostic file base64 content is not stored in MongoDB.
- Current secure default is `ENABLE_DIAGNOSTIC_UPLOAD=false`, which disables online file upload until object storage + signed URLs are configured.

## Diagnostic file storage strategy (required for production uploads)

Use private object storage (S3-compatible/Supabase Storage), store only metadata in MongoDB, and expose downloads only via short-lived signed URLs.

Recommended retention policy: auto-delete uploaded diagnostic files after 30-90 days based on clinical/legal policy.

## Incident cleanup note (`users_db.json` exposure)

`users_db.json` was removed from source control and added to `.gitignore`.
Treat previous exposure as a security incident:
- rotate affected passwords immediately
- invalidate active sessions/tokens
- notify stakeholders according to your policy

## Vercel deployment notes

Set environment variables in Vercel Project Settings:
- `MONGODB_URI`
- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `ALLOWED_ORIGINS` (include your production domain)
- optional mail and upload vars

If frontend and API share the same deployment domain, keep that domain in `ALLOWED_ORIGINS`.
`__Host-*` cookies require HTTPS, `Path=/`, `Secure`, and no `Domain` attribute.
