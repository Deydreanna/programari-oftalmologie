# Ophthalmology Appointments

Secure booking and admin dashboard for ophthalmology appointments.

## Security hardening summary

This repository now enforces:
- fail-closed environment validation (`JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `JWT_STEPUP_SECRET`, `MONGODB_URI`, `ALLOWED_ORIGINS`)
- no superadmin escalation by email
- superadmin bootstrap only through seed script
- dedicated admin panel at `/adminpanel`
- public self-signup disabled
- CORS allowlist from environment
- rate limiting + login lockout/backoff
- helmet security headers
- cookie-based sessions + CSRF double-submit protection
- role separation (`viewer`, `scheduler`, `superadmin`) + step-up auth for destructive operations
- unique `(date, time)` booking index to prevent double booking
- expanded audit logs for auth/admin actions
- no CNP collection/persistence and no base64 file content persistence

## Prerequisites

- Node.js 20.x (LTS)
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
JWT_STEPUP_SECRET=<at least 32 chars>
ALLOWED_ORIGINS=https://drbaltaprog.vercel.app,http://localhost:3000
```

Optional:

```bash
PORT=3000
ACCESS_TOKEN_TTL_MINUTES=15
REFRESH_TOKEN_TTL_DAYS=30
STEP_UP_TOKEN_TTL_MINUTES=5
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

Generate separate secrets for `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, and `JWT_STEPUP_SECRET`.

## Validate env before start

```bash
npm run check:env
```

The server also validates env at startup and exits if invalid.

## Superadmin bootstrap (one-time safe flow)

Public signup is disabled. New users are created only by `superadmin` in `/adminpanel`.
For first-time setup use the seed flow below.

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

## Verification

Run baseline security checks:

```bash
npm test
npm run scan:secrets
npm audit --audit-level=high
```

Quick grep checks:

```bash
# no unsafe dynamic HTML sinks in frontend
rg -n "innerHTML\s*=|outerHTML|insertAdjacentHTML" public

# no browser bearer-token usage / token storage
rg -n "authToken|Authorization|Bearer\s+" public
```

Cookie + CSRF + RBAC curl checks (use HTTPS deployment):

```bash
export BASE_URL="https://your-app.vercel.app"
rm -f super.cookies viewer.cookies scheduler.cookies

# 1) superadmin login -> should set __Host-access/__Host-refresh/__Host-csrf
curl -i -c super.cookies -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"identifier":"superadmin@example.com","password":"superadmin-password"}'
grep "__Host-access\|__Host-refresh\|__Host-csrf" super.cookies

# 2) session check
curl -i -b super.cookies "$BASE_URL/api/auth/me"

# 3) CSRF failure check (missing header => 403)
curl -i -b super.cookies -X POST "$BASE_URL/api/auth/refresh"

# 4) CSRF success check + refresh
CSRF=$(awk '$6=="__Host-csrf"{print $7}' super.cookies | tail -n 1)
curl -i -b super.cookies -c super.cookies -X POST "$BASE_URL/api/auth/refresh" \
  -H "X-CSRF-Token: $CSRF"

# 5) logout with CSRF should clear session cookies; /me should then return 401
curl -i -b super.cookies -c super.cookies -X POST "$BASE_URL/api/auth/logout" \
  -H "X-CSRF-Token: $CSRF"
curl -i -b super.cookies "$BASE_URL/api/auth/me"

# 6) slots validation (invalid date format and invalid real date)
curl -i "$BASE_URL/api/slots?date=2026/02/18"
curl -i "$BASE_URL/api/slots?date=2026-02-31"

# 7) viewer cannot delete/export/reset
curl -i -c viewer.cookies -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"identifier":"viewer@example.com","password":"viewer-password"}'
V_CSRF=$(awk '$6=="__Host-csrf"{print $7}' viewer.cookies | tail -n 1)
curl -i -b viewer.cookies -X DELETE "$BASE_URL/api/admin/appointment/REPLACE_ID" \
  -H "X-CSRF-Token: $V_CSRF"
curl -i -b viewer.cookies "$BASE_URL/api/admin/export"

# 8) scheduler cannot reset/export (but can read + operational actions)
curl -i -c scheduler.cookies -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"identifier":"scheduler@example.com","password":"scheduler-password"}'
S_CSRF=$(awk '$6=="__Host-csrf"{print $7}' scheduler.cookies | tail -n 1)
curl -i -b scheduler.cookies -X POST "$BASE_URL/api/admin/reset" \
  -H "X-CSRF-Token: $S_CSRF"
curl -i -b scheduler.cookies "$BASE_URL/api/admin/export"

# 9) security headers check
curl -I "$BASE_URL/"
curl -I "$BASE_URL/api/auth/me"
```

Expected security header highlights on production routes:
- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- `Permissions-Policy`
- `Strict-Transport-Security`
- `Cache-Control: no-store` on `/api/*` and auth pages

Browser check:
- open DevTools -> Network -> select `/` and `/api/auth/me` responses
- verify the headers above are present

## Quick sanity checks for admin/signup changes

```bash
export BASE_URL="https://your-app.vercel.app"

# 1) public signup blocked
curl -i -X POST "$BASE_URL/api/auth/signup" \
  -H "Content-Type: application/json" \
  --data '{"email":"public@example.com","phone":"0712345678","password":"Password123!","displayName":"Public User"}'
# expected: 403 (or 404 if you choose to hide route)

# 2) login as non-superadmin then try create-user -> 403
curl -i -c viewer.cookies -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"identifier":"viewer@example.com","password":"viewer-password"}'
V_CSRF=$(awk '$6=="__Host-csrf"{print $7}' viewer.cookies | tail -n 1)
curl -i -b viewer.cookies -X POST "$BASE_URL/api/admin/users" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $V_CSRF" \
  --data '{"email":"new.user@example.com","phone":"0711111111","password":"Password123!","displayName":"New User","role":"viewer"}'

# 3) login as superadmin then create-user -> 201
curl -i -c super.cookies -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"identifier":"superadmin@example.com","password":"superadmin-password"}'
S_CSRF=$(awk '$6=="__Host-csrf"{print $7}' super.cookies | tail -n 1)
curl -i -b super.cookies -X POST "$BASE_URL/api/admin/users" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $S_CSRF" \
  --data '{"email":"new.admin@example.com","phone":"0722222222","password":"Password123!","displayName":"New Admin","role":"scheduler"}'

# 4) admin panel route exists and is separate from homepage
curl -I "$BASE_URL/"
curl -I "$BASE_URL/adminpanel"
```

Optional git history secret scan:

```bash
git log -p -S "JWT_ACCESS_SECRET"
git log -p -G "mongodb(\\+srv)?:\\/\\/"
```

Charset/diacritics checks:

```bash
export BASE_URL="https://your-app.vercel.app"

# 1) UTF-8 debug payload should render Romanian diacritics + emoji
curl -i "$BASE_URL/debug/charset"

# 2) POST text with Romanian diacritics; write/read must match
curl -i -X POST "$BASE_URL/debug/charset" \
  -H "Content-Type: application/json; charset=utf-8" \
  --data '{"text":"Mănăstire, țuică, șură, înger"}'
```

Expected:
- response `Content-Type` includes `charset=utf-8`
- response body preserves Romanian diacritics
- debug roundtrip reports `dbRoundtripMatches: true`

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
- `JWT_STEPUP_SECRET`
- `ALLOWED_ORIGINS` (include your production domain)
- optional mail and upload vars

If frontend and API share the same deployment domain, keep that domain in `ALLOWED_ORIGINS`.
`__Host-*` cookies require HTTPS, `Path=/`, `Secure`, and no `Domain` attribute.

Pin Node runtime to avoid unstable UTF-8 behavior:
- `package.json` uses `"engines": { "node": "20.x" }`
- in Vercel Project Settings -> Node.js Version, set `20.x`

xd
hd
