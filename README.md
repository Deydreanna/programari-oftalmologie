# Ophthalmology Appointments

Node.js + Express application for ophthalmology bookings, with secure cookie auth, CSRF, RBAC, and audit logging. MongoDB remains active, and Postgres (Neon-compatible) infrastructure is prepared in parallel.

## What changed (multi-doctor refactor)

- Booking is now **multi-doctor**.
- Public flow is: **doctor -> date -> slot -> patient data**.
- Admin panel remains at **`/adminpanel`**.
- Public self-signup remains disabled (`POST /api/auth/signup` returns 403).
- Users can be created/managed only by **superadmin**.
- Scheduler/viewer access is doctor-scoped through `managedDoctorIds`.

## Security baseline (kept)

- Cookie-based auth (`__Host-*` cookies), no bearer-token localStorage auth.
- CSRF double-submit protection.
- Helmet hardening and CORS allowlist.
- RBAC (`viewer`, `scheduler`, `superadmin`) enforced server-side.
- Step-up auth for destructive/sensitive actions.
- Rate limits + login lockout/backoff.
- Audit logging for auth/admin operations.
- `Cache-Control: no-store` on API/auth-sensitive paths.

## Data model highlights

### Doctor

Collection fields include:

- `slug` (unique)
- `displayName`, `specialty`, `isActive`
- `bookingSettings`:
  - `consultationDurationMinutes`
  - `workdayStart`, `workdayEnd`
  - `monthsToShow`
  - `timezone`
- `availabilityRules.weekdays`
- `blockedDates`
- `createdByUserId`, `updatedByUserId`, timestamps

### Appointment

Now includes:

- `doctorId` (required)
- `doctorSnapshotName`

Unique booking constraint:

- `UNIQUE (doctorId, date, time)`

### User

Now includes:

- `managedDoctorIds: ObjectId[]`

## Startup migration (idempotent)

On startup, the app runs a safe migration routine:

1. Ensures a default doctor exists (`prof-dr-balta-florian`).
2. Backfills legacy appointments missing `doctorId`.
3. Backfills missing `doctorSnapshotName` on appointments.
4. Backfills missing `managedDoctorIds` on users.

Scope decision:

- Existing non-superadmin users are kept with `managedDoctorIds: []` (safer default), so superadmin must assign doctor scope explicitly.

## Install and run

```bash
npm install
npm run check:env
npm start
```

## Required env vars

```bash
DB_PROVIDER=mongo
MONGODB_URI=mongodb://localhost:27017/appointments
JWT_ACCESS_SECRET=<at least 32 chars>
JWT_REFRESH_SECRET=<at least 32 chars>
JWT_STEPUP_SECRET=<at least 32 chars>
ALLOWED_ORIGINS=https://your-app.vercel.app,http://localhost:3000
```

### Postgres env vars (Phase 1)

- `DB_PROVIDER`: `mongo` (default), `postgres`, or `dual`
- `DATABASE_URL`: required when `DB_PROVIDER=postgres` or `DB_PROVIDER=dual`
- Optional pool tuning:
  - `PG_POOL_MAX` (default `10`)
  - `PG_IDLE_TIMEOUT_MS` (default `30000`)
  - `PG_CONNECTION_TIMEOUT_MS` (default `5000`)

Example:

```bash
DB_PROVIDER=dual
DATABASE_URL=postgresql://<user>:<password>@<host>/<database>?sslmode=require
```

## Postgres (Phase 1 infrastructure)

- Connection module: `db/postgres.js`
- SQL migrations: `db/migrations/*.sql`
- Migration runner: `npm run db:migrate`
- Connectivity check: `npm run db:check:postgres`

Current behavior:

- `DB_PROVIDER=mongo`: users/auth + doctors/availability + appointments use MongoDB.
- `DB_PROVIDER=postgres` or `DB_PROVIDER=dual`: users/auth/roles + doctors/availability/blocked days are persisted in Postgres.
- Appointments and audit logs remain on MongoDB in this phase.
- `DB_PROVIDER=dual` supports lazy user and doctor migration from MongoDB to Postgres.

### Run migrations

```bash
npm run db:migrate
```

### Test Postgres connectivity

```bash
npm run db:check:postgres
```

### Verify auth + RBAC flow (requires running server + superadmin creds)

```bash
$env:BASE_URL="http://localhost:3000"
$env:SUPERADMIN_IDENTIFIER="superadmin@example.com"
$env:SUPERADMIN_PASSWORD="YourSuperadminPassword"
npm run test:auth-rbac
```

## MongoDB TLS hardening

Mongo transport security is enforced in code via `mongoose.connect(MONGODB_URI, options)` with TLS options, not only via URI defaults.

### Added env vars

- `MONGO_TLS_MIN_VERSION` (default: `TLSv1.3`, allowed values: `TLSv1.3`, `TLSv1.2`)
- `MONGO_TLS_ALLOW_FALLBACK_TO_1_2` (default: `false`)
- `MONGO_TLS_CA_FILE` (optional, custom CA bundle path)
- `MONGO_TLS_CERT_KEY_FILE` (optional, client cert/key bundle path)
- `MONGO_TLS_CERT_KEY_PASSWORD` (optional, client cert/key password)

### Behavior

1. Startup fails if `MONGODB_URI` is missing or contains insecure TLS overrides.
2. First connection attempt always uses `tls: true` and `minVersion` from `MONGO_TLS_MIN_VERSION` (default `TLSv1.3`).
3. If and only if a TLS protocol compatibility error is detected and `MONGO_TLS_ALLOW_FALLBACK_TO_1_2=true`, the app retries once with `minVersion: TLSv1.2`.
4. The app does not fallback for authentication, DNS, URI parsing, certificate validation, or unrelated errors.
5. Startup logs include effective TLS policy and Node runtime version, without logging full Mongo URI or credentials.

### Atlas example (recommended)

```bash
MONGODB_URI=mongodb+srv://<user>:<password>@cluster0.example.mongodb.net/appointments?retryWrites=true&w=majority
MONGO_TLS_MIN_VERSION=TLSv1.3
MONGO_TLS_ALLOW_FALLBACK_TO_1_2=false
```

### Self-hosted example (custom CA/client cert)

```bash
MONGODB_URI=mongodb://db1.example.internal:27017,db2.example.internal:27017/appointments?replicaSet=rs0
MONGO_TLS_MIN_VERSION=TLSv1.3
MONGO_TLS_ALLOW_FALLBACK_TO_1_2=false
MONGO_TLS_CA_FILE=/etc/certs/mongo-ca.pem
MONGO_TLS_CERT_KEY_FILE=/etc/certs/mongo-client.pem
MONGO_TLS_CERT_KEY_PASSWORD=<optional-password>
```

### Diagnostics

- `GET /api/admin/mongo-tls` (superadmin only) returns non-sensitive Mongo TLS metadata and connection state.

### Insecure flags to avoid

Never add these to `MONGODB_URI`: `tls=false`, `ssl=false`, `tlsAllowInvalidCertificates=true`, `tlsAllowInvalidHostnames=true`, `tlsInsecure=true`.

## Node runtime

- `package.json` pins Node: `20.x`
- In Vercel Project Settings set **Node.js Version = 20.x**

## Core endpoints

### Public

- `GET /api/public/doctors` (active doctors only, safe fields)
- `GET /api/slots?doctor=<slug-or-id>&date=YYYY-MM-DD`
- `POST /api/book` (or `POST /api/appointments`) with `doctorId` or `doctorSlug`

### Admin (role protected)

- Doctors:
  - `GET /api/admin/doctors`
  - `POST /api/admin/doctors` (superadmin)
  - `PATCH /api/admin/doctors/:id` (scheduler scoped to assigned doctors, or superadmin)
  - `POST /api/admin/doctors/:id/block-date` (scheduler scoped to assigned doctors, or superadmin)
  - `DELETE /api/admin/doctors/:id/block-date/:date` (scheduler scoped to assigned doctors, or superadmin)
- Users:
  - `POST /api/admin/users` (superadmin)
  - `GET /api/admin/users` (superadmin)
  - `PATCH /api/admin/users/:id` (superadmin + step-up)
  - `DELETE /api/admin/users/:id` (superadmin + step-up)
- System diagnostics:
  - `GET /api/admin/mongo-tls` (superadmin)

## Verification scripts

- Security baseline:

```bash
npm test
npm run scan:secrets
```

- Booking race protection:

```bash
npm run test:race
```

- Multi-doctor verification (requires superadmin credentials):

```bash
$env:BASE_URL="http://localhost:3000"
$env:SUPERADMIN_IDENTIFIER="superadmin@example.com"
$env:SUPERADMIN_PASSWORD="YourSuperadminPassword"
npm run test:multidoctor
```

## Manual sanity checks (quick)

1. Public signup blocked:

```bash
curl -i -X POST "$BASE_URL/api/auth/signup" -H "Content-Type: application/json" --data '{"email":"x@y.com","phone":"0712345678","password":"Password123!","displayName":"X"}'
```

2. Public slots require doctor:

```bash
curl -i "$BASE_URL/api/slots?date=2026-03-04"
```

3. Admin panel route is dedicated:

```bash
curl -I "$BASE_URL/"
curl -I "$BASE_URL/adminpanel"
```

## Notes

- `/adminpanel` HTML is static, but all sensitive data/actions require authenticated API calls with RBAC + CSRF.
- Do not hardcode secrets in repo; keep them in Vercel/project environment variables.
