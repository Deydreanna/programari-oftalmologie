# SECURITY

## Threat Model Assumptions
- Primary risk is compromise of patient and admin data through browser attacks (XSS/CSRF), stolen credentials, over-privileged accounts, and operator mistakes.
- Frontend and API are deployed same-origin on Vercel over HTTPS.
- Attackers may control patient input fields (name, email, phone, notes) and may attempt stored XSS in admin views.
- DB compromise blast radius is reduced by data minimization and least-privilege operational access.

## Session Auth and CSRF
- Browser auth uses secure cookies only:
  - `__Host-access` (httpOnly, Secure, SameSite=Strict, Path=/, short TTL)
  - `__Host-refresh` (httpOnly, Secure, SameSite=Strict, Path=/, longer TTL)
  - `__Host-csrf` (Secure, SameSite=Strict, Path=/, readable by frontend)
- No bearer token storage in `localStorage`/`sessionStorage`.
- CSRF protection uses double-submit token:
  - frontend sends `X-CSRF-Token` on all state-changing requests.
  - server checks header equals `__Host-csrf` cookie.
  - missing/mismatch -> `403`.

## Admin Role Policy
- Roles:
  - `viewer`: read-only admin views.
  - `scheduler`: read + operational scheduling actions (for example resend confirmation email).
  - `superadmin`: destructive operations and user role management.
- Destructive routes are `superadmin` only and require step-up token:
  - reset/delete/export/user role changes.
- Step-up flow:
  - `POST /api/auth/step-up` with password + action.
  - server issues short-lived action token.
  - destructive route must include `X-Step-Up-Token`.

## Audit Logging Coverage
Audit records are stored in dedicated `AuditLog` collection and include:
- actor user id + role
- action
- result (`success`/`failure`/`denied`)
- target type/id
- IP
- user-agent
- timestamp
- metadata (context fields)

Events logged include:
- login success/failure
- signup
- logout
- step-up success/failure/denials
- appointment list/detail/file access
- resend email
- delete/reset/export
- user role change
- authorization denials

## Required Sensitive Env Vars (Vercel)
- `MONGODB_URI`
- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `JWT_STEPUP_SECRET`
- `ALLOWED_ORIGINS`

Optional security tuning:
- `ACCESS_TOKEN_TTL_MINUTES`
- `REFRESH_TOKEN_TTL_DAYS`
- `STEP_UP_TOKEN_TTL_MINUTES`

## Secret Rotation
1. Generate new strong values for `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `JWT_STEPUP_SECRET`.
2. Update Vercel env vars.
3. Redeploy.
4. Force logout by invalidating active sessions (users re-authenticate and get new cookies).
5. Rotate Mongo credentials if exposure is suspected.
6. Run `npm run scan:secrets` and review git history hygiene guidance in README.

## Retention Guidance
- Keep audit logs for at least 12 months (or stricter clinical/legal requirement).
- Apply archival/deletion policy via scheduled DB job or managed retention controls.
- Restrict direct access to audit collection to operational security/admin personnel only.
