# SECURITY

## Threat Model
- Risc principal: acces neautorizat la date pacient/admin prin atacuri browser, credential stuffing, escaladare de roluri sau configurare operationala gresita.
- Aplicatia ruleaza HTTPS in productie, cu sesiuni pe cookie securizat.
- Input-urile utilizatorilor sunt tratate ca ne-incredere.

## Session Auth si CSRF
- Cookie-uri:
  - `__Host-access` (`httpOnly`, `Secure`, `SameSite=Strict`, `Path=/`)
  - `__Host-refresh` (`httpOnly`, `Secure`, `SameSite=Strict`, `Path=/`)
  - `__Host-csrf` (`Secure`, `SameSite=Strict`, `Path=/`, accesibil frontend)
- Fara token storage in `localStorage`/`sessionStorage`.
- CSRF double-submit:
  - frontend trimite `X-CSRF-Token` pentru request-uri state-changing
  - backend compara header-ul cu cookie-ul `__Host-csrf`
  - mismatch/missing -> `403`

## RBAC si Step-up
- Roluri:
  - `viewer`: read-only
  - `scheduler`: operatiuni de programare
  - `superadmin`: operatiuni destructive + management utilizatori/roluri
- Endpointurile sensibile cer step-up token (`X-Step-Up-Token`) emis prin `POST /api/auth/step-up`.

## Rate Limiting si Lockout
- Rate limiting pe login/refresh/admin/book.
- Login lockout + backoff incremental pentru incercari repetate.

## Audit Logging
- Evenimentele sensibile sunt jurnalizate in Postgres (`audit_logs`):
  - actor, rol, actiune, rezultat, target, IP, user-agent, metadata.

## Postgres / Neon Security
- `DATABASE_URL` este obligatoriu.
- Conexiunile catre Postgres folosesc TLS obligatoriu.
- Configurari insecure (`ssl=false`, `sslmode=disable|allow|prefer`) sunt respinse la validare.
- Query-urile sunt parametrizate (fara concatenare SQL pentru input utilizator).

## Env Vars Sensibile Obligatorii
- `DATABASE_URL`
- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `JWT_STEPUP_SECRET`
- `ALLOWED_ORIGINS`

## Rotire secrete
1. Genereaza valori noi pentru secretele JWT.
2. Actualizeaza variabilele de mediu in platforma de deploy.
3. Redeploy.
4. Forteaza reautentificarea utilizatorilor.
5. Ruleaza `npm run scan:secrets`.
