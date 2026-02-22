# programari-oftalmologie

Aplicatie Node.js + Express pentru programari oftalmologie, cu autentificare pe cookie securizat, CSRF double-submit, RBAC, rate limiting si audit logging.

Runtime-ul este **Postgres-only** (compatibil Neon). Suportul MongoDB a fost eliminat.

## Cerinte
- Node.js `20.x`
- O baza Postgres accesibila prin `DATABASE_URL` cu TLS activ

## Configurare mediu
Variabile obligatorii:
- `DATABASE_URL`  
  Trebuie sa fie `postgres://` sau `postgresql://`, cu baza in path.  
  Conexiunile folosesc TLS obligatoriu.
- `JWT_ACCESS_SECRET` (minim 32 caractere)
- `JWT_REFRESH_SECRET` (minim 32 caractere)
- `JWT_STEPUP_SECRET` (minim 32 caractere)
- `ALLOWED_ORIGINS` (lista separata prin virgula)

Variabile optionale:
- `ACCESS_TOKEN_TTL_MINUTES` (default `15`)
- `REFRESH_TOKEN_TTL_DAYS` (default `30`)
- `STEP_UP_TOKEN_TTL_MINUTES` (default `5`)
- `ENABLE_DIAGNOSTIC_UPLOAD` (`true` / `false`)
- `EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`, `EMAIL_SMTP_SECURE`, `EMAIL_USER`, `EMAIL_PASS`, `EMAIL_FROM_NAME`
- `SUPERADMIN_EMAIL` si `SUPERADMIN_PASSWORD` (pentru bootstrap/seed)

## Instalare si rulare
```bash
npm install
npm run check:env
npm run db:migrate
npm start
```

## Scripturi utile
- `npm run check:env` - validare stricta a variabilelor de mediu
- `npm run db:migrate` - ruleaza migrarile SQL
- `npm run db:check:postgres` - health check Postgres
- `npm run seed:superadmin` - creeaza/actualizeaza superadmin in Postgres
- `npm run test:security` - verificari frontend security
- `npm run test:race` - test cursa pe slot booking
- `npm run test:multidoctor` - verificari multidoctor/scoping
- `npm run test:auth-rbac` - verificari auth + RBAC
- `npm run scan:secrets` - scan simplu pentru secrete hardcodate

## Note de compatibilitate API
- Identificatorii publici `_id` pentru utilizatori/medici/programari raman in format legacy de 24 caractere unde este cazul (din campuri `legacy_mongo_id` in Postgres).
- Contractele de raspuns admin/public au fost pastrate.

## Securitate
Aplicatia mentine:
- cookie-uri `__Host-*` securizate
- CSRF double-submit (`X-CSRF-Token`)
- Helmet + CORS allowlist strict
- RBAC server-side (`viewer`, `scheduler`, `superadmin`)
- step-up auth pentru actiuni sensibile
- rate limiting + lockout/backoff login
- audit logging in Postgres
- `Cache-Control: no-store` pe endpointuri sensibile
