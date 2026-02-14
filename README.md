# Instrucțiuni de Instalare și Rulare

Deoarece mediul curent nu are Node.js preinstalat, va trebui să urmați acești pași pe calculatorul dvs. pentru a rula aplicația.

## 1. Instalare Node.js

Dacă nu aveți deja Node.js instalat:

1. Mergeți la [nodejs.org](https://nodejs.org/).
2. Descărcați și instalați versiunea **LTS** (Recommended for most users).
3. După instalare, deschideți un terminal (Command Prompt sau PowerShell) și verificați dacă funcționează tastând:

   ```bash
   node -v
   npm -v
   ```

## 2. Configurare Proiect

1. Deschideți terminalul în folderul proiectului (`e:\Antigravity`).
2. Instalați dependențele necesare rulând comanda:

   ```bash
   npm install
   ```

   *Aceasta va instala: express, body-parser, cors, xlsx, nodemailer, node-cron.*

## 3. Configurare Email (Opțional dar Recomandat)

Pentru ca funcția de trimitere email să funcționeze, trebuie să editați fișierul `server.js`.

1. Deschideți `server.js`.
2. Căutați liniile (aprox. linia 130):

   ```javascript
   user: process.env.EMAIL_USER || 'YOUR_EMAIL@gmail.com',
   pass: process.env.EMAIL_PASS || 'YOUR_APP_PASSWORD'
   ```

3. Înlocuiți cu adresa dvs. de Gmail și [Parola de Aplicație](https://support.google.com/accounts/answer/185833?hl=ro) (nu parola normală de login).
   *Alternativ, puteți configura variabile de mediu.*

## 4. Pornire Aplicație

1. În terminal, rulați:

   ```bash
   npm start
   ```

2. Veți vedea mesajul: `Server running on http://localhost:3000`.

## 5. Utilizare

1. Deschideți un browser la adresa [http://localhost:3000](http://localhost:3000).
2. Selectați data (doar zilele de Miercuri sunt valide).
3. Alegeți un interval orar disponibil.
4. Completați formularul și salvați.

## Functionalități Automate

- **Raport Excel**: Este generat automat în fiecare Miercuri la ora 18:00 și trimis pe email.
- **Testare Manuală Email**: Puteți forța trimiterea raportului accesând în browser: `http://localhost:3000/api/test-email`.
