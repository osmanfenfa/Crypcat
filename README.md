# Crypca

`Crypca` is a FastAPI web toolkit.

## Features

1. Password strength auditor with entropy, pattern checks, and crack-time estimates.
2. Hash identifier plus offline dictionary cracking for common digest algorithms.
3. File encryption/decryption using `cryptography` (Fernet + PBKDF2 key derivation).
4. Brute-force simulation for authorized local testing scenarios.
5. Secure password generator with policy enforcement controls.

## Files (all in one directory)

- `app.py`
- `database.py`
- `security_core.py`
- `schemas.py`
- `index.html`
- `style.css`
- `script.js`
- `requirements.txt`

## PostgreSQL Setup

1. Create a database:

2. Set environment variable (PowerShell):

```powershell
$env:DATABASE_URL="postgresql://postgres:YOUR_PASSWORD@localhost:5432/sabilok_db"
```

The app creates `security_logs` table automatically on startup.

## Run

1. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

2. Start the app:

```powershell
uvicorn app:app --reload
```

3. Open:

`http://127.0.0.1:8000`

## Notes

- For safety, logs store summaries and metadata, not raw plaintext passwords.
- Use cracking/simulation features only on systems and data you are authorized to test.
- If PostgreSQL is down, the app still starts in degraded mode and logging is paused until DB reconnect succeeds.

## Troubleshooting PostgreSQL Timeout

If you see `psycopg.errors.ConnectionTimeout` to `localhost:5432`:

1. Confirm PostgreSQL service is running.

```powershell
Get-Service *postgres*
```

2. Start your PostgreSQL service (service name can vary, example below).

```powershell
Start-Service postgresql-x64-16
```

3. Verify port 5432 is reachable.

```powershell
Test-NetConnection localhost -Port 5432
```

4. Check your DB URL before running Uvicorn.

```powershell
$env:DATABASE_URL="postgresql://postgres:YOUR_PASSWORD@localhost:5432/sabilok_db"
```