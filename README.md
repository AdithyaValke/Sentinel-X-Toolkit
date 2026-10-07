# SentinelX

SentinelX is a security toolkit for authorized analysis. It combines browser-based tools, a Flask API, and persistent investigation workspaces. PostgreSQL is used for accounts and investigations; stateless tools can run without it.

- **Live application:** [sentinel-x-toolkit.vercel.app](https://sentinel-x-toolkit.vercel.app)
- **Repository:** [ShadowM300/Sentinel-X-Toolkit](https://github.com/ShadowM300/Sentinel-X-Toolkit)

## Features

### Common tools

Base64, URL, and Hex encoding/decoding; JSON formatting, validation, and minification; hash conversion for MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224/256/384/512, and SHAKE-128/256. SHAKE output is fixed at 32 bytes. Identify Hash suggests candidates heuristically and cannot prove an algorithm.

### Chain Builder

Chain Base64, URL, and Hex transformations in order. Chains allow up to 10 steps, requests up to 10 KiB, and each step's output up to 64 KiB.

### Analysis Lab

- **IoC Defanger & Sanitizer:** Defang or refang indicators locally.
- **Payload Generator:** Generate reference connectivity examples from validated addresses and ports; SentinelX does not execute them.
- **JWT Analyzer/Decoder:** Inspect JWT structure and claims locally; optionally verify HMAC using HS256, HS384, or HS512.
- **IoC Extractor:** Detect potential IPs, domains/URLs, hashes, and email addresses with context and occurrence counts; save selected results to investigations.
- **Security Headers Analyzer:** Analyze pasted response headers locally; save selected findings to investigations.
- **Regex Tester & Pattern Analyzer:** Test expressions, flags, matches, positions, and capture groups.

### Investigations

Authenticated users can manage investigation workspaces containing IOCs, findings, evidence, and timeline events. Investigations support editing, close/reopen, deletion, and ownership enforcement. Supported analysis tools can save their results to an investigation.

## Architecture

| Component | Technology / purpose |
|---|---|
| Frontend | Next.js, React, and TypeScript; deployed on Vercel |
| API | Flask; stateless processing, authentication, and investigation APIs |
| Database | PostgreSQL via SQLAlchemy; users, sessions, and investigation data |
| Migrations | Alembic |
| Authentication | Argon2id password hashes and opaque server-side sessions |
| Rate limiting | Flask-Limiter with Redis-compatible shared storage in production |
| Backend hosting | Render |

## Project Structure

```text
.
├── render.yaml
├── security-payload-workbench-backend/  # Flask API, Alembic, tests
└── security-payload-workbench-dashboard/ # Next.js app, components, tests
```

The directory names are legacy internal paths; public-facing branding is SentinelX.

## Local Setup

### Prerequisites and clone

Install Node.js with Corepack, pnpm 12.3.4, Python with `venv`, and PostgreSQL for authentication and investigations.

```powershell
git clone https://github.com/ShadowM300/Sentinel-X-Toolkit.git
cd Sentinel-X-Toolkit
```

### Backend

Create a local PostgreSQL database named `sentinelx`, then run in PowerShell:

```powershell
cd security-payload-workbench-backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
$env:DATABASE_URL = "postgresql+psycopg://USER:PASSWORD@localhost:5432/sentinelx"
$env:FRONTEND_ORIGIN = "http://localhost:3000"
$env:PORT = "8000"
python -m alembic upgrade head
python app.py
```

The backend reads `DATABASE_URL` from its local `.env` if the process environment does not set it. Without a database URL, the backend starts with stateless tools available; authentication and investigations are unavailable.

### Frontend

In a second PowerShell terminal:

```powershell
cd security-payload-workbench-dashboard
Copy-Item .env.example .env.local
corepack pnpm install --frozen-lockfile
corepack pnpm dev
```

Open `http://localhost:3000`. The example frontend configuration targets the local API at `http://localhost:8000`.

## Environment Variables

### Backend

| Variable | Purpose and requirement |
|---|---|
| `DATABASE_URL` | PostgreSQL connection for auth, sessions, investigations, and migrations. Optional for startup/stateless tools; required for database-backed operations. |
| `FRONTEND_ORIGIN` | Explicit CORS/auth origin allowlist; comma-separated values are supported. Required in production; production origins must use HTTPS. |
| `RATE_LIMIT_STORAGE_URI` | Redis-compatible shared rate-limit store. Optional locally (memory storage); required on Render. |
| `API_RATE_LIMIT_PER_MINUTE` | Shared per-minute limit for public POST APIs; defaults to `60`. |
| `TRUST_CLOUDFLARE_CLIENT_IP` | Defaults to `false`. Set to `true` only when origin ingress is separately restricted to Cloudflare; then the API validates `CF-Connecting-IP`. `X-Forwarded-For` is never trusted. |
| `PORT` | API listen port; defaults to `8000` locally and is supplied by Render. |
| `SESSION_COOKIE_NAME` | Session cookie name; defaults to `sentinelx_session`. |
| `SESSION_LIFETIME_SECONDS` | Session lifetime; defaults to `604800` seconds. |
| `RENDER` | Set by Render; enables production settings such as secure session cookies and required production configuration. |

### Frontend

| Variable | Purpose and requirement |
|---|---|
| `NEXT_PUBLIC_API_URL` | Flask API base URL without an endpoint path. Defaults to localhost in development; required and HTTPS-only in production. |

## Database and Availability

PostgreSQL stores user accounts, authentication sessions, investigations, IOCs, findings, evidence, and timeline events. Stateless tools do not require PostgreSQL. `/health` does not query the database; stateless APIs remain usable during a database outage. Recognized database availability failures return HTTP `503` without exposing infrastructure details. The backend reconnects when PostgreSQL returns; restore `DATABASE_URL` if its configuration was removed.

## API Overview

| Endpoint | Purpose |
|---|---|
| `GET /health` | Backend availability check |
| `/api/process` | Base64, URL, Hex, hash conversion, and related processing |
| `/api/chain` | Chained transformations |
| `/api/identify-hash` | Heuristic hash candidates |
| `/api/extract-iocs` | Potential indicator extraction |
| `/api/auth/*` | Registration, login, logout, and session handling |
| `/api/investigations/*` | Authenticated investigation management |

Database-backed endpoints require an authenticated session where applicable.

## Authentication and Security

SentinelX uses Argon2id password hashing, opaque server-side sessions with only token hashes stored in PostgreSQL, secure HttpOnly production cookies, session expiration/revocation, and investigation ownership checks. Child investigation resources are scoped through their parent investigation.

Controls include a 10 KiB API request limit, input validation and bounded resources, explicit CORS origins, HTTPS production origins, origin checks for authenticated state-changing requests, Redis-backed production rate limits, safe client-IP handling, generic unexpected-error responses, `nosniff`, no-store API responses, Content Security Policy and browser security headers. The server does not fetch arbitrary URLs or execute application-supplied commands. Use SentinelX only with systems and data you are authorized to analyze.

## Testing

Run from each application directory:

```powershell
# Frontend
corepack pnpm test
corepack pnpm exec tsc --noEmit
corepack pnpm build

# Backend
python -m pytest -q
```

If Windows permissions prevent pytest from enumerating the system temporary directory, run from the backend directory with its virtual environment and an ignored local temp path:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp .pytest-tmp\pytest-validation
```

## Deployment

### Vercel

Deploy the Next.js application from `security-payload-workbench-dashboard/`. Set `NEXT_PUBLIC_API_URL` to the HTTPS Flask API base URL, without an endpoint suffix.

### Render

The Flask service is configured by the root `render.yaml`; it installs backend requirements, starts Gunicorn, and checks `/health`. Configure `DATABASE_URL`, `FRONTEND_ORIGIN`, and `RATE_LIMIT_STORAGE_URI` in the Render service environment. Production frontend origins must use HTTPS, and production rate limiting requires reachable Redis-compatible storage.

Render Free does not automatically run Alembic migrations in this configuration. When a deployment requires a schema migration, run it manually against the production database before relying on the new schema. From the backend directory, with the intended production `DATABASE_URL` set:

```powershell
python -m alembic upgrade head
```

Never commit production credentials.

## Troubleshooting

- **Frontend cannot reach the API:** Check that the backend is running and `NEXT_PUBLIC_API_URL` is the base URL without an API path.
- **CORS errors:** Match `FRONTEND_ORIGIN` to the browser's exact origin, including scheme and port.
- **Authentication or investigation `503`:** Check PostgreSQL availability and `DATABASE_URL`; stateless tools should remain available.
- **Migration errors:** Run `python -m alembic upgrade head` from the backend directory with the intended `DATABASE_URL`.
- **Render startup/rate-limit errors:** Check `FRONTEND_ORIGIN`, `DATABASE_URL`, `RATE_LIMIT_STORAGE_URI`, Redis availability, and service logs.
- **`429 Too Many Requests`:** Wait for the rate-limit window to expire or adjust the positive `API_RATE_LIMIT_PER_MINUTE` value.

## License

No license file or license terms are included in the repository.
