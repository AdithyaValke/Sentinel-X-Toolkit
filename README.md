# SentinelX

SentinelX is a desktop- and laptop-first security toolkit for authorized security analysis. It brings common data transforms, hash tools, an Analysis Lab, and persistent investigations into one web application. Some tools run locally in the browser; API-backed tools use the Flask service.

- Website: [sentinel-x-toolkit.vercel.app](https://sentinel-x-toolkit.vercel.app)
- Repository: [ShadowM300/Sentinel-X-Toolkit](https://github.com/ShadowM300/Sentinel-X-Toolkit)

## Features

### Common Tools

- **Base64, URL, and Hex:** encode and decode text.
- **Hash Tools:** calculate MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224/256/384/512, and SHAKE-128/256. SHAKE produces a fixed 32-byte output.
- **Identify Hash:** return likely algorithm candidates with evidence; results can be ambiguous and are not cryptographic verification.
- **JSON Formatter & Validator:** validate, format, or minify JSON in the browser.

### Chain Builder

Build ordered workflows of up to 10 Base64, URL, and Hex transformations. Review each step output; requests are limited to 10 KiB and each step output to 64 KiB.

### Analysis Lab

- **IoC Defanger & Sanitizer:** locally defang or refang common indicators.
- **Payload Generator:** create reference connectivity examples from validated addresses and ports. Examples are not executed by the app.
- **JWT Analyzer/Decoder:** inspect token structure and claims locally; optional HMAC verification supports HS256, HS384, and HS512.
- **IoC Extractor:** find potential IP, domain/URL, hash, and email indicators with context and counts; selected results can be saved to an investigation.
- **Security Headers Analyzer:** analyze pasted response headers locally; selected findings can be saved to an investigation.
- **Regex Tester & Pattern Analyzer:** test regular expressions with flags, match positions, and capture groups.

### Investigations

Authenticated users can create, edit, close, reopen, and delete investigations. Each workspace includes IOCs, findings, evidence, and a timeline. IoC Extractor and Security Headers Analyzer can save selected results to an investigation.

## Architecture

| Part | Technology and role |
|---|---|
| Frontend | Next.js, React, and TypeScript; deployed on Vercel |
| API | Flask on Render; serves stateless tools, authentication, and investigation APIs |
| Persistence | PostgreSQL via SQLAlchemy; schema changes use Alembic migrations |
| Authentication | Argon2id password hashes and opaque server-side sessions in HttpOnly cookies |
| Browser tools | JSON, regex, JWT review, header analysis, defanging, and payload reference generation run locally |

## Project Structure

```text
.
├── README.md
├── render.yaml
├── security-payload-workbench-backend/
│   ├── app.py
│   ├── database.py
│   ├── hash_identifier.py
│   ├── models.py
│   ├── alembic.ini
│   ├── migrations/
│   ├── requirements.txt
│   └── tests/
└── security-payload-workbench-dashboard/
    ├── app/                 # Next.js routes and global styles
    ├── components/          # Tool and shared UI components
    ├── lib/                 # API clients and tool logic
    ├── tests/
    ├── package.json
    └── pnpm-lock.yaml
```

## Local Setup

### Prerequisites

- Node.js and Corepack; the dashboard declares `pnpm@12.3.4` in `package.json`.
- Python and `venv`.
- PostgreSQL for authentication, sessions, and investigations. Stateless tools can run without it.

### Clone the repository

```powershell
git clone https://github.com/ShadowM300/Sentinel-X-Toolkit.git
cd Sentinel-X-Toolkit
```

### Configure PostgreSQL and start the backend

Create a local PostgreSQL database named `sentinelx`, then open a PowerShell terminal:

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

The backend also reads `DATABASE_URL` from its local `.env` file when the process variable is unset. Keep credentials out of source control. You can omit the database URL and migration command to use stateless tools only; authentication and investigations will be unavailable.

### Install and start the frontend (second terminal)

```powershell
cd security-payload-workbench-dashboard
Copy-Item .env.example .env.local
corepack pnpm install --frozen-lockfile
corepack pnpm dev
```

Open [http://localhost:3000](http://localhost:3000); the frontend example points to `http://localhost:8000`.

## Environment Variables

| Variable | Purpose | Requirement |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | Flask API base URL used by the browser; use the base URL without an endpoint path. | Optional in development (defaults to `http://localhost:8000`); required in production and must use HTTPS. |
| `DATABASE_URL` | PostgreSQL connection used by authentication, sessions, investigations, and migrations. | Optional for backend startup and stateless tools; required for database-backed operations. |
| `FRONTEND_ORIGIN` | Explicit frontend origin allowlist for CORS and auth requests; comma-separated origins are supported. | Defaults to localhost in development; required on Render. |
| `RATE_LIMIT_STORAGE_URI` | Shared Redis-compatible storage for rate limits. | Optional locally (memory storage is used); required on Render. |
| `API_RATE_LIMIT_PER_MINUTE` | Limit shared by public POST API routes. | Optional; defaults to `60` and must be a positive integer. |
| `PORT` | Backend listen port. | Defaults to `8000` locally; supplied by Render in deployment. |
| `SESSION_COOKIE_NAME`, `SESSION_LIFETIME_SECONDS` | Session cookie name and lifetime. | Optional; default to `sentinelx_session` and `604800` seconds. |
| `RENDER` | Enables production settings, including secure session cookies and required production configuration. | Set by Render. |

## Database and Availability

PostgreSQL stores authentication/session and investigation data. Those features require a working database; stateless tools can continue operating without PostgreSQL. The `/health` endpoint does not query the database, and recognized database availability failures return controlled HTTP 503 responses. If `DATABASE_URL` is removed from the deployment environment, restore it to re-enable database-backed features. Once PostgreSQL is reachable again, the backend can reconnect without a code change.

## API Overview

- `GET /health` reports backend availability without checking PostgreSQL.
- Stateless tools use `/api/process`, `/api/chain`, `/api/identify-hash`, and `/api/extract-iocs`.
- Authentication routes are under `/api/auth`; investigation routes are under `/api/investigations` and require authentication and ownership checks.

## Authentication

Passwords are stored as Argon2id hashes. Sessions use opaque tokens stored server-side, with only a hash of each token kept in PostgreSQL. Browser cookies are HttpOnly, scoped to `/api`, and use Secure cookies in Render production. Investigation access is authenticated and limited to records owned by the current user.

## Security

- API request bodies are limited to 10 KiB and inputs are validated.
- CORS uses explicit HTTP(S) origins; wildcard origins are rejected.
- Public POST endpoints share a per-client moving-window rate limit. Render requires Redis-compatible shared storage; rate-limit storage failures fail closed.
- The API adds `X-Content-Type-Options: nosniff`, disables API response caching, and returns generic unexpected-error responses. The frontend configures a Content Security Policy and additional browser security headers.
- Rate limiting does not trust `X-Forwarded-For`; database availability failures return 503 without exposing infrastructure details.
- Use SentinelX only with data and systems you are authorized to analyze. Hash identification is heuristic; it does not prove an algorithm or verify a digest.

## Testing

Run commands from the relevant application directory:

```powershell
# Frontend
corepack pnpm test
corepack pnpm exec tsc --noEmit
corepack pnpm build

# Backend
python -m pytest -q
```

## Deployment

- **Vercel:** deploy the Next.js frontend from `security-payload-workbench-dashboard/` and set `NEXT_PUBLIC_API_URL` to the HTTPS backend base URL.
- **Render:** deploy the Flask service using the root `render.yaml`; it installs `requirements.txt`, starts Gunicorn, and uses `/health` for its health check.
- **Services:** configure `FRONTEND_ORIGIN`, `RATE_LIMIT_STORAGE_URI`, and `DATABASE_URL` on the backend. Render production requires explicit frontend CORS configuration and shared Redis-compatible rate-limit storage.

## Troubleshooting

- **API connection errors:** confirm the backend is running and that `NEXT_PUBLIC_API_URL` is the base URL, without an API path suffix.
- **CORS errors:** set `FRONTEND_ORIGIN` to the exact browser origin, including scheme and port where applicable.
- **Auth or investigations return 503:** check that PostgreSQL is available and `DATABASE_URL` is configured.
- **Migration errors:** set `DATABASE_URL`, activate the backend virtual environment, and run `python -m alembic upgrade head` from the backend directory.
- **Render startup or 503 errors:** check `FRONTEND_ORIGIN` and confirm `RATE_LIMIT_STORAGE_URI` points to a reachable Redis-compatible service.
- **Requests return 429:** the public POST API limit is shared; wait for requests to age out of the window or adjust the positive `API_RATE_LIMIT_PER_MINUTE` value.

## License

No license file or license terms are currently included in the repository.
