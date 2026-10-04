# Payload Workbench

Payload Workbench is a security-focused utility workspace for encoding and decoding text, generating common hashes, reviewing likely hash formats, and working with indicators and network-security references. The web interface is built with Next.js and TypeScript; API-backed operations use a separate Flask service.

**Live application:** [payload-workbench.vercel.app](https://payload-workbench.vercel.app)

**Source repository:** [ShadowM300/Payload-Workbench](https://github.com/ShadowM300/Payload-Workbench) (the repository's configured Git remote)

## Contents

- [Features](#features)
- [Live demo and services](#live-demo-and-services)
- [Technology stack](#technology-stack)
- [Architecture and API](#architecture-and-api)
- [Project structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Local setup and development](#local-setup-and-development)
- [Environment variables](#environment-variables)
- [API reference](#api-reference)
- [Security and responsible use](#security-and-responsible-use)
- [Testing and build](#testing-and-build)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Limitations and proposed work](#limitations-and-proposed-work)
- [License](#license)

## Features

The shared application shell provides navigation to the workspace tools, a global search for pages and tools, responsive sidebar navigation, light/dark/system theme selection, and a status indicator that checks the Flask health endpoint.

### Dashboard

The dashboard links to Payload Tools, Hash Tools, Identify Hash, and Security Lab. It displays the current API health status and a recent-activity panel populated with **sample, non-persistent data**; it is not a stored activity log.

### Payload Tools

Encode and decode UTF-8 text using Base64, URL percent-encoding, and hexadecimal. Each operation is sent to the Flask API. The page includes input and output buffers, character counts, validation and request status, clear/copy controls, and the configured API health status.

### Chain Builder

Build ordered pipelines of up to 10 Base64, URL, and hex string transformations. Outputs are shown after each successful step, with copy controls and quick presets. Each request has a 10 KiB body limit; a step output above 64 KiB is rejected.

### Hash Tools

Generate a digest from input text using MD5, SHA-256, or SHA-512. Hashing happens in the Flask service. MD5 is included for legacy compatibility; it is not suitable for security-sensitive password storage.

### Identify Hash

Submit one or more candidate strings for format-based analysis. The backend checks lengths, character sets, and known prefixes/structured formats, then returns likely candidates and evidence. It can identify patterns associated with common raw digests (including CRC32/CRC32b, MySQL, MD4, MD5, NTLM, SHA-family, RIPEMD-160, SHA-3, and BLAKE2 forms) and password-hash formats such as bcrypt, Argon2, scrypt, and Unix crypt variants.

This is a heuristic, not cryptographic verification: different algorithms can produce the same length and character format. Results can be ambiguous, and should be checked against the system or data format that produced the value. The feature does not crack hashes or recover their original input.
Identify Hash accepts up to 50 non-empty lines per request.

### Security Lab

The Security Lab has an overview/catalog, an **IoC Defanger & Sanitizer** tool, a **Payload Generator**, a **JWT Decoder** tab, and a **Planned Modules** tab.

- **IoC Defanger & Sanitizer** detects simple indicator patterns (such as IP addresses, email addresses, and domains) and locally defangs or refangs text. It replaces URL schemes and separators such as dots and @; it does not call the Flask API.
- **Payload Generator (reference generator)** validates an IP address and port, then renders platform-specific TCP connectivity, port-open, or HTTP reachability examples. Listener setup and socat relay outputs are static, commented reference templates. Generation is local in the browser: the application does not execute the displayed commands or make network connections. If a user copies and runs a connectivity example, that example can contact its configured target; use only authorized lab systems.
- **JWT Decoder and Analyzer** decodes a pasted JWT in the browser and reviews the header, claims, timestamps, signature algorithm, key-source headers, key ID, and sensitive-looking payload keys. It flags unsigned/empty signatures, expired tokens, future nbf/iat values, non-numeric timestamps, missing exp/iss/aud/sub claims, lifetimes longer than one year, unexpected token type, HMAC shared-secret algorithms, and asymmetric algorithm policy. It also warns about jku, x5u, jwk, x5c, kid, and payload keys that look like passwords, secrets, SSNs, or card data. It is a defensive aid, not a token validator or a security guarantee.
- JWT contents are Base64URL encoded, not encrypted. Decoding and optional HMAC verification use browser-side code and Web Crypto only. The pasted token and verification secret remain in the mounted panel's React state; they are not sent to a server or stored in browser persistence. HMAC verification supports HS256, HS384, and HS512 only; asymmetric algorithms require a public key and are not verified by this panel. A matching HMAC signature does not establish that the issuer, audience, claims, or authorization policy are trustworthy.
- **Planned Modules** currently shows PCAP Inspector and YARA Validator as unreleased roadmap items. They are informational cards, not working tools.

The global search supports title/description/keyword matching and keyboard navigation. Ctrl+K or ⌘K focuses search; arrow keys move through results, Enter opens the selected result, and Escape closes the result list. Theme selection is saved in browser storage and follows the operating-system preference when set to System.

## Live demo and services

- Frontend: [https://payload-workbench.vercel.app](https://payload-workbench.vercel.app)
- Flask health endpoint: [https://payload-workbench.onrender.com/health](https://payload-workbench.onrender.com/health)

The frontend deployment URLs are provided for this project; their current availability is not guaranteed by this repository. Payload encoding/decoding, hashing, hash identification, and the shared API health indicator require the Flask backend to be reachable. The IoC sanitizer, Payload Generator, and JWT Decoder operate locally in the browser.

## Technology stack

- **Frontend:** Next.js 16, React 19, TypeScript 5.7, Tailwind CSS 4, PostCSS
- **UI utilities:** Base UI, class-variance-authority, clsx, tailwind-merge, and lucide-react
- **Backend:** Python, Flask 3, Flask-CORS, Flask-Limiter with Redis support, and Gunicorn
- **Tests:** Node.js built-in test runner for frontend utility/API tests; pytest for Flask API tests
- **Deployment configuration:** render.yaml configures a Python web service on Render. The frontend is a Next.js application configured for deployment with Vercel by setting its project root to the dashboard directory.

Dependency versions are declared in the dashboard package.json, pnpm-lock.yaml, and backend requirements.txt.

## Architecture and API

The browser calls the Flask service using the base URL in NEXT_PUBLIC_API_URL. Payload/hash processing uses POST /api/process; operation pipelines use POST /api/chain; hash-format analysis also has a dedicated POST /api/identify-hash endpoint. The frontend health indicator calls GET /health. Security Lab indicator sanitization and reference generation are client-side.

~~~mermaid
flowchart LR
    U[Browser] --> N[Next.js frontend]
    N -->|GET /health| F[Flask API]
    N -->|POST /api/process and /api/chain| F
    N -->|POST /api/identify-hash| F
    F -->|Shared rate-limit state in production| R[(Redis-compatible store)]
    N -. local-only tools .-> L[IoC sanitizer and reference generator]
~~~

render.yaml configures the backend root directory, install/start commands, and /health health-check path. The public processing and identification endpoints share a moving-window rate limit. Production on Render requires shared Redis-compatible rate-limit storage.

## Project structure

~~~text
.
├── README.md
├── render.yaml
    ├── security-payload-workbench-backend/
│   ├── app.py
│   ├── hash_identifier.py
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── tests/
│       └── test_app.py
└── security-payload-workbench-dashboard/
    ├── app/                 # Next.js routes and global styles
    ├── components/          # Shared shell and page components
    ├── lib/                 # API client, operations, search, and utilities
    ├── public/              # Static assets
    ├── tests/               # Frontend utility and API tests
    ├── package.json
    ├── pnpm-lock.yaml
    └── .env.example
~~~

Frontend routes are /dashboard, /payload-tools, /chain-builder, /hash-tools, /identify-hash, and /security-lab.

## Prerequisites

- Node.js 20.9 or newer for the Next.js version used here. The documented frontend test command uses Node's built-in TypeScript stripping flag, available in Node 22.6 or newer.
- Corepack and pnpm 12.3.4, as declared by the frontend package manifest.
- Python 3.10 or newer for the backend's type syntax. The repository does not pin a Python patch version.
- A Redis-compatible service is required for the Render production backend. Local development defaults to in-memory rate-limit storage.

## Local setup and development

Run the backend and frontend in separate terminals. The commands below use PowerShell from the repository root.

### 1. Start the Flask API

~~~powershell
cd security-payload-workbench-backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

# Optional: these are the local defaults shown in .env.example.
$env:FRONTEND_ORIGIN = "http://localhost:3000"
$env:PORT = "8000"
python app.py
~~~

The API listens on http://localhost:8000 by default. The Flask app does not load .env files itself; configure variables in the shell or your deployment environment. Runtime dependencies include Flask, Flask-CORS, Flask-Limiter with its Redis extra, and Gunicorn. Install `requirements-dev.txt` to add pytest for local testing.

### 2. Start the Next.js frontend

In a second terminal:

~~~powershell
cd security-payload-workbench-dashboard
Copy-Item .env.example .env.local
corepack pnpm install --frozen-lockfile
corepack pnpm dev
~~~

Open [http://localhost:3000](http://localhost:3000). The example .env.local points the frontend at http://localhost:8000. Restart the development server after changing environment variables.

## Environment variables

| Variable | Purpose and use | Required? | Safe local example / production setting |
|---|---|---|---|
| NEXT_PUBLIC_API_URL | Frontend API base URL used for /health and /api/... requests. It is exposed to the browser bundle. | Optional in development (falls back to http://localhost:8000); required in production when API features are used. | http://localhost:8000; production: https://your-render-service.onrender.com |
| FRONTEND_ORIGIN | Flask-CORS allowlist. Accepts comma-separated explicit HTTP(S) origins, without paths or wildcards. | Defaults to http://localhost:3000 locally; required when running on Render. | http://localhost:3000; production: https://payload-workbench.vercel.app |
| API_RATE_LIMIT_PER_MINUTE | Positive integer request limit per client IP, shared by both POST API endpoints. | Optional; defaults to 60. | 60 |
| RATE_LIMIT_STORAGE_URI | Flask-Limiter storage backend. | Optional locally (defaults to process memory); required on Render and must use a Redis-compatible redis://, rediss://, or redis+cluster:// URI. | Local example: redis://localhost:6379/0; production: private Redis-compatible URL from Render |
| PORT | Port used by python app.py; Render supplies this to Gunicorn. | Optional locally; defaults to 8000. | 8000 |
| NODE_ENV | Next.js environment mode; the API client uses production mode to require an explicit API base URL. | Managed by Next.js; do not normally set manually. | Set automatically by dev/build/start commands |
| RENDER | Enables Render-specific CORS, proxy-IP, and production rate-limit storage requirements in Flask. | Set by Render; do not set manually for local development. | Set automatically by Render |

On Render, the platform sets RENDER; the app uses it to require an explicit CORS origin and Redis-compatible rate-limit storage. Do not set RATE_LIMIT_STORAGE_URI to memory:// in production. Keep production storage URLs private, and do not put credentials in NEXT_PUBLIC_API_URL.

## API reference

All processing requests must use Content-Type: application/json. The API limits request bodies to 10 KiB. The two POST endpoints share the configured per-IP moving-window limit.

### GET /health

Returns 200 with:

~~~json
{ "status": "ok" }
~~~

### POST /api/process

Required JSON fields are input_text (string) and operation (string). For operation: "hash", include hash_algorithm (string).

~~~json
{
  "input_text": "hello",
  "operation": "hash",
  "hash_algorithm": "SHA-256"
}
~~~

Supported operation values:

| Operation | Behavior | Additional field |
|---|---|---|
| base64_encode / base64_decode | Encode UTF-8 text or strictly decode Base64 bytes as UTF-8. | — |
| url_encode / url_decode | Percent-encode or decode text. | — |
| hex_encode / hex_decode | Encode UTF-8 bytes as hex or decode hex bytes as UTF-8. | — |
| hash | Generate an MD5, SHA-256, or SHA-512 digest. Algorithm names are case/space/hyphen normalized. | hash_algorithm |
| identify_hash | Analyze one or more lines for likely hash formats and candidates. | — |

A successful standard processing response is:

~~~json
{ "success": true, "result": "<string>", "error": null }
~~~

Invalid requests and invalid Base64/hex decode input return a JSON error response with success: false, an empty result, and an error message. Hash-identification responses also include analysis fields such as input_length, character_format, candidates, is_ambiguous, warning, recommendation, and (for multiline input) lines.

### POST /api/identify-hash

Accepts hash (string); input_text is also accepted as a fallback field. Empty input is rejected. The response contains the analysis summary, candidate matches with evidence/explanations, ambiguity/warning/recommendation fields, and per-line analysis when multiple non-empty lines are supplied.

Candidate identification uses format clues and structured prefixes. It does not verify a candidate by hashing a known input.

### POST /api/chain

Accepts `input_text` (string) and `steps` (a non-empty array of at most 10 objects, each containing only an `operation` string). Allowed operations are `base64_encode`, `base64_decode`, `url_encode`, `url_decode`, `hex_encode`, and `hex_decode`. Each transform reuses the corresponding `/api/process` implementation and feeds its string result into the next step. Hashing and hash identification are excluded.

~~~json
{"input_text":"hello world","steps":[{"operation":"url_encode"},{"operation":"base64_encode"}]}
~~~

A successful response contains each ordered result and the final value:

~~~json
{"steps":[{"operation":"url_encode","output":"hello%20world"},{"operation":"base64_encode","output":"aGVsbG8lMjB3b3JsZA=="}],"final":"aGVsbG8lMjB3b3JsZA=="}
~~~

Invalid requests, failed transforms, or output above 64 KiB UTF-8 at any step return HTTP 400. Step failures identify the zero-based step index; runtime errors use generic messages. Failed execution responses also include completed `steps` and `failed_step` so the UI can preserve earlier outputs.

### HTTP errors

- **400 Bad Request:** malformed/missing/invalid fields, unsupported operations/algorithms, empty identification input, or invalid Base64/hex.
- **404 Not Found** and **405 Method Not Allowed:** unknown paths and unsupported methods.
- **413 Request Entity Too Large:** request body exceeds 10 KiB.
- **415 Unsupported Media Type:** request is not JSON.
- **429 Too Many Requests:** shared API rate limit exceeded.
- **503 Service Unavailable:** trusted client IP cannot be verified in Render, or production rate-limit storage is unavailable.
- **500 Internal Server Error:** unexpected server error; response details are generic.

Error responses use the JSON shape { "success": false, "result": "", "error": "<message>" } where applicable. Rate-limit responses include limiter headers.

## Security and responsible use

- Flask-CORS allows only explicit HTTP(S) origins. The Render deployment requires FRONTEND_ORIGIN; wildcard and path-bearing origins are rejected.
- /api/process, /api/chain, and /api/identify-hash share a Flask-Limiter moving-window limit, which enforces the limit continuously across window boundaries. One chain call counts as one request. Render requires a shared Redis-compatible store; a storage outage fails closed with HTTP 503. Requests above the limit receive HTTP 429.
- In Render mode, the limiter validates the single CF-Connecting-IP address as the client IP and does not trust X-Forwarded-For. If that trusted header is missing or invalid, the request fails with HTTP 503. Outside Render, local/test use the socket peer address and do not trust forwarded headers.
- The request body is capped at 10 KiB; API inputs and required fields are validated, and unexpected server errors return a generic response.
- The app does not execute Security Lab output or initiate network connections for generated references. Manually running a generated reachability check is a separate action and can contact the entered host.
- Hash identification is heuristic and may return ambiguous candidates. MD5 is not appropriate for modern password storage; use a purpose-built password hashing scheme such as Argon2id or bcrypt for password storage.
- These controls describe the current implementation and do not guarantee that a deployment is secure against every threat.

### Render client IP assumption

The backend assumes all inbound Render traffic arrives through Cloudflare, which supplies `CF-Connecting-IP`. Rate-limited API routes fail closed with HTTP 503 if that header is missing or invalid. The API never trusts `X-Forwarded-For`.

## Testing and build

The frontend `test` script runs the Node.js built-in test runner. Commands below should be run from the indicated project directory.

~~~powershell
# Frontend: from security-payload-workbench-dashboard
corepack pnpm test
corepack pnpm exec tsc --noEmit
corepack pnpm build

# Backend: from security-payload-workbench-backend
python -m pip install -r requirements-dev.txt
python -m pytest -q
~~~

The backend test suite uses pytest and Flask's test client. It covers processing operations, chains and chain limits, hash identification, validation/error responses, CORS, rate limiting, and Render proxy/storage configuration. Frontend tests cover utilities, JWT parsing/findings/timestamps/HMAC verification, Security Lab tab parsing, chain step management and response validation, route mapping, search, API contracts, and latest-request behavior.

## Deployment

### Flask backend on Render

render.yaml sets the backend root to security-payload-workbench-backend, installs requirements.txt, starts Gunicorn with two workers and a 30-second timeout on the platform-provided $PORT, and uses /health as its health-check path. Revisit the worker count if the Render instance size changes. Configure:

1. FRONTEND_ORIGIN as the exact deployed frontend origin. For the supplied frontend URL, that is https://payload-workbench.vercel.app.
2. RATE_LIMIT_STORAGE_URI as the private internal connection URL for a Redis-compatible Render Key Value service. Keep it in the same region as the backend where possible.
3. API_RATE_LIMIT_PER_MINUTE as a positive integer if the default of 60 is not appropriate.

Confirm that Render reports the service healthy and that https://payload-workbench.onrender.com/health returns {"status":"ok"}.

### Next.js frontend on Vercel

Set the Vercel project root to security-payload-workbench-dashboard. Use the Next.js framework and pnpm lockfile. Set NEXT_PUBLIC_API_URL to the Flask service base URL (for the supplied deployment, https://payload-workbench.onrender.com, with no /api/process suffix), then build and deploy. Since this value is compiled into the browser bundle, redeploy after changing it.

When changing frontend domains, update Render's FRONTEND_ORIGIN to the exact origin and restart/redeploy the backend. Test an API operation and check that the health endpoint responds; browser requests also require the CORS origin to match exactly.

## Troubleshooting

- **API shown offline:** Open the configured API base URL with /health appended. Confirm the Flask service is running and returns {"status":"ok"}.
- **Frontend API or CORS errors:** Check NEXT_PUBLIC_API_URL for the service base URL (no endpoint suffix), then make FRONTEND_ORIGIN exactly match the browser's scheme, host, and port. Restart/redeploy after changes.
- **Production service fails to start:** On Render, verify FRONTEND_ORIGIN, a valid positive API_RATE_LIMIT_PER_MINUTE, and a private Redis-compatible RATE_LIMIT_STORAGE_URI. A missing or non-Redis storage URL prevents startup.
- **Requests return 429:** The per-IP moving-window request limit is shared by both POST endpoints. Wait until earlier requests age out of the window or set an appropriate positive limit.
- **Requests return 503:** Check that Render supplies a valid single CF-Connecting-IP value and that the Redis-compatible rate-limit store is available. Storage failures intentionally fail closed.
- **Dependency install or frontend build errors:** Use Node.js compatible with the Next.js requirement, Corepack with pnpm 12.3.4, and run the frozen-lockfile install from the dashboard directory. Install backend packages from requirements.txt.
- **Local Flask connection fails:** Start the backend on port 8000 and verify NEXT_PUBLIC_API_URL=http://localhost:8000 in .env.local.

## Limitations and proposed work

- Identify Hash reports candidates from formats and patterns, not proof of the algorithm.
- Dashboard recent activity is sample data and is not persisted.
- Planned Modules lists PCAP Inspector and YARA Validator as unreleased concepts; they are not implemented tools.

## License

No license file is present in the repository. No license terms are stated here.
