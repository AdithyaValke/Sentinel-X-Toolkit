# Payload Workbench

Payload Workbench is a small security utility with a Next.js, React, and TypeScript frontend and a Flask REST API. Encoding, decoding, and hashing requests are processed by Flask; the browser sends input text to the configured API.

## Requirements

- Python 3.10 or newer
- Node.js compatible with the Next.js version in `security-payload-workbench dashboard/package.json`
- pnpm 12.3.4, as declared by the frontend package manifest

## Run locally (PowerShell)

Open two terminals from the repository root.

### Flask API

```powershell
cd security-payload-workbench-backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

The API listens on `http://localhost:8000` by default. `PORT` can override this. Flask does not load `.env` automatically, so set environment variables in the shell when changing them:

```powershell
$env:FRONTEND_ORIGIN = "http://localhost:3000"
$env:PORT = "8000"
python app.py
```

### Next.js frontend

```powershell
cd "security-payload-workbench dashboard"
Copy-Item .env.example .env.local
corepack pnpm install --frozen-lockfile
corepack pnpm dev
```

`.env.local` sets `NEXT_PUBLIC_API_URL=http://localhost:8000`. Restart the Next.js server after changing it. Open `http://localhost:3000`.

## API

`POST /api/process` accepts JSON with `input_text` and `operation`; hash requests also provide `hash_algorithm`.

```json
{
  "input_text": "hello",
  "operation": "hash",
  "hash_algorithm": "SHA-256"
}
```

Supported operations are `base64_encode`, `base64_decode`, `url_encode`, `url_decode`, `hex_encode`, `hex_decode`, `hash`, and `identify_hash`. Supported hash names for hashing are MD5, SHA-256, and SHA-512 (case and hyphens are normalized). Responses have `{ "success": boolean, "result": string, "error": string | null }`. Validation failures use 400, a wrong content type uses 415, and requests over 10 KiB use 413. The API health check is `GET /health`.

### Hash Identification (`identify_hash` and `POST /api/identify-hash`)

The **Identify Hash Function** analyzes candidate cryptographic algorithms and password formats based on digest length, character sets, and structured prefixes.

#### Request via `/api/process`

```json
{
  "input_text": "5d41402abc4b2a76b9719d911017c592",
  "operation": "identify_hash"
}
```

#### Dedicated Endpoint: `POST /api/identify-hash`

```json
{
  "hash": "5d41402abc4b2a76b9719d911017c592"
}
```

#### Response Structure

```json
{
  "success": true,
  "result": "Matches: MD5 (Hashcat: 0), NTLM (Hashcat: 1000), or MD4 (Hashcat: 900)",
  "error": null,
  "input_length": 32,
  "character_format": "hexadecimal",
  "candidates": [
    {
      "algorithm": "MD5",
      "hashcat_mode": "0",
      "evidence": "length_and_format_match",
      "explanation": "Input is 32 hexadecimal characters (128-bit), consistent with a raw MD5 digest."
    },
    {
      "algorithm": "NTLM",
      "hashcat_mode": "1000",
      "evidence": "length_and_format_match",
      "explanation": "NTLM representations are also 32 hexadecimal characters (MD4 of UTF-16LE)."
    },
    {
      "algorithm": "MD4",
      "hashcat_mode": "900",
      "evidence": "length_and_format_match",
      "explanation": "MD4 produces 32 hexadecimal characters; common in legacy systems and protocols."
    },
    {
      "algorithm": "LM",
      "hashcat_mode": "3000",
      "evidence": "length_and_format_match",
      "explanation": "LAN Manager (LM) hashes are 32 hexadecimal characters (two 7-byte DES halves)."
    }
  ],
  "is_ambiguous": true,
  "warning": "Digest length and character format alone cannot definitively identify a hash algorithm. Multiple cryptographic algorithms produce identical output lengths.",
  "recommendation": "Verify candidate algorithm using application context, database schema, prefix markers, or source code configuration."
}
```

#### Supported Formats and Heuristics

- **Raw Hexadecimal Digests:**
  - 8 characters: CRC32, CRC32b (Hashcat: 11500)
  - 16 characters: MySQL 3.23 (Hashcat: 200)
  - 32 characters: MD5 (Hashcat: 0), NTLM (Hashcat: 1000), MD4 (Hashcat: 900), LM (Hashcat: 3000)
  - 40 characters: SHA-1 (Hashcat: 100), MySQL 4.1+/5+ (Hashcat: 300), RIPEMD-160 (Hashcat: 6000)
  - 41 characters with `*`: MySQL 4.1+/5+ standard format (`*` + 40 hex chars)
  - 56 characters: SHA-224 (Hashcat: 1300), SHA-512/224
  - 64 characters: SHA-256 (Hashcat: 1400), SHA-512/256, SHA3-256 (Hashcat: 17400), BLAKE2s-256
  - 96 characters: SHA-384 (Hashcat: 10800), SHA3-384 (Hashcat: 17500)
  - 128 characters: SHA-512 (Hashcat: 1700), SHA3-512 (Hashcat: 17600), BLAKE2b-512
- **Password & Modular Crypt Formats:**
  - `bcrypt`: Recognizable `$2a$`, `$2b$`, or `$2y$` prefixes, 60-character length (Hashcat: 3200)
  - `Argon2`: Recognizable `$argon2id$`, `$argon2i$`, or `$argon2d$` structured prefixes (Hashcat: 25300)
  - `scrypt`: Documented `$7$` or `$scrypt$` modular crypt prefixes (Hashcat: 8900)
  - `Unix Crypt`: `$1$` (MD5-crypt, Hashcat: 500), `$5$` (SHA-256-crypt, Hashcat: 7400), `$6$` (SHA-512-crypt, Hashcat: 1800), DES-crypt (13 characters from `[a-zA-Z0-9./]`, Hashcat: 1500)
- **Multiline Input:** Multiple hashes separated by newlines are analyzed line-by-line independently.

#### Known Limitations and Ambiguity Principles

- **Heuristic Nature:** Hash identification is format-based and deterministic, but cannot definitively prove which algorithm produced a raw digest. Many distinct algorithms output identical digest lengths (e.g., MD5 and NTLM are both 32 hexadecimal characters).
- **No Cryptographic Guarantee:** The presence of a recognized structure or prefix does not verify that the hash is authentic, unmodified, or computationally valid.
- **Verification Recommendation:** Always cross-reference candidates with application context, configuration files, database column names, or password policy settings.

Example:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/process -ContentType "application/json" -Body '{"input_text":"5d41402abc4b2a76b9719d911017c592","operation":"identify_hash"}'
Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/identify-hash -ContentType "application/json" -Body '{"hash":"$2a$12$e8KERg7gm.bQ1qV8q6uP5.9M5M.x2Y7Wv0.qP4P.r8X1V3Z2Y7Wv0"}'
Invoke-RestMethod http://localhost:8000/health
```

## Tests and production build

```powershell
cd security-payload-workbench-backend
python -m pip install -r requirements.txt
python -m pytest -q
cd "..\security-payload-workbench dashboard"
corepack pnpm install --frozen-lockfile
corepack pnpm exec tsc --noEmit
corepack pnpm build
```

The backend test suite uses pytest, included in `requirements.txt` for this mini project.

## Deploy the Flask backend to Render

1. Create a Render Web Service from this repository and use the repository `render.yaml` Blueprint configuration, or configure the service manually.
2. The service root is `security-payload-workbench-backend`; build with `pip install -r requirements.txt` and start with `gunicorn --bind 0.0.0.0:$PORT app:app`.
3. Set `FRONTEND_ORIGIN` to the exact deployed frontend origin (scheme and hostname, no path), for example `https://your-frontend.example`. The app refuses to start on Render without this setting. `GET /health` is the health-check path.
4. Wait for Render to report the service healthy. Use the service URL Render assigns; no backend URL is assumed here.

## Deploy the Next.js frontend to Vercel

1. Import this repository into Vercel and set the project root to `security-payload-workbench dashboard`.
2. Use the Next.js framework preset and the package manifest scripts. Vercel should install with pnpm from `pnpm-lock.yaml`.
3. Set `NEXT_PUBLIC_API_URL` to the actual Render service base URL, without `/api/process` (for example, the URL shown in your Render dashboard).
4. Deploy. If you use a custom frontend domain, update the backend's `FRONTEND_ORIGIN` to that exact origin and redeploy/restart the API.
5. Visit the deployed site, process an input, then check the browser Network panel for a successful request to `/api/process`. Also open the deployed backend's `/health` endpoint.

## Troubleshooting

- **CORS errors:** Set `FRONTEND_ORIGIN` to the exact browser origin, including `https://` and any non-default port. For multiple approved origins, separate them with commas. Restart the backend after changes.
- **Health check fails:** Confirm Render starts `app:app` from the backend root, has `gunicorn` installed, and binds to `$PORT`; inspect Render logs for missing `FRONTEND_ORIGIN` or dependency errors.
- **Frontend cannot reach Flask:** Check `NEXT_PUBLIC_API_URL`, confirm `/health` is reachable, and verify CORS allows the exact frontend origin. Since the variable is public and compiled into the client bundle, redeploy the frontend after changing it.
- **Local API connection fails:** Start Flask on port 8000 and confirm `.env.local` contains `NEXT_PUBLIC_API_URL=http://localhost:8000`.
- **Install/build fails:** Use the pnpm version declared in `package.json` and install from the frontend project root with the frozen lockfile.
