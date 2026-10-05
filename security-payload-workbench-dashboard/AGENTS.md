<!-- BEGIN:nextjs-agent-rules -->

# SentinelX — Agent Instructions

## Project Identity

This project is **SentinelX**, a general-purpose cybersecurity toolkit.

It was previously called **Payload Workbench**. Some internal directory names, package names, API/service names, and legacy references may still use the old name. Do not rename or restructure those automatically.

SentinelX is intended for students, developers, cybersecurity professionals, researchers, and authorized security testing.

The application contains defensive analysis tools, encoding/decoding utilities, hash analysis, JWT analysis, IoC analysis, and authorized security-reference utilities.

---

# 1. Core Engineering Rules

Before making changes:

1. Inspect the existing implementation.
2. Understand the current architecture and data flow.
3. Reuse existing components, utilities, types, API clients, and patterns.
4. Make the smallest change that correctly solves the requested problem.
5. Preserve existing functionality unless the user explicitly asks for a behavior change.
6. Do not perform broad rewrites or unnecessary refactors.
7. Do not replace working implementations with a new architecture without a clear reason.
8. Do not modify unrelated files.
9. Do not introduce dependencies unless they are genuinely necessary.
10. Do not remove existing security controls.
11. Do not weaken validation, rate limiting, CORS, CSP, request limits, or error handling to make a feature easier to implement.

When uncertain, inspect first rather than guessing.

---

# 2. Architecture

The repository contains two main applications.

## Frontend

Location:

`security-payload-workbench-dashboard/`

Stack:

* Next.js
* React
* TypeScript
* Tailwind CSS
* pnpm

The frontend is deployed separately from the Flask API.

Frontend responsibilities:

* UI
* navigation
* client-side tools
* local analysis
* API communication
* browser-only state
* user interaction

## Backend

Location:

`security-payload-workbench-backend/`

Stack:

* Python
* Flask
* Flask-CORS
* Flask-Limiter
* Redis-compatible rate-limit storage
* Gunicorn

Backend responsibilities:

* API-backed transformations
* hashing
* hash identification
* IoC extraction
* chain processing
* request validation
* rate limiting

Do not move a client-side feature to the backend unless there is a clear architectural/security reason.

Do not add a backend merely because it is possible.

---

# 3. Existing API

Current API endpoints include:

* `GET /health`
* `POST /api/process`
* `POST /api/chain`
* `POST /api/identify-hash`
* `POST /api/extract-iocs`

The API uses JSON.

Current request body limit:

* 10 KiB

Public POST API endpoints use the shared Flask-Limiter rate limit.

Production rate limiting uses a Redis-compatible shared store.

Do not bypass or weaken these protections.

---

# 4. API Client Rules

Frontend API calls should go through:

`lib/api.ts`

Do not scatter raw `fetch()` calls throughout components when an existing API helper is appropriate.

API clients must:

* use the configured API base URL
* use AbortController/timeouts for network requests
* validate response shapes
* handle non-JSON responses safely
* handle HTTP errors
* avoid exposing raw internal server errors
* support cancellation where appropriate

Do not trust API responses simply because TypeScript types say they are valid. Runtime validation is intentional.

---

# 5. Backend Security Rules

The backend is publicly reachable in production.

Treat all request data as untrusted.

Always validate:

* JSON structure
* field types
* allowed values
* collection sizes
* request size
* operation names
* algorithm names
* user-controlled strings

Never assume frontend validation is sufficient.

The backend must independently enforce security constraints.

---

# 6. CORS

Production CORS must remain explicit.

Never change production CORS to:

```text
*
```

Do not accept arbitrary origins.

`FRONTEND_ORIGIN` must remain an explicit HTTP(S) origin.

Do not introduce wildcard origins as a quick fix for frontend/API connectivity problems.

---

# 7. Client IP and Rate Limiting

Production Render traffic currently uses the trusted `CF-Connecting-IP` header.

Do not start trusting:

```text
X-Forwarded-For
```

or other arbitrary client-controlled forwarding headers.

The application intentionally fails closed when the trusted production client IP cannot be verified.

Do not change this behavior merely to make local testing easier.

Local/test behavior may use the socket peer address.

Production rate limiting must remain backed by shared Redis-compatible storage.

Do not configure production rate limiting to use process-local memory.

---

# 8. Request Limits

Current limits are intentional.

Backend request body limit:

`10 KiB`

Chain maximum:

`10 steps`

Chain per-step output maximum:

`64 KiB`

Hash identification:

`50 non-empty lines`

Do not remove or substantially increase these limits without a documented reason and corresponding resource/security analysis.

When adding a new API endpoint, establish explicit input and output limits.

---

# 9. Error Handling

Never expose:

* stack traces
* internal filesystem paths
* environment variables
* Redis connection details
* secrets
* exception messages that contain sensitive internals

Production API errors should remain generic.

Log useful diagnostic information server-side without logging user secrets or raw sensitive payloads.

Do not return arbitrary Python exception strings to users.

---

# 10. Security Headers

The frontend currently defines security headers in:

`next.config.mjs`

Existing protections include:

* Content-Security-Policy
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy
* X-Frame-Options

The production CSP intentionally does not allow `unsafe-eval`.

The current CSP uses `unsafe-inline` for compatibility with the existing Next.js/theme implementation.

Do not remove or weaken the CSP casually.

If improving CSP, prefer a proper nonce/hash-based strategy rather than simply adding more allowed sources.

Any CSP change must be tested against:

* development
* production build
* theme switching
* navigation
* Vercel analytics if still enabled
* API requests

Do not add `unsafe-eval` to production CSP.

---

# 11. SSRF / Network Safety

This is extremely important.

Do not add server-side network access based solely on user-supplied:

* URLs
* hostnames
* IP addresses
* ports
* domains
* webhook URLs
* callback URLs

Never make the backend automatically:

* fetch arbitrary URLs
* scan arbitrary hosts
* resolve arbitrary internal domains
* connect to arbitrary ports
* proxy arbitrary requests
* follow unrestricted redirects

unless the feature has been explicitly designed with appropriate SSRF protections.

If a future feature requires outbound network access, treat these as mandatory design concerns:

* private/internal IP blocking
* loopback blocking
* link-local blocking
* metadata-service blocking
* DNS rebinding protection
* redirect validation
* IPv4/IPv6 validation
* connection and read timeouts
* response-size limits
* protocol restrictions
* rate limiting
* audit logging
* authentication/authorization where appropriate

Do not implement a network-scanning feature as a simple `requests.get(user_url)` endpoint.

---

# 12. Command Execution

Never execute user-controlled commands.

Never use:

* `eval`
* `exec`
* `new Function`
* shell execution
* subprocess execution
* dynamic command construction

for user-provided security-tool input unless the user explicitly requests a carefully designed execution feature and the architecture has been reviewed for isolation and authorization.

The existing Payload/Reference Generator only produces reference commands. It must not execute them.

Preserve that behavior.

---

# 13. XSS Safety

Never introduce:

* `dangerouslySetInnerHTML`
* raw `innerHTML`
* unsafe HTML rendering
* unsanitized HTML from user input

unless absolutely necessary and accompanied by proper sanitization.

React's normal escaped rendering should be preferred.

Security-tool input may contain attacker-controlled text, HTML, JavaScript, shell syntax, or malicious payloads. Treat it as plain text.

---

# 14. Sensitive Data

Security tools may process:

* JWTs
* API tokens
* passwords
* secrets
* credentials
* hashes
* IP addresses
* domains
* emails
* incident logs
* security telemetry

Do not store sensitive user input unnecessarily.

Do not add sensitive input to:

* localStorage
* sessionStorage
* analytics
* Recent Activity
* URL query parameters
* server logs
* console logs
* error telemetry

unless explicitly required and clearly documented.

Recent Activity should contain only safe metadata such as:

* tool name
* operation
* success/failure
* generic description
* timestamp

Never put actual tokens, secrets, payloads, hashes, or raw IoCs into activity descriptions.

---

# 15. JWT Analyzer

JWT decoding is intentionally performed in the browser.

JWT payloads are encoded, not encrypted.

The analyzer is a defensive heuristic tool, not a complete JWT security validator.

Do not send pasted JWTs or HMAC secrets to the Flask backend unless explicitly required by a future feature.

HMAC verification currently uses browser Web Crypto.

Supported HMAC algorithms:

* HS256
* HS384
* HS512

Do not claim that a valid HMAC signature proves the token is trustworthy.

Do not claim that decoding proves authorization validity.

Preserve warnings around:

* algorithm selection
* expiry
* issuer
* audience
* subject
* jku
* x5u
* jwk
* x5c
* kid
* sensitive-looking payload keys

---

# 16. IoC Extractor

The IoC Extractor uses the Flask API.

Current categories:

* IP
* domain/URL
* hash
* email

Extraction is pattern-based.

It does not determine whether an indicator is malicious.

Do not add reputation claims unless a real reputation source is introduced.

Do not automatically contact extracted IPs/domains.

Preserve the distinction between:

* extraction
* enrichment
* reputation
* verdict

They are different operations.

---

# 17. Security Headers Analyzer

The Security Headers Analyzer is client-side/local.

It analyzes supplied HTTP response headers.

It must not automatically fetch arbitrary websites unless a future feature explicitly introduces a secure remote-scanning architecture.

Assessment logic should be value-aware.

Do not treat every present header as a vulnerability.

Distinguish between:

* correctly configured
* missing
* weak
* misconfigured
* informational
* not assessed

Remediation text must correspond to the actual observed value.

Do not recommend enabling a header that is already present.

---

# 18. Frontend State and Persistence

Browser persistence should be used only when necessary.

Current intentional persistence includes theme/activity behavior.

Sensitive tool input must remain in ephemeral component state unless there is a documented reason otherwise.

When adding localStorage/sessionStorage:

* validate parsed data
* cap stored size
* handle storage failures
* never assume storage exists
* do not persist secrets

---

# 19. UI / UX Rules

Preserve the existing SentinelX design language.

Use existing:

* shared sidebar
* shared header
* theme system
* UI components
* spacing conventions
* typography
* cards
* buttons
* status patterns

Do not create a second navigation system for a new feature unless explicitly required.

New pages must remain responsive.

Mobile support is mandatory.

Do not design only for desktop.

Test layouts conceptually at narrow phone widths as well as desktop widths.

Avoid unnecessary page expansion caused by long result content.

Long outputs should use appropriate scrolling or constrained containers.

---

# 20. Accessibility

Preserve and improve accessibility.

Interactive controls should have:

* accessible names
* keyboard support
* visible focus states
* appropriate disabled states
* appropriate ARIA only when necessary

Do not use ARIA as a substitute for semantic HTML.

Inputs need associated labels or accessible names.

Status/error messages should use appropriate live regions where useful.

---

# 21. Search and Navigation

Global search is shared application infrastructure.

When adding a tool/page:

* update the appropriate catalog/search source
* preserve keyboard navigation
* preserve existing route behavior
* preserve deep-link behavior where applicable

Do not duplicate search implementations.

---

# 22. Testing Requirements

Before declaring a change complete, run the relevant tests.

Frontend:

```text
corepack pnpm test
corepack pnpm exec tsc --noEmit
corepack pnpm build
```

Backend:

```text
python -m pytest -q
```

For security-sensitive changes also run:

```text
git diff --check
```

Tests should cover both:

* expected successful behavior
* malformed/malicious/untrusted input

For new API endpoints, add backend tests for:

* missing fields
* wrong types
* invalid values
* oversized input
* malformed JSON
* unsupported operations
* rate-limit behavior where practical
* unexpected input structures

For frontend security logic, add regression tests for important edge cases.

Do not claim tests passed unless they were actually run.

Do not claim browser testing unless a real browser test was performed.

---

# 23. Dependencies

Avoid unnecessary dependencies.

Before adding a package:

1. Check whether the existing stack already provides the capability.
2. Check whether a small local utility is sufficient.
3. Consider bundle size.
4. Consider security implications.
5. Prefer maintained, widely used packages.

Do not upgrade large dependency groups casually.

A dependency upgrade should be isolated and tested.

---

# 24. Git Rules

Do not commit, push, merge, or deploy unless the user explicitly asks.

When the user asks for a code change, implement and verify it first.

Do not silently merge branches.

Do not reset or discard unrelated user changes.

Never use destructive Git commands such as:

```text
git reset --hard
git clean -fd
```

unless the user explicitly requests that exact action.

Preserve unrelated work.

---

# 25. Deployment Rules

Production consists of:

* Next.js frontend
* Flask backend
* Redis-compatible rate-limit storage

Do not change deployment configuration unnecessarily.

Do not expose:

* Redis URLs
* credentials
* environment secrets
* API keys

in source code or frontend `NEXT_PUBLIC_*` variables.

Remember:

`NEXT_PUBLIC_*` variables are exposed to the browser.

Only put genuinely public configuration in them.

---

# 26. Environment Variables

Frontend:

`NEXT_PUBLIC_API_URL`

Backend:

`FRONTEND_ORIGIN`

`API_RATE_LIMIT_PER_MINUTE`

`RATE_LIMIT_STORAGE_URI`

`PORT`

`RENDER` is platform-managed.

Never place secrets in:

* source files
* README examples
* frontend public environment variables
* committed `.env` files

`.env.example` may contain safe placeholders/defaults only.

---

# 27. Security Tool Safety

SentinelX may contain tools that generate security testing references.

The application should distinguish between:

1. generating a reference
2. displaying a payload
3. analyzing input
4. executing an action

The first three can often remain local and safe.

Do not silently turn a reference generator into an execution engine.

If an action can affect another system, require explicit user initiation and appropriate safety boundaries.

---

# 28. Preserve Existing Naming Carefully

The project has legacy names containing "Payload Workbench".

Do not perform a global rename just because the public brand is now SentinelX.

Change branding only where requested.

Do not rename backend service identifiers, package names, paths, or environment variables unless there is a specific migration plan.

---

# 29. Change Management

For every requested feature:

1. Inspect existing implementation.
2. Identify the smallest set of files that should change.
3. Implement the feature.
4. Add/update tests.
5. Run TypeScript checks if frontend code changed.
6. Run backend tests if backend code changed.
7. Run production build for frontend changes.
8. Run `git diff --check`.
9. Review the final diff for unrelated changes.
10. Report exactly what changed and what verification actually passed.

Do not modify unrelated modules simply because they could be improved.

---

# 30. Security Review Mindset

When reviewing or implementing code, actively check for:

* XSS
* SSRF
* command injection
* path traversal
* SQL injection if a database is ever introduced
* prototype pollution
* unsafe deserialization
* regex denial of service
* resource exhaustion
* excessive request amplification
* authentication/authorization failures
* CORS mistakes
* CSP weakening
* secret exposure
* sensitive data persistence
* insecure redirects
* trust of forwarded headers
* unsafe URL handling
* insecure dependency usage

For every finding, distinguish:

* confirmed vulnerability
* likely weakness
* defense-in-depth recommendation
* intentional design tradeoff

Do not label something a vulnerability merely because it could theoretically be hardened.

---

# 31. Output Expectations for Coding Tasks

When completing a coding task, report:

### Changed

List the files changed and what each change does.

### Security

Mention any security-relevant behavior that changed.

### Verification

List commands actually run and their actual results.

### Not tested

Explicitly mention anything that could not be tested.

Never fabricate test results.

---

# 32. Most Important Rule

**Preserve working behavior and security controls.**

When in doubt:

* inspect first
* make the smallest safe change
* test it
* avoid unrelated refactors
* never weaken a security control just to make implementation easier
* never claim verification that was not performed

<!-- END:nextjs-agent-rules -->
