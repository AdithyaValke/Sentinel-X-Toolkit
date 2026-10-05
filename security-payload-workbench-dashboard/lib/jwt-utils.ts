export type JwtSeverity = 'critical' | 'warning' | 'info'
export type JwtFinding = { severity: JwtSeverity; title: string; explanation: string; whatToCheck: string }
export type JwtTimestamp = { claim: 'exp' | 'nbf' | 'iat'; seconds: number; utc: string; local: string; relative: string }
export type JwtAnalysis = {
  token: string
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
  encodedHeader: string
  encodedPayload: string
  algorithm: string
  findings: JwtFinding[]
  timestamps: JwtTimestamp[]
}
export type JwtParseResult = { ok: true; analysis: JwtAnalysis } | { ok: false; error: string }
export type HmacVerification = { status: 'valid' | 'invalid' | 'unsupported'; explanation: string }

export const JWT_MAX_INPUT_BYTES = 8 * 1024
export const CLOCK_SKEW_TOLERANCE_SECONDS = 60
const YEAR_SECONDS = 365 * 24 * 60 * 60

export function normalizeJwtInput(input: string): { token: string; error?: string } {
  const trimmed = input.trim().replace(/^Bearer\s+/i, '').trim()
  if (new TextEncoder().encode(trimmed).byteLength > JWT_MAX_INPUT_BYTES) {
    return { token: '', error: 'Token exceeds the 8 KiB size limit.' }
  }
  return { token: trimmed }
}

function decodeBase64Url(segment: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(segment)) return null
  const unpadded = segment.replace(/=+$/, '')
  if (unpadded.length % 4 === 1) return null
  const explicitPadding = segment.length - unpadded.length
  const requiredPadding = (4 - unpadded.length % 4) % 4
  if (explicitPadding > 0 && (segment.length % 4 !== 0 || explicitPadding !== requiredPadding)) return null
  const base64 = unpadded.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - unpadded.length % 4) % 4)
  try {
    const binary = atob(base64)
    return Uint8Array.from(binary, (character) => character.charCodeAt(0))
  } catch {
    return null
  }
}

function decodeJsonObject(segment: string, label: 'Header' | 'Payload'): { value: Record<string, unknown> } | { error: string } {
  const bytes = decodeBase64Url(segment)
  if (!bytes) return { error: `${label} is not valid Base64URL` }
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return { error: `${label} is not valid UTF-8` }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return { error: `${label} is not valid JSON` }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { error: `${label} must be a JSON object` }
  return { value: parsed as Record<string, unknown> }
}

export function formatJwtRelativeTime(claim: JwtTimestamp['claim'], seconds: number, nowMs = Date.now()): string {
  const delta = seconds - nowMs / 1000
  const amount = Math.abs(delta)
  if (claim === 'iat' && (amount <= 5 || (delta > 0 && delta <= CLOCK_SKEW_TOLERANCE_SECONDS))) return 'issued just now'
  if (claim === 'nbf' && amount <= 5) return 'valid now'
  let value = Math.round(amount)
  let unitIndex = 0
  const units = ['second', 'minute', 'hour', 'day', 'year']
  const steps = [60, 60, 24, 365]
  while (unitIndex < steps.length && value >= steps[unitIndex]) {
    value = Math.round(value / steps[unitIndex])
    unitIndex += 1
  }
  const unit = units[unitIndex]
  const plural = value === 1 ? unit : `${unit}s`
  if (claim === 'exp') return delta >= 0 ? `expires in ${value} ${plural}` : `expired ${value} ${plural} ago`
  if (claim === 'nbf') return delta >= 0 ? `valid in ${value} ${plural}` : `valid since ${value} ${plural} ago`
  return delta >= 0 ? `issued ${value} ${plural} from now` : `issued ${value} ${plural} ago`
}

function timestamp(claim: JwtTimestamp['claim'], seconds: number, nowSeconds: number): JwtTimestamp {
  const date = new Date(seconds * 1000)
  return {
    claim,
    seconds,
    utc: `${date.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, '')} UTC`,
    local: date.toLocaleString(),
    relative: formatJwtRelativeTime(claim, seconds, nowSeconds * 1000),
  }
}

function finding(severity: JwtSeverity, title: string, explanation: string, whatToCheck: string): JwtFinding {
  return { severity, title, explanation, whatToCheck }
}

function findSensitiveKeys(value: unknown): string[] {
  const found = new Set<string>()
  const sensitive = /password|secret|ssn|card/i
  let visited = 0
  function visit(current: unknown, depth: number) {
    if (!current || typeof current !== 'object' || depth > 16 || visited > 2000) return
    for (const [key, child] of Object.entries(current)) {
      visited += 1
      if (sensitive.test(key)) found.add(key)
      visit(child, depth + 1)
    }
  }
  visit(value, 0)
  return [...found]
}

function analyzeClaims(header: Record<string, unknown>, payload: Record<string, unknown>, signature: string, nowSeconds: number) {
  const findings: JwtFinding[] = []
  const algorithm = typeof header.alg === 'string' ? header.alg : ''
  const normalizedAlg = algorithm.toUpperCase()
  if (normalizedAlg === 'NONE') {
    findings.push(finding('critical', 'Unsigned token algorithm', 'The token declares alg none and has no cryptographic signature protection.', 'Reject unsigned tokens and require the expected algorithm on the server.'))
  } else if (!signature) {
    findings.push(finding('critical', 'Empty signature', 'The signature segment is empty while the header declares a signed algorithm.', 'Require a valid signature before trusting any claims.'))
  }

  const times = new Map<JwtTimestamp['claim'], number>()
  for (const claim of ['exp', 'nbf', 'iat'] as const) {
    const value = payload[claim]
    if (value === undefined) continue
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      findings.push(finding('warning', `Invalid ${claim} claim`, `The ${claim} claim is present but is not a numeric timestamp.`, 'Check that the issuer encodes this claim as a NumericDate.'))
      continue
    }
    if (!Number.isFinite(value * 1000) || !Number.isFinite(new Date(value * 1000).getTime())) {
      findings.push(finding('warning', `Invalid ${claim} claim`, `The ${claim} timestamp is outside the supported date range.`, 'Check that the NumericDate is within a valid clock range.'))
      continue
    }
    times.set(claim, value)
  }

  if (!('exp' in payload)) {
    findings.push(finding('warning', 'No expiration claim', 'The token has no exp claim to limit its lifetime.', 'Confirm that the application enforces an appropriate expiration policy.'))
  } else if (times.has('exp') && times.get('exp')! <= nowSeconds) {
    findings.push(finding('warning', 'Token is expired', 'The exp time is in the past.', 'Reject expired tokens and check clock synchronization.'))
  }
  if (times.has('nbf') && times.get('nbf')! > nowSeconds + CLOCK_SKEW_TOLERANCE_SECONDS) findings.push(finding('warning', 'Token is not active yet', 'The nbf time is more than the allowed clock-skew tolerance in the future.', 'Check whether this token should be accepted before its not-before time.'))
  if (times.has('iat') && times.get('iat')! > nowSeconds + CLOCK_SKEW_TOLERANCE_SECONDS) findings.push(finding('warning', 'Issued-at time is in the future', 'The iat time is more than the allowed clock-skew tolerance in the future.', 'Check token issuance and clock synchronization.'))
  if (times.has('iat') && times.has('exp') && times.get('exp')! - times.get('iat')! > YEAR_SECONDS) {
    findings.push(finding('warning', 'Long token lifetime', 'The exp and iat claims span more than one year.', 'Review whether a shorter lifetime and refresh flow would reduce exposure.'))
  }

  for (const key of ['jku', 'x5u', 'jwk', 'x5c']) {
    if (key in header) findings.push(finding('warning', `Key source in header: ${key}`, `The header includes ${key}, which may supply a remote or embedded key source.`, 'Do not trust token-provided key material or fetch arbitrary key URLs.'))
  }
  if ('kid' in header) findings.push(finding('warning', 'Key ID is user-controlled', 'The kid header is untrusted input that some servers use in file or database lookups.', 'Validate and safely map key IDs without using them as paths or queries.'))
  const sensitiveKeys = findSensitiveKeys(payload)
  if (sensitiveKeys.length) findings.push(finding('warning', 'Sensitive-looking payload keys', `Payload keys ${sensitiveKeys.join(', ')} may contain sensitive data; JWT payloads are encoded, not encrypted.`, 'Do not place secrets or personal data in a readable JWT payload.'))

  for (const claim of ['iss', 'aud', 'sub'] as const) {
    if (!(claim in payload)) findings.push(finding('info', `Missing ${claim} claim`, `The payload does not include ${claim}.`, `Check whether this application requires a trusted ${claim} value.`))
  }
  if (header.typ !== 'JWT') {
    findings.push(finding('info', 'Unexpected token type', 'The header typ value is not JWT.', 'Confirm the expected token type to reduce token-confusion risks.'))
  }
  if (/^HS(256|384|512)$/i.test(algorithm)) findings.push(finding('info', 'Shared-secret algorithm', `${algorithm.toUpperCase()} uses a shared secret for signing and verification.`, 'Confirm the secret is high entropy, protected, and rotated appropriately.'))
  if (/^(RS|ES|PS)/i.test(algorithm)) findings.push(finding('info', 'Asymmetric algorithm', `${algorithm} uses a public/private key algorithm.`, 'Pin the expected algorithm and do not accept HMAC using a public key as the secret.'))

  const timestamps = [...times.entries()].map(([claim, value]) => timestamp(claim, value, nowSeconds))
  return { algorithm, findings, timestamps }
}

export function analyzeJwt(input: string, nowMs = Date.now()): JwtParseResult {
  const normalized = normalizeJwtInput(input)
  if (normalized.error) return { ok: false, error: normalized.error }
  if (!normalized.token) return { ok: false, error: 'Token is empty.' }
  let parts = normalized.token.split('.')
  if (parts.length === 2) parts = [...parts, '']
  if (parts.length !== 3) return { ok: false, error: 'Token must have 3 parts' }
  const header = decodeJsonObject(parts[0], 'Header')
  if ('error' in header) return { ok: false, error: header.error }
  const payload = decodeJsonObject(parts[1], 'Payload')
  if ('error' in payload) return { ok: false, error: payload.error }
  const { algorithm, findings, timestamps } = analyzeClaims(header.value, payload.value, parts[2], nowMs / 1000)
  return { ok: true, analysis: { token: normalized.token, header: header.value, payload: payload.value, signature: parts[2], encodedHeader: parts[0], encodedPayload: parts[1], algorithm, findings, timestamps } }
}

export async function verifyHmac(token: string, secret: string): Promise<HmacVerification> {
  try {
    const parsed = analyzeJwt(token)
    if (!parsed.ok) return { status: 'invalid', explanation: parsed.error }
    const { analysis } = parsed
    const algorithmName = analysis.algorithm.toUpperCase()
    const hash = algorithmName === 'HS256' ? 'SHA-256' : algorithmName === 'HS384' ? 'SHA-384' : algorithmName === 'HS512' ? 'SHA-512' : null
    if (!hash) return { status: 'unsupported', explanation: 'This algorithm needs a public key; verification is not supported here.' }
    const signature = decodeBase64Url(analysis.signature)
    if (!signature) return { status: 'invalid', explanation: 'The signature is not valid Base64URL.' }
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash }, false, ['sign'])
    const signed = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${analysis.encodedHeader}.${analysis.encodedPayload}`)))
    if (signed.length !== signature.length) return { status: 'invalid', explanation: 'The signature does not match this secret.' }
    let difference = 0
    for (let index = 0; index < signed.length; index += 1) difference |= signed[index] ^ signature[index]
    return difference === 0
      ? { status: 'valid', explanation: 'The signature matches this secret.' }
      : { status: 'invalid', explanation: 'The signature does not match this secret.' }
  } catch {
    return { status: 'invalid', explanation: 'Signature verification could not be completed for this input.' }
  }
}

export async function createSampleJwt(nowMs = Date.now()): Promise<string> {
  const secret = 'demo-secret'
  const now = Math.floor(nowMs / 1000)
  const header = { alg: 'HS256', typ: 'JWT' }
  const payload = { iss: 'sentinelx-demo', aud: 'local-learning', sub: 'sample-user', iat: now, exp: now + 3600 }
  const encode = (value: unknown) => {
    const bytes = new TextEncoder().encode(JSON.stringify(value))
    let binary = ''
    bytes.forEach((byte) => { binary += String.fromCharCode(byte) })
    return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  }
  const signingInput = `${encode(header)}.${encode(payload)}`
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput)))
  let binary = ''
  signature.forEach((byte) => { binary += String.fromCharCode(byte) })
  const encodedSignature = btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  return `${signingInput}.${encodedSignature}`
}

export function formatJsonForDisplay(value: unknown, maxChars = 12000, maxDepth = 12): string {
  let visited = 0
  function bound(current: unknown, depth: number): unknown {
    if (depth > maxDepth) return '[Nested content omitted]'
    if (!current || typeof current !== 'object') return current
    if (Array.isArray(current)) {
      const items = current.slice(0, 300).map((item) => { visited += 1; return visited > 2000 ? '[Content omitted]' : bound(item, depth + 1) })
      if (current.length > 300) items.push('[Additional items omitted]')
      return items
    }
    const output = Object.create(null) as Record<string, unknown>
    for (const [key, child] of Object.entries(current)) {
      visited += 1
      if (visited > 2000) { output['…'] = '[Content omitted]'; break }
      output[key] = bound(child, depth + 1)
    }
    return output
  }
  const text = JSON.stringify(bound(value, 0), null, 2)
  const suffix = '\n… [Display limited]'
  return text.length > maxChars ? `${text.slice(0, Math.max(0, maxChars - suffix.length))}${suffix}` : text
}
