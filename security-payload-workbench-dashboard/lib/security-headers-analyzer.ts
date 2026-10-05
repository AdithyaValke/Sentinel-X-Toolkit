export type HeaderFindingStatus = 'present' | 'missing' | 'misconfigured' | 'not-assessed'
export type HeaderFindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface ParsedHeaders { values: Map<string, string[]>; malformedLines: string[] }
export interface SecurityHeaderFinding {
  id: string
  header: string
  status: HeaderFindingStatus
  severity: HeaderFindingSeverity
  title: string
  explanation: string
  remediation: string
  observedValue?: string
  example?: string
}
export interface SecurityHeadersAnalysis {
  findings: SecurityHeaderFinding[]
  parsedHeaderCount: number
  detectedHeaderCount: number
  cookieCount: number
  malformedLines: string[]
}

const checks = [
  ['content-security-policy', 'Content-Security-Policy', 'A policy can reduce the impact of content injection when it is specific and enforced.', 'Review sources, remove unsafe allowances where possible, and deploy a tested policy.', 'medium'],
  ['strict-transport-security', 'Strict-Transport-Security', 'HSTS tells browsers to use HTTPS for a configured period.', 'Use HSTS only after HTTPS is reliable across the domain and include an appropriate max-age.', 'medium'],
  ['x-content-type-options', 'X-Content-Type-Options', 'nosniff helps prevent MIME-type confusion in browsers.', 'Set X-Content-Type-Options: nosniff.', 'low'],
  ['x-frame-options', 'X-Frame-Options', 'This legacy control can limit framing and clickjacking exposure.', 'Set DENY or SAMEORIGIN when framing is not required; use CSP frame-ancestors for modern policy.', 'medium'],
  ['referrer-policy', 'Referrer-Policy', 'Controls how much URL context is sent as a referrer.', 'Choose an explicit policy such as strict-origin-when-cross-origin based on application needs.', 'low'],
  ['permissions-policy', 'Permissions-Policy', 'Limits browser features available to documents and embedded content.', 'Declare a policy for sensitive features that the application does not need.', 'low'],
  ['cross-origin-opener-policy', 'Cross-Origin-Opener-Policy', 'Controls browsing-context isolation across origins.', 'Consider same-origin where isolation is required and compatible with the application.', 'info'],
  ['cross-origin-resource-policy', 'Cross-Origin-Resource-Policy', 'Controls which origins may load resources.', 'Consider same-origin or same-site for resources that should not be broadly embedded.', 'info'],
  ['cross-origin-embedder-policy', 'Cross-Origin-Embedder-Policy', 'Controls whether cross-origin resources must opt into embedding.', 'Consider require-corp only when cross-origin isolation is a deliberate, tested requirement.', 'info'],
] as const

export function parseResponseHeaders(input: string): ParsedHeaders {
  const values = new Map<string, string[]>()
  const malformedLines: string[] = []
  for (const raw of input.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || /^HTTP\/\d(?:\.\d)?\s+\d{3}/i.test(line)) continue
    const separator = line.indexOf(':')
    if (separator <= 0) { malformedLines.push(line); continue }
    const name = line.slice(0, separator).trim().toLowerCase()
    const value = line.slice(separator + 1).trim()
    if (!name || !value) { malformedLines.push(line); continue }
    values.set(name, [...(values.get(name) ?? []), value])
  }
  return { values, malformedLines }
}

function assessHeader(id: string, name: string, value: string | undefined, severity: HeaderFindingSeverity): SecurityHeaderFinding {
  if (!value) return { id, header: name, status: 'missing', severity, title: `${name} was not observed`, explanation: 'This check could not find the header in the supplied response. Missing does not by itself prove a vulnerability; relevance depends on the application and deployment.', remediation: `Review whether ${name} is appropriate for this application and add an explicit policy when it is needed.` }
  let status: HeaderFindingStatus = 'present'
  let explanation = `${name} was observed in the supplied headers.`
  let remediation = 'Review the value against the application architecture and test browser behavior before deploying changes.'
  if (id === 'content-security-policy' && /(^|\s)(unsafe-inline|unsafe-eval|\*)/i.test(value)) { status = 'misconfigured'; severity = 'high'; explanation = 'The policy contains broad or unsafe source allowances that can reduce its protective value.'; remediation = 'Replace broad sources with explicit origins and nonces or hashes where appropriate.' }
  if (id === 'strict-transport-security' && !/max-age=\d+/i.test(value)) { status = 'misconfigured'; explanation = 'The header does not contain a recognizable max-age directive.'; remediation = 'Use a tested max-age value and only enable HSTS when HTTPS coverage is understood.' }
  if (id === 'x-content-type-options' && !/^nosniff$/i.test(value.trim())) { status = 'misconfigured'; explanation = 'The observed value is not the expected nosniff directive.'; remediation = 'Set the value to nosniff.' }
  return { id, header: name, status, severity, title: status === 'present' ? `${name} recognized` : `${name} may need review`, explanation, remediation, observedValue: value, example: id === 'x-content-type-options' ? 'X-Content-Type-Options: nosniff' : undefined }
}

function cookieFindings(values: string[]): SecurityHeaderFinding[] {
  return values.map((cookie, index) => {
    const parts = cookie.split(';').map((part) => part.trim())
    const name = parts[0]?.split('=')[0] || `cookie-${index + 1}`
    const lower = parts.slice(1).map((part) => part.toLowerCase())
    const missing: string[] = []
    if (!lower.includes('secure')) missing.push('Secure')
    if (!lower.includes('httponly')) missing.push('HttpOnly')
    if (!lower.some((part) => part.startsWith('samesite='))) missing.push('SameSite')
    return { id: `cookie-${index}`, header: `Set-Cookie: ${name}`, status: missing.length ? 'misconfigured' : 'present', severity: missing.includes('Secure') ? 'high' : missing.includes('HttpOnly') ? 'medium' : 'low', title: missing.length ? `${name} is missing ${missing.join(', ')}` : `${name} attributes observed`, explanation: missing.length ? 'Cookie attributes are context-dependent, but the supplied cookie does not declare all common browser protections.' : 'Secure, HttpOnly, and SameSite attributes were observed for this cookie.', remediation: 'Set attributes according to the cookie purpose, transport, cross-site, and client-side access requirements.', observedValue: cookie, example: `${name}=<value>; Secure; HttpOnly; SameSite=Lax` } satisfies SecurityHeaderFinding
  })
}

export function analyzeSecurityHeaders(input: string): SecurityHeadersAnalysis {
  const parsed = parseResponseHeaders(input)
  const findings = checks.map(([id, name, , , severity]) => assessHeader(id, name, parsed.values.get(id)?.[0], severity))
  findings.push(...cookieFindings(parsed.values.get('set-cookie') ?? []))
  return { findings, parsedHeaderCount: [...parsed.values.values()].reduce((total, values) => total + values.length, 0), detectedHeaderCount: parsed.values.size, cookieCount: parsed.values.get('set-cookie')?.length ?? 0, malformedLines: parsed.malformedLines }
}

export function findingsToCsv(findings: SecurityHeaderFinding[]) {
  const escape = (value: string) => `"${value.replaceAll('"', '""')}"`
  return ['Header,Status,Severity,Explanation,Remediation,Observed value', ...findings.map((finding) => [finding.header, finding.status, finding.severity, finding.explanation, finding.remediation, finding.observedValue ?? ''].map(escape).join(','))].join('\n')
}

export function findingsToJson(analysis: SecurityHeadersAnalysis) { return JSON.stringify(analysis, null, 2) }

export const SECURITY_HEADERS_SAMPLE = `HTTP/2 200 OK\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'\nStrict-Transport-Security: max-age=31536000\nX-Content-Type-Options: nosniff\nReferrer-Policy: strict-origin-when-cross-origin\nSet-Cookie: session=redacted; Secure; HttpOnly; SameSite=Lax`

export const STATUS_LABELS: Record<HeaderFindingStatus, string> = { present: 'Present', missing: 'Missing', misconfigured: 'Review', 'not-assessed': 'Not assessed' }
export const SEVERITY_LABELS: Record<HeaderFindingSeverity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }
export const HEADER_CHECK_COUNT = checks.length
export const SEVERITIES: HeaderFindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
export const STATUSES: HeaderFindingStatus[] = ['present', 'missing', 'misconfigured', 'not-assessed']

export interface SecurityHeadersAnalyzerService { analyze(input: string): SecurityHeadersAnalysis }
export const localSecurityHeadersAnalyzer: SecurityHeadersAnalyzerService = { analyze: analyzeSecurityHeaders }
