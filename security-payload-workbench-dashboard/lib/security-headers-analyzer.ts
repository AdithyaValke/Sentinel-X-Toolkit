export type HeaderFindingStatus = 'present' | 'missing' | 'misconfigured' | 'not-assessed'
export type HeaderFindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface SecurityHeaderFinding {
  id: string
  header: string
  status: HeaderFindingStatus
  severity: HeaderFindingSeverity
  observedValue?: string
  explanation: string
  risk: string
  remediation: string
  example?: string
}

export interface SecurityHeadersAnalysis {
  recognizedHeaders: number
  detectedHeaders: number
  findings: SecurityHeaderFinding[]
  cookies: number
  rawInputLength: number
}

export interface SecurityHeadersAnalyzerService {
  analyze(input: string): SecurityHeadersAnalysis
}

const checks = [
  ['Content-Security-Policy', 'medium', 'Controls which sources browsers may load.', 'A missing or permissive policy can increase XSS impact depending on application behavior.', 'Define a restrictive policy from observed application dependencies. Avoid unsafe-inline and unsafe-eval where possible.', "default-src 'self'; object-src 'none'; base-uri 'self'"] ,
  ['Strict-Transport-Security', 'medium', 'Instructs browsers to use HTTPS for future requests.', 'Missing HSTS is a transport-hardening gap on HTTPS deployments; this input cannot verify TLS or domain coverage.', 'Enable only after HTTPS is working consistently, then choose max-age and includeSubDomains deliberately.', 'max-age=31536000; includeSubDomains'] ,
  ['X-Content-Type-Options', 'low', 'Prevents MIME-type sniffing.', 'Without nosniff, browsers may interpret some responses using a content type different from the server declaration.', 'Set the value to nosniff on responses serving user-controlled or executable content.', 'nosniff'] ,
  ['X-Frame-Options', 'medium', 'Controls legacy framing behavior.', 'Missing framing protection may permit clickjacking where the application has sensitive actions.', 'Use DENY or SAMEORIGIN when framing is not required; CSP frame-ancestors is the modern companion.', 'SAMEORIGIN'] ,
  ['Referrer-Policy', 'low', 'Controls referrer information sent with requests.', 'A missing policy leaves behavior to browser defaults and can expose more URL context than intended.', 'Choose an explicit policy such as strict-origin-when-cross-origin or no-referrer.', 'strict-origin-when-cross-origin'] ,
  ['Permissions-Policy', 'low', 'Restricts browser powerful features.', 'Missing policy is not automatically a vulnerability, but unused capabilities may remain available to embedded content.', 'Disable features the application does not use and scope required features to trusted origins.', 'camera=(), microphone=(), geolocation=()'] ,
  ['Cross-Origin-Opener-Policy', 'info', 'Controls browsing-context group isolation.', 'Not required for every application; isolation depends on cross-origin window and deployment needs.', 'Consider same-origin when cross-origin isolation or opener isolation is part of the threat model.', 'same-origin'] ,
  ['Cross-Origin-Resource-Policy', 'info', 'Controls which origins may load resources.', 'Applicability depends on whether resources are intended for cross-origin consumption.', 'Choose same-origin, same-site, or cross-origin per resource distribution requirements.', 'same-origin'] ,
  ['Cross-Origin-Embedder-Policy', 'info', 'Controls whether cross-origin resources can be embedded.', 'Not assessed as a missing protection because enabling it can break legitimate integrations.', 'Consider require-corp only when the application needs cross-origin isolation and all dependencies support it.', 'require-corp'] ,
] as const

function parseHeaders(input: string) {
  const values = new Map<string, string[]>()
  const malformed: string[] = []
  for (const line of input.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || /^HTTP\/\d(?:\.\d)?\s+\d+/.test(trimmed) || /^[-=]+$/.test(trimmed)) continue
    const separator = trimmed.indexOf(':')
    if (separator <= 0) { malformed.push(trimmed); continue }
    const name = trimmed.slice(0, separator).trim().toLowerCase()
    const value = trimmed.slice(separator + 1).trim()
    if (!name || !value) { malformed.push(trimmed); continue }
    values.set(name, [...(values.get(name) ?? []), value])
  }
  return { values, malformed }
}

export const securityHeadersAnalyzer: SecurityHeadersAnalyzerService = {
  analyze(input) {
    const { values, malformed } = parseHeaders(input)
    const findings: SecurityHeaderFinding[] = checks.map(([header, defaultSeverity, explanation, risk, remediation, example]) => {
      const observed = values.get(header.toLowerCase())?.join('\n')
      let status: HeaderFindingStatus = observed ? 'present' : 'missing'
      let severity = defaultSeverity as HeaderFindingSeverity
      if (observed) {
        const normalized = observed.toLowerCase()
        if (header === 'Content-Security-Policy' && (normalized.includes("unsafe-inline") || normalized.includes("unsafe-eval") || normalized.includes('*'))) { status = 'misconfigured'; severity = 'high' }
        if (header === 'Strict-Transport-Security' && (!/max-age=\d+/.test(normalized) || /max-age=0/.test(normalized))) { status = 'misconfigured'; severity = 'medium' }
        if (header === 'X-Content-Type-Options' && normalized !== 'nosniff') { status = 'misconfigured'; severity = 'medium' }
        if (header === 'X-Frame-Options' && !/^(deny|sameorigin)$/i.test(normalized)) { status = 'misconfigured'; severity = 'medium' }
      }
      if (status === 'missing' && severity === 'info') status = 'not-assessed'
      return { id: header.toLowerCase().replaceAll('-', '_'), header, status, severity, observedValue: observed, explanation, risk, remediation, example }
    })
    const cookies = values.get('set-cookie') ?? []
    cookies.forEach((cookie, index) => {
      const lower = cookie.toLowerCase()
      const missing: string[] = []
      if (!lower.includes('; secure')) missing.push('Secure')
      if (!lower.includes('; httponly')) missing.push('HttpOnly')
      if (!lower.includes('samesite=')) missing.push('SameSite')
      findings.push({ id: `cookie_${index}`, header: `Set-Cookie #${index + 1}`, status: missing.length ? 'misconfigured' : 'present', severity: missing.includes('Secure') ? 'medium' : 'low', observedValue: cookie, explanation: 'Cookie attributes reduce exposure during transport, scripting, and cross-site requests.', risk: missing.length ? `This cookie is missing: ${missing.join(', ')}. Requirements depend on whether it is a session, cross-site, or non-sensitive cookie.` : 'The common hardening attributes are present; cookie scope and application context still matter.', remediation: 'Review each cookie independently. Add Secure for HTTPS, HttpOnly for server-managed secrets, and an intentional SameSite value.', example: 'session=...; Secure; HttpOnly; SameSite=Lax' })
    })
    if (malformed.length) findings.push({ id: 'input_format', header: 'Input format', status: 'not-assessed', severity: 'info', explanation: 'Some lines did not contain a recognizable header name and value.', risk: `${malformed.length} line${malformed.length === 1 ? '' : 's'} were skipped.`, remediation: 'Use one header per line in the form Name: value. HTTP status lines and blank lines are supported.' })
    return { recognizedHeaders: checks.length, detectedHeaders: [...values.keys()].filter((key) => checks.some(([h]) => h.toLowerCase() === key) || key === 'set-cookie').length, findings, cookies: cookies.length, rawInputLength: input.length }
  },
}

export const SECURITY_HEADERS_SAMPLE = `HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self'; object-src 'none'\nX-Content-Type-Options: nosniff\nReferrer-Policy: strict-origin-when-cross-origin\nSet-Cookie: session=demo; Secure; HttpOnly; SameSite=Lax`

export function exportAnalysisJson(analysis: SecurityHeadersAnalysis) { return JSON.stringify(analysis, null, 2) }
export function exportAnalysisCsv(analysis: SecurityHeadersAnalysis) {
  const esc = (value = '') => `"${value.replaceAll('"', '""').replaceAll('\n', ' ')}"`
  return ['Header,Status,Severity,Observed,Explanation,Remediation', ...analysis.findings.map((f) => [f.header, f.status, f.severity, f.observedValue ?? '', f.explanation, f.remediation].map(esc).join(','))].join('\n')
}
