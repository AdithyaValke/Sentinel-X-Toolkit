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
  ['Content-Security-Policy', 'medium', 'Controls which sources browsers may load.', 'A missing or permissive policy can increase XSS impact depending on application behavior.', "default-src 'self'; object-src 'none'; base-uri 'self'"],
  ['Strict-Transport-Security', 'medium', 'Instructs browsers to use HTTPS for future requests.', 'HSTS applies only after a browser receives it over HTTPS; this text review cannot verify TLS or domain coverage.', 'max-age=31536000; includeSubDomains'],
  ['X-Content-Type-Options', 'low', 'Prevents MIME-type sniffing.', 'Without nosniff, browsers may interpret some responses using a content type different from the server declaration.', 'nosniff'],
  ['X-Frame-Options', 'medium', 'Controls legacy framing behavior.', 'Missing framing protection may permit clickjacking where the application has sensitive actions.', 'SAMEORIGIN'],
  ['Referrer-Policy', 'low', 'Controls referrer information sent with requests.', 'An explicit policy can limit URL details shared in the Referer header.', 'strict-origin-when-cross-origin'],
  ['Permissions-Policy', 'info', 'Restricts selected browser capabilities.', 'The effect of a policy depends on which features the application and embedded content need.', 'camera=(), microphone=(), geolocation=()'],
  ['Cross-Origin-Opener-Policy', 'info', 'Controls browsing-context group isolation.', 'Not required for every application; isolation depends on cross-origin window and deployment needs.', 'same-origin'],
  ['Cross-Origin-Resource-Policy', 'info', 'Controls which origins may load resources.', 'Applicability depends on whether resources are intended for cross-origin consumption.', 'same-origin'],
  ['Cross-Origin-Embedder-Policy', 'info', 'Controls whether cross-origin resources can be embedded.', 'Not assessed as a missing protection because enabling it can break legitimate integrations.', 'require-corp'],
] as const

const referrerPolicies = new Set(['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'])

function assessHeader(header: string, observed: string | undefined, missingSeverity: HeaderFindingSeverity) {
  if (!observed) {
    if (header.startsWith('Cross-Origin-') || header === 'Permissions-Policy') {
      return { status: 'not-assessed' as const, severity: 'info' as const, explanation: 'This header is not required for every application and was not supplied.', risk: 'No conclusion about this control can be drawn from its absence alone.', remediation: 'Assess whether this control fits the application and its cross-origin integrations.' }
    }
    const missingGuidance: Record<string, { explanation: string; remediation: string }> = {
      'Content-Security-Policy': { explanation: 'No Content-Security-Policy was supplied.', remediation: 'Define a policy from the application’s required sources and test it before enforcement.' },
      'Strict-Transport-Security': { explanation: 'No Strict-Transport-Security policy was supplied.', remediation: 'If the site is consistently HTTPS, add HSTS with a deliberate max-age; confirm subdomain readiness before adding includeSubDomains.' },
      'X-Content-Type-Options': { explanation: 'X-Content-Type-Options is missing.', remediation: 'Add X-Content-Type-Options: nosniff to responses where MIME sniffing should be prevented.' },
      'X-Frame-Options': { explanation: 'X-Frame-Options is missing.', remediation: 'Set DENY or SAMEORIGIN if the application does not need to be framed; use CSP frame-ancestors for modern framing control.' },
      'Referrer-Policy': { explanation: 'No explicit Referrer-Policy was supplied.', remediation: 'Choose an explicit policy such as strict-origin-when-cross-origin or no-referrer.' },
    }
    return { status: 'missing' as const, severity: missingSeverity, explanation: missingGuidance[header]?.explanation ?? 'The header is missing.', risk: 'Review whether this control is required for the application and its deployment.', remediation: missingGuidance[header]?.remediation ?? 'Review the header configuration for this application.' }
  }

  const value = observed.trim()
  const normalized = value.toLowerCase()
  if (header === 'Content-Security-Policy') {
    const risky: string[] = []
    for (const directive of value.split(';')) {
      const [rawName, ...sources] = directive.trim().split(/\s+/)
      const name = rawName?.toLowerCase()
      if (!name) continue
      for (const source of sources) {
        const token = source.toLowerCase()
        const inlineDirective = ['script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem', 'style-src-attr', 'default-src'].includes(name)
        const evalDirective = ['script-src', 'script-src-elem', 'script-src-attr', 'default-src'].includes(name)
        if (token === "'unsafe-inline'" && inlineDirective) risky.push(`${token} in ${name}`)
        if (token === "'unsafe-eval'" && evalDirective) risky.push(`${token} in ${name}`)
      }
    }
    if (risky.length) return { status: 'misconfigured' as const, severity: 'high' as const, explanation: `CSP contains ${[...new Set(risky)].join(' and ')}. unsafe-inline weakens protection against script injection; unsafe-eval permits string-to-code evaluation.`, risk: 'These directives can reduce CSP protection if an injection flaw is present.', remediation: `Remove ${[...new Set(risky.map((item) => item.split(' in ')[0]))].join(' and ')} where possible. Use nonces or hashes for required inline scripts, and remove unsafe-eval unless a reviewed dependency requires it.` }
    return { status: 'present' as const, severity: 'info' as const, explanation: 'A Content-Security-Policy is present and no unsafe-inline or unsafe-eval source was found in script/style or default directives.', risk: 'This text-only check does not prove that the policy is complete or correct for the application.', remediation: 'Review allowed sources against application requirements and keep the policy as restrictive as practical.' }
  }
  if (header === 'Strict-Transport-Security') {
    const maxAgeMatch = normalized.match(/(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?=;|$)/)
    const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : NaN
    if (!Number.isFinite(maxAge) || maxAge <= 0) return { status: 'misconfigured' as const, severity: 'medium' as const, explanation: 'HSTS is present, but max-age is missing, malformed, or zero.', risk: 'Browsers will not retain a useful HTTPS-only policy with this max-age value.', remediation: 'Set a positive max-age. Increase it toward 31536000 seconds after HTTPS readiness is confirmed.' }
    if (maxAge < 31536000) return { status: 'misconfigured' as const, severity: 'medium' as const, explanation: `HSTS max-age is ${maxAge} seconds, below the analyzer’s one-year baseline of 31536000 seconds.`, risk: 'A short duration reduces how long browsers remember the HTTPS-only policy.', remediation: 'If HTTPS is stable, consider increasing max-age to at least 31536000 seconds. Add includeSubDomains only when every subdomain supports HTTPS.' }
    const directives = new Set(normalized.split(';').map((part) => part.trim().split(/[=\s]/, 1)[0]))
    const options = [directives.has('includesubdomains') ? 'includeSubDomains is enabled.' : 'Consider includeSubDomains if all subdomains are HTTPS-capable.', directives.has('preload') ? 'The preload directive is present; eligibility is not verified here.' : 'Consider preload only if the deployment satisfies the required preload prerequisites.']
    return { status: 'present' as const, severity: 'info' as const, explanation: `HSTS is enabled with observed value “${value}” and a valid max-age of ${maxAge} seconds. ${options.join(' ')}`, risk: 'This text review cannot verify that the response is delivered over HTTPS or that every covered host is ready.', remediation: 'The supplied max-age is active. Treat includeSubDomains and preload as deployment-specific choices.' }
  }
  if (header === 'X-Content-Type-Options') {
    if (normalized === 'nosniff') return { status: 'present' as const, severity: 'info' as const, explanation: 'X-Content-Type-Options is correctly set to nosniff.', risk: 'This setting reduces MIME-sniffing behavior in supported browsers.', remediation: 'No change is indicated by the supplied value.' }
    return { status: 'misconfigured' as const, severity: 'medium' as const, explanation: `X-Content-Type-Options has unexpected value “${value}”; nosniff is the recognized value.`, risk: 'The supplied value may not prevent MIME-type sniffing.', remediation: 'Replace the unexpected value with X-Content-Type-Options: nosniff.' }
  }
  if (header === 'X-Frame-Options') {
    if (/^(deny|sameorigin)$/i.test(value)) return { status: 'present' as const, severity: 'info' as const, explanation: `X-Frame-Options is correctly configured as ${value.toUpperCase()}.`, risk: 'This directive provides legacy framing control; CSP frame-ancestors can provide modern policy control.', remediation: 'No change is indicated by the supplied value. Keep SAMEORIGIN if same-origin framing is intentional.' }
    return { status: 'misconfigured' as const, severity: 'medium' as const, explanation: `X-Frame-Options has unrecognized or unsafe value “${value}”.`, risk: 'Browsers may not apply reliable framing protection.', remediation: 'Use DENY or SAMEORIGIN when framing is not required, and configure CSP frame-ancestors for modern browsers.' }
  }
  if (header === 'Referrer-Policy') {
    const policies = normalized.split(',').map((item) => item.trim())
    const unknown = policies.filter((policy) => !referrerPolicies.has(policy))
    if (unknown.length) return { status: 'misconfigured' as const, severity: 'medium' as const, explanation: `The Referrer-Policy value contains unrecognized token${unknown.length > 1 ? 's' : ''}: ${unknown.join(', ')}.`, risk: 'Browsers may ignore an invalid policy token and use a less predictable default.', remediation: 'Use a recognized policy such as strict-origin-when-cross-origin or no-referrer.' }
    if (policies.includes('unsafe-url')) return { status: 'misconfigured' as const, severity: 'medium' as const, explanation: 'The unsafe-url policy can send the full referrer URL, including path and query, to other origins.', risk: 'Sensitive URL details may be disclosed in cross-origin requests.', remediation: 'Consider strict-origin-when-cross-origin or no-referrer to limit cross-origin URL disclosure.' }
    if (policies.includes('no-referrer-when-downgrade')) return { status: 'misconfigured' as const, severity: 'low' as const, explanation: 'no-referrer-when-downgrade may send full URL details to secure destinations.', risk: 'The policy does not limit URL detail on secure-to-secure requests.', remediation: 'Consider strict-origin-when-cross-origin if reducing cross-origin URL detail is appropriate.' }
    return { status: 'present' as const, severity: 'info' as const, explanation: `An explicit Referrer-Policy is configured (${value}).`, risk: 'The chosen policy controls what URL information is shared with destinations.', remediation: 'No change is indicated by this recognized policy; confirm it matches application privacy needs.' }
  }
  if (header === 'Permissions-Policy') {
    const sensitiveFeatures = new Set(['accelerometer', 'camera', 'clipboard-read', 'display-capture', 'geolocation', 'gyroscope', 'microphone', 'payment', 'serial', 'usb'])
    const unrestricted = [...normalized.matchAll(/(?:^|,)\s*([a-z-]+)\s*=\s*(?:\*|\([^)]*\*[^)]*\))/g)].map((match) => match[1]).filter((feature) => sensitiveFeatures.has(feature))
    if (unrestricted.length) return { status: 'misconfigured' as const, severity: 'medium' as const, explanation: `The policy allows unrestricted use of ${[...new Set(unrestricted)].join(', ')}.`, risk: 'Sensitive browser capabilities may be available to documents or embedded origins more broadly than intended.', remediation: 'Restrict these capabilities to () or an explicit trusted origin list where application behavior permits.' }
    return { status: 'present' as const, severity: 'info' as const, explanation: `Permissions-Policy is present (${value}). The capabilities it specifies are evaluated as written; unspecified capabilities are not assumed to be insecure.`, risk: 'This check does not determine which additional capabilities the application should restrict.', remediation: 'No change is indicated for the specified values. Review only capabilities relevant to the application.' }
  }
  return { status: 'present' as const, severity: 'info' as const, explanation: `${header} is present (${value}).`, risk: 'Whether this setting is appropriate depends on application integrations and deployment requirements.', remediation: 'Review this value against the application’s cross-origin requirements.' }
}

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
    const findings: SecurityHeaderFinding[] = checks.map(([header, missingSeverity, _description, _risk, example]) => {
      const observed = values.get(header.toLowerCase())?.join('\n')
      const assessment = assessHeader(header, observed, missingSeverity)
      return { id: header.toLowerCase().replaceAll('-', '_'), header, ...assessment, observedValue: observed, example }
    })
    const cookies = values.get('set-cookie') ?? []
    cookies.forEach((cookie, index) => {
      const lower = cookie.toLowerCase()
      const missing: string[] = []
      const attributes = lower.split(';').slice(1).map((attribute) => attribute.trim())
      if (!attributes.includes('secure')) missing.push('Secure')
      if (!attributes.includes('httponly')) missing.push('HttpOnly')
      if (!attributes.some((attribute) => attribute.startsWith('samesite='))) missing.push('SameSite')
      findings.push({ id: `cookie_${index}`, header: `Set-Cookie #${index + 1}`, status: missing.length ? 'misconfigured' : 'present', severity: missing.includes('Secure') ? 'medium' : missing.length ? 'low' : 'info', observedValue: cookie, explanation: missing.length ? `Cookie attribute review: ${missing.join(', ')} is not present.` : 'Secure, HttpOnly, and SameSite attributes are present.', risk: missing.length ? `Secure and SameSite may be appropriate depending on deployment and cookie purpose; HttpOnly is appropriate for server-managed secrets. Missing: ${missing.join(', ')}.` : 'The common hardening attributes are present; cookie scope and application context still matter.', remediation: missing.length ? `Review this cookie’s purpose and deployment. ${missing.includes('Secure') ? 'Add Secure when it is served over HTTPS. ' : ''}${missing.includes('HttpOnly') ? 'Add HttpOnly for cookies not accessed by client-side scripts. ' : ''}${missing.includes('SameSite') ? 'Choose an intentional SameSite value (Lax, Strict, or None) based on cross-site use; do not apply Strict without checking the cookie purpose.' : ''}`.trim() : 'No attribute change is indicated by these checks; review the cookie’s scope and purpose.', example: 'session=...; Secure; HttpOnly; SameSite=Lax' })
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
