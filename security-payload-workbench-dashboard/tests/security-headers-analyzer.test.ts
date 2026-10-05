import assert from 'node:assert/strict'
import test from 'node:test'
import { securityHeadersAnalyzer } from '../lib/security-headers-analyzer.ts'

function finding(input: string, header: string) {
  const result = securityHeadersAnalyzer.analyze(input)
  const item = result.findings.find((row) => row.header === header)
  assert.ok(item, `expected a finding row for ${header}`)
  return item
}

test('HSTS recognizes a valid one-year policy and optional hardening directives', () => {
  const valid = finding('Strict-Transport-Security: max-age=31536000', 'Strict-Transport-Security')
  assert.equal(valid.status, 'present')
  assert.equal(valid.severity, 'info')
  assert.match(valid.explanation, /31536000/)
  assert.doesNotMatch(valid.remediation, /enable hsts/i)
  assert.match(valid.explanation, /Consider includeSubDomains/)
  const expanded = finding('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload', 'Strict-Transport-Security')
  assert.equal(expanded.status, 'present')
  assert.match(expanded.explanation, /includeSubDomains is enabled/)
})

test('HSTS missing, zero, malformed, and too-short max-age are distinguished', () => {
  assert.equal(finding('', 'Strict-Transport-Security').status, 'missing')
  for (const value of ['max-age=0', 'max-age=abc', 'max-age=86400', 'includeSubDomains']) {
    const item = finding(`Strict-Transport-Security: ${value}`, 'Strict-Transport-Security')
    assert.equal(item.status, 'misconfigured', value)
    assert.equal(item.severity, 'medium', value)
  }
})

test('X-Content-Type-Options assessment follows its supplied value', () => {
  const good = finding('X-Content-Type-Options: nosniff', 'X-Content-Type-Options')
  assert.equal(good.status, 'present')
  assert.equal(good.severity, 'info')
  assert.doesNotMatch(good.remediation, /set the value|add .*nosniff/i)
  const missing = finding('', 'X-Content-Type-Options')
  assert.equal(missing.status, 'missing')
  assert.match(missing.remediation, /X-Content-Type-Options: nosniff/)
  const bad = finding('X-Content-Type-Options: sniff', 'X-Content-Type-Options')
  assert.equal(bad.status, 'misconfigured')
  assert.match(bad.remediation, /nosniff/)
})

test('X-Frame-Options DENY and SAMEORIGIN are both valid', () => {
  for (const value of ['SAMEORIGIN', 'DENY']) {
    const item = finding(`X-Frame-Options: ${value}`, 'X-Frame-Options')
    assert.equal(item.status, 'present')
    assert.equal(item.severity, 'info')
    assert.doesNotMatch(item.remediation, /use deny/i)
  }
})

test('Referrer-Policy distinguishes valid, missing, and weak values', () => {
  const valid = finding('Referrer-Policy: strict-origin-when-cross-origin', 'Referrer-Policy')
  assert.equal(valid.status, 'present')
  assert.equal(valid.severity, 'info')
  assert.match(valid.explanation, /explicit Referrer-Policy/)
  assert.equal(finding('', 'Referrer-Policy').status, 'missing')
  const weak = finding('Referrer-Policy: unsafe-url', 'Referrer-Policy')
  assert.equal(weak.status, 'misconfigured')
  assert.match(weak.explanation, /full referrer URL/)
})

test('Permissions-Policy reports specified restrictions and flags unrestricted sensitive features', () => {
  const restrictive = finding('Permissions-Policy: geolocation=(), microphone=()', 'Permissions-Policy')
  assert.equal(restrictive.status, 'present')
  assert.equal(restrictive.severity, 'info')
  assert.match(restrictive.explanation, /unspecified capabilities are not assumed to be insecure/)
  assert.equal(finding('', 'Permissions-Policy').status, 'not-assessed')
  const permissive = finding('Permissions-Policy: geolocation=*', 'Permissions-Policy')
  assert.equal(permissive.status, 'misconfigured')
  assert.match(permissive.explanation, /geolocation/)
})

test('CSP findings name unsafe directives and safe CSP is informational', () => {
  const weak = finding("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; object-src 'none'", 'Content-Security-Policy')
  assert.equal(weak.status, 'misconfigured')
  assert.equal(weak.severity, 'high')
  assert.match(weak.explanation, /unsafe-inline.*script-src/)
  assert.match(weak.explanation, /weakens protection against script injection/)
  assert.match(weak.remediation, /Remove 'unsafe-inline'/)
  assert.match(weak.remediation, /nonces or hashes/)
  const evalPolicy = finding("Content-Security-Policy: script-src 'self' 'unsafe-eval'", 'Content-Security-Policy')
  assert.match(evalPolicy.explanation, /unsafe-eval/)
  const styleInline = finding("Content-Security-Policy: style-src 'unsafe-inline'", 'Content-Security-Policy')
  assert.equal(styleInline.status, 'misconfigured')
  const irrelevantEval = finding("Content-Security-Policy: style-src 'unsafe-eval'; object-src 'none'", 'Content-Security-Policy')
  assert.equal(irrelevantEval.status, 'present')
  const safe = finding("Content-Security-Policy: default-src 'self'; object-src 'none'", 'Content-Security-Policy')
  assert.equal(safe.status, 'present')
  assert.equal(safe.severity, 'info')
})

test('cookie attributes are assessed individually without requiring SameSite=Strict', () => {
  const complete = finding('Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax', 'Set-Cookie #1')
  assert.equal(complete.status, 'present')
  assert.equal(complete.severity, 'info')
  const partial = finding('Set-Cookie: session_id=abc123; Path=/; HttpOnly', 'Set-Cookie #1')
  assert.equal(partial.status, 'misconfigured')
  assert.match(partial.risk, /Secure and SameSite/)
  assert.doesNotMatch(partial.remediation, /SameSite=Strict/)
  assert.equal(securityHeadersAnalyzer.analyze('Set-Cookie: session=abc; HttpOnly').cookies, 1)
})

test('full sample preserves pass, issue, not-assessed, and summary counts', () => {
  const sample = `HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: nginx/1.24.0
Date: Mon, 05 Oct 2026 03:20:15 GMT
Content-Length: 18452
Cache-Control: public, max-age=3600
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=()
Access-Control-Allow-Origin: *
Set-Cookie: session_id=abc123; Path=/; HttpOnly`
  const analysis = securityHeadersAnalyzer.analyze(sample)
  const byHeader = new Map(analysis.findings.map((item) => [item.header, item]))
  assert.equal(byHeader.get('Content-Security-Policy')?.status, 'misconfigured')
  assert.equal(byHeader.get('Strict-Transport-Security')?.status, 'present')
  assert.equal(byHeader.get('X-Content-Type-Options')?.status, 'present')
  assert.equal(byHeader.get('X-Frame-Options')?.status, 'present')
  assert.equal(byHeader.get('Referrer-Policy')?.status, 'present')
  assert.equal(byHeader.get('Permissions-Policy')?.status, 'present')
  for (const header of ['Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy', 'Cross-Origin-Embedder-Policy']) assert.equal(byHeader.get(header)?.status, 'not-assessed')
  assert.equal(byHeader.get('Set-Cookie #1')?.status, 'misconfigured')
  assert.equal(analysis.recognizedHeaders, 9)
  assert.equal(analysis.detectedHeaders, 7)
  assert.equal(analysis.cookies, 1)
  assert.equal(analysis.findings.length, 10)
  assert.equal(analysis.findings.filter((item) => item.status === 'missing' || item.status === 'misconfigured').length, 2)
})
