import assert from 'node:assert/strict'
import test from 'node:test'
import { FINDING_SEVERITIES, listInvestigationsPage } from '../lib/api.ts'
import {
  buildHeaderFindingPayload,
  clearHeaderFindingSelection,
  mapHeaderFindingSeverity,
  removeSavedHeaderFindings,
  saveHeaderFindingsToInvestigation,
  selectVisibleHeaderFindings,
  toggleHeaderFindingSelection,
} from '../lib/security-header-investigation.ts'
import type { SecurityHeaderFinding } from '../lib/security-headers-analyzer.ts'

const findings: SecurityHeaderFinding[] = [
  { id: 'content_security_policy', header: 'Content-Security-Policy', status: 'missing', severity: 'medium', explanation: 'No policy was supplied.', risk: 'May increase XSS impact.', remediation: 'Define a restrictive policy.' },
  { id: 'x_content_type_options', header: 'X-Content-Type-Options', status: 'misconfigured', severity: 'low', observedValue: 'wrong', explanation: 'The value is not nosniff.', risk: 'MIME sniffing may occur.', remediation: 'Set nosniff.' },
]

const findingResponse = (index: number, payload: Record<string, unknown>) => ({
  id: index + 1, investigation_id: 17, ...payload, status: 'open', source: null,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
})

test('finding selection toggles individually, selects visible rows, and clears', () => {
  let selected = toggleHeaderFindingSelection(new Set(), findings[0].id)
  selected = selectVisibleHeaderFindings(selected, findings.map(({ id }) => id), true)
  assert.deepEqual([...selected], findings.map(({ id }) => id))
  selected = selectVisibleHeaderFindings(selected, [findings[0].id], false)
  assert.deepEqual([...selected], [findings[1].id])
  assert.deepEqual([...toggleHeaderFindingSelection(selected, findings[1].id)], [])
  assert.deepEqual([...clearHeaderFindingSelection()], [])
})

test('analyzer severities map explicitly to supported Investigation severities', () => {
  assert.deepEqual(['critical', 'high', 'medium', 'low', 'info'].map((severity) => mapHeaderFindingSeverity(severity as SecurityHeaderFinding['severity'])), FINDING_SEVERITIES.slice().reverse())
})

test('finding payload contains useful plain text, supported fields, and bounded lengths', () => {
  const payload = buildHeaderFindingPayload({
    ...findings[0], header: 'H'.repeat(250), explanation: 'E'.repeat(9000),
  })
  assert.deepEqual(Object.keys(payload).sort(), ['description', 'severity', 'title'])
  assert.ok(Array.from(payload.title).length <= 200)
  assert.ok(Array.from(payload.description).length <= 8000)
  assert.match(payload.title, /Security header:/)
  assert.match(payload.description, /Remediation:/)
  assert.match(payload.description, /truncated to fit the Investigation API limit/)
  assert.equal(payload.severity, 'medium')
})

test('cookie observed values are redacted in saved context', () => {
  const payload = buildHeaderFindingPayload({
    id: 'cookie_0', header: 'Set-Cookie #1', status: 'misconfigured', severity: 'high',
    observedValue: 'session=secret-token; Secure', explanation: 'Cookie is missing flags.',
    risk: 'Session exposure.', remediation: 'Set HttpOnly.',
  })
  assert.match(payload.description, /Observed value: Secure/)
  assert.doesNotMatch(payload.description, /session=/)
  assert.doesNotMatch(payload.description, /secret-token/)
})

test('investigation picker uses the authenticated list API and supports an empty result', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async (input, init) => {
      assert.match(String(input), /\/api\/investigations\?limit=20&offset=0$/)
      assert.equal(init?.credentials, 'include')
      return new Response(JSON.stringify({ items: [], limit: 20, offset: 0 }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    assert.deepEqual(await listInvestigationsPage({ limit: 20, offset: 0 }), { items: [], limit: 20, offset: 0 })
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationsPage(), (error: unknown) => error instanceof Error && /authentication required/i.test(error.message))
  } finally { globalThis.fetch = originalFetch }
})

test('save uses the authenticated Finding API and sends only title, description, and severity', async () => {
  const originalFetch = globalThis.fetch
  try {
    const bodies: unknown[] = []
    globalThis.fetch = async (input, init) => {
      assert.match(String(input), /\/api\/investigations\/17\/findings$/)
      assert.equal(init?.method, 'POST')
      assert.equal(init?.credentials, 'include')
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      bodies.push(body)
      return new Response(JSON.stringify({ item: findingResponse(bodies.length, body) }), { status: 201, headers: { 'content-type': 'application/json' } })
    }
    const result = await saveHeaderFindingsToInvestigation('17', [findings[0]])
    assert.deepEqual(result.saved, [findings[0]])
    assert.deepEqual(result.failed, [])
    assert.deepEqual(Object.keys(bodies[0] as object).sort(), ['description', 'severity', 'title'])
  } finally { globalThis.fetch = originalFetch }
})

test('partial save failures stay selected while successful findings are removed for retry', async () => {
  const originalFetch = globalThis.fetch
  try {
    let request = 0
    globalThis.fetch = async (_input, init) => {
      const payload = JSON.parse(String(init?.body)) as Record<string, unknown>
      request += 1
      if (request === 2) return new Response(JSON.stringify({ error: 'Description is too long' }), { status: 400, headers: { 'content-type': 'application/json' } })
      return new Response(JSON.stringify({ item: findingResponse(request, payload) }), { status: 201, headers: { 'content-type': 'application/json' } })
    }
    const initial = await saveHeaderFindingsToInvestigation('17', findings)
    assert.deepEqual(initial.saved, [findings[0]])
    assert.equal(initial.failed[0].finding.id, findings[1].id)
    assert.equal(initial.failed[0].message, 'Description is too long')
    const selectionAfterSave = removeSavedHeaderFindings(new Set(findings.map(({ id }) => id)), initial.saved)
    assert.deepEqual([...selectionAfterSave], [findings[1].id])
    const retried = await saveHeaderFindingsToInvestigation('17', [findings[1]])
    assert.deepEqual(retried.saved, [findings[1]])
    assert.equal(request, 3)
  } finally { globalThis.fetch = originalFetch }
})

test('save preserves authentication and malformed response errors', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'content-type': 'application/json' } })
    const expired = await saveHeaderFindingsToInvestigation('17', findings)
    assert.equal(expired.authenticationExpired, true)
    assert.equal(expired.failed.length, findings.length)
    assert.match(expired.failed[1].message, /not attempted/i)

    globalThis.fetch = async () => new Response(JSON.stringify({ item: { id: 'invalid' } }), { status: 201, headers: { 'content-type': 'application/json' } })
    const malformed = await saveHeaderFindingsToInvestigation('17', [findings[0]])
    assert.equal(malformed.saved.length, 0)
    assert.equal(malformed.failed.length, 1)
    assert.ok(malformed.failed[0].message.includes('Invalid finding response'))
  } finally { globalThis.fetch = originalFetch }
})

test('forbidden responses stop subsequent writes and are exposed as an authentication expiry', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers: { 'content-type': 'application/json' } })
    const result = await saveHeaderFindingsToInvestigation('17', [findings[0]])
    assert.equal(result.authenticationExpired, true)
    assert.equal(result.failed[0].message, 'Forbidden')
  } finally { globalThis.fetch = originalFetch }
})
