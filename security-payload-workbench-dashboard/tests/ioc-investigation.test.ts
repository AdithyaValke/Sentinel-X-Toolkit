import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError, createInvestigationIOC, deleteInvestigation, listInvestigationsPage, updateInvestigation } from '../lib/api.ts'
import { canPersistIndicators, saveIndicatorsToInvestigation, selectVisibleIndicators, toggleIndicatorSelection, type ExtractedIndicator } from '../lib/ioc-investigation.ts'

const indicators: ExtractedIndicator[] = [
  { id: 'ip:192.0.2.8', category: 'ip', value: '192.0.2.8', occurrences: 2, context: 'connecting to 192.0.2.8' },
  { id: 'domain:cdn.example.test', category: 'domain', value: 'cdn.example.test', occurrences: 1, context: 'cdn.example.test' },
  { id: 'email:analyst@example.test', category: 'email', value: 'analyst@example.test', occurrences: 1, context: 'analyst@example.test' },
]

const investigationRecord = (overrides: Record<string, unknown> = {}) => ({
  id: 41, title: 'Incident', description: 'Current description', status: 'open',
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z', closed_at: null,
  ...overrides,
})

test('investigation updates send only supported fields and return the updated record', async () => {
  const originalFetch = globalThis.fetch
  try {
    let sentBody: unknown
    globalThis.fetch = async (input, init) => {
      assert.match(String(input), /\/api\/investigations\/41$/)
      assert.equal(init?.method, 'PATCH')
      assert.equal(init?.credentials, 'include')
      sentBody = JSON.parse(String(init?.body))
      return new Response(JSON.stringify({ item: investigationRecord({ title: 'Updated', description: null }) }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    const updated = await updateInvestigation('41', { title: 'Updated', description: null })
    assert.deepEqual(sentBody, { title: 'Updated', description: null })
    assert.equal(updated.title, 'Updated')
    assert.equal(updated.description, null)
    assert.equal('owner_id' in (sentBody as object), false)
  } finally { globalThis.fetch = originalFetch }
})

test('investigation updates support close and reopen payloads and preserve API validation errors', async () => {
  const originalFetch = globalThis.fetch
  try {
    const bodies: unknown[] = []
    globalThis.fetch = async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { status: string }
      bodies.push(body)
      return new Response(JSON.stringify({ item: investigationRecord({ status: body.status, closed_at: body.status === 'closed' ? '2026-01-03T00:00:00Z' : null }) }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    assert.equal((await updateInvestigation('41', { status: 'closed' })).status, 'closed')
    assert.equal((await updateInvestigation('41', { status: 'open' })).status, 'open')
    assert.deepEqual(bodies, [{ status: 'closed' }, { status: 'open' }])
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'title must be at most 200 characters' }), { status: 400, headers: { 'content-type': 'application/json' } })
    await assert.rejects(updateInvestigation('41', { title: 'x'.repeat(201) }), (error: unknown) => error instanceof ApiError && error.status === 400 && /200 characters/.test(error.message))
  } finally { globalThis.fetch = originalFetch }
})

test('investigation update preserves authentication failures', async () => {
  const originalFetch = globalThis.fetch
  try {
    let requestInit: RequestInit | undefined
    globalThis.fetch = async (_input, init) => {
      requestInit = init
      return new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'content-type': 'application/json' } })
    }
    await assert.rejects(updateInvestigation('41', { status: 'closed' }), (error: unknown) => error instanceof ApiError && error.status === 401)
    assert.equal(requestInit?.credentials, 'include')
  } finally { globalThis.fetch = originalFetch }
})

test('investigation deletion sends authenticated DELETE and handles success and failure', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async (input, init) => {
      assert.match(String(input), /\/api\/investigations\/41$/)
      assert.equal(init?.method, 'DELETE')
      assert.equal(init?.credentials, 'include')
      return new Response(null, { status: 204 })
    }
    await deleteInvestigation('41')
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Investigation not found' }), { status: 404, headers: { 'content-type': 'application/json' } })
    await assert.rejects(deleteInvestigation('41'), (error: unknown) => error instanceof ApiError && error.status === 404 && error.message === 'Investigation not found')
  } finally { globalThis.fetch = originalFetch }
})

test('selection supports toggle, multi-select, visible selection, clear, and save gating', () => {
  let selected = toggleIndicatorSelection(new Set(), indicators[0].id)
  assert.deepEqual([...selected], [indicators[0].id])
  selected = toggleIndicatorSelection(selected, indicators[0].id)
  assert.equal(selected.size, 0)
  selected = selectVisibleIndicators(selected, indicators.slice(0, 2).map((item) => item.id), true)
  assert.equal(selected.size, 2)
  selected = selectVisibleIndicators(selected, [indicators[1].id], false)
  assert.deepEqual([...selected], [indicators[0].id])
  assert.equal(canPersistIndicators(true, 1, false), true)
  assert.equal(canPersistIndicators(false, 1, false), false)
  assert.equal(canPersistIndicators(true, 0, false), false)
  assert.equal(canPersistIndicators(true, 1, true), false)
})

test('investigation selector list uses authenticated paginated API and validates records', async () => {
  const originalFetch = globalThis.fetch
  try {
    let url = ''
    globalThis.fetch = async (input, init) => {
      url = String(input)
      assert.equal(init?.credentials, 'include')
      return new Response(JSON.stringify({ items: [{ id: 9, title: 'Incident', description: null, status: 'investigating', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z', closed_at: null }], limit: 20, offset: 20 }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    const page = await listInvestigationsPage({ limit: 20, offset: 20 })
    assert.match(url, /\/api\/investigations\?limit=20&offset=20$/)
    assert.equal(page.items[0].id, 9)
    assert.equal(page.offset, 20)
    globalThis.fetch = async () => new Response(JSON.stringify({ items: [{ id: 9 }], limit: 20, offset: 0 }), { status: 200, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationsPage(), /invalid investigations response/i)
  } finally { globalThis.fetch = originalFetch }
})

test('multiple selected indicators create distinct IOC requests with source extractor', async () => {
  const originalFetch = globalThis.fetch
  try {
    const bodies: unknown[] = []
    globalThis.fetch = async (input, init) => {
      assert.match(String(input), /\/api\/investigations\/41\/iocs$/)
      assert.equal(init?.method, 'POST')
      assert.equal(init?.credentials, 'include')
      const body = JSON.parse(String(init?.body)) as { ioc_type: string; value: string; source: string }
      bodies.push(body)
      return new Response(JSON.stringify({ item: { id: bodies.length, investigation_id: 41, ...body, normalized_value: body.value, confidence: null, first_seen: null, last_seen: null, created_at: '2026-01-01T00:00:00Z' } }), { status: 201, headers: { 'content-type': 'application/json' } })
    }
    const result = await saveIndicatorsToInvestigation('41', indicators.slice(0, 2))
    assert.equal(result.saved.length, 2)
    assert.equal(result.failed.length, 0)
    assert.deepEqual(bodies, [
      { ioc_type: 'ip', value: '192.0.2.8', source: 'extractor' },
      { ioc_type: 'domain', value: 'cdn.example.test', source: 'extractor' },
    ])

    globalThis.fetch = async (_input, init) => {
      assert.deepEqual(JSON.parse(String(init?.body)), { ioc_type: 'email', value: 'analyst@example.test', source: 'extractor' })
      return new Response(JSON.stringify({ error: 'Invalid IOC source' }), { status: 400, headers: { 'content-type': 'application/json' } })
    }
    await assert.rejects(createInvestigationIOC('41', { ioc_type: 'email', value: indicators[2].value, source: 'extractor' }), (error: unknown) => error instanceof ApiError && error.status === 400 && error.message === 'Invalid IOC source')
  } finally { globalThis.fetch = originalFetch }
})

test('save canonicalizes supported defanged values in API payload without changing extractor display values', async () => {
  const originalFetch = globalThis.fetch
  const extracted: ExtractedIndicator[] = [
    { id: 'ip:defanged', category: 'ip', value: '192[.]0[.]2[.]1', occurrences: 1, context: '192[.]0[.]2[.]1' },
    { id: 'domain:defanged', category: 'domain', value: 'malicious[.]example[.]com', occurrences: 1, context: 'malicious[.]example[.]com' },
    { id: 'url:defanged', category: 'domain', value: 'hxxps://malicious[.]example[.]com/payload.exe', occurrences: 1, context: 'hxxps://malicious[.]example[.]com/payload.exe' },
    { id: 'hash:upper', category: 'hash', value: 'A'.repeat(64), occurrences: 1, context: 'A'.repeat(64) },
    { id: 'email:defanged', category: 'email', value: 'analyst[@]example[.]com', occurrences: 1, context: 'analyst[@]example[.]com' },
  ]
  try {
    const bodies: unknown[] = []
    globalThis.fetch = async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { ioc_type: string; value: string; source: string }
      bodies.push(body)
      return new Response(JSON.stringify({ item: { id: bodies.length, investigation_id: 41, ...body, normalized_value: body.value, confidence: null, first_seen: null, last_seen: null, created_at: '2026-01-01T00:00:00Z' } }), { status: 201, headers: { 'content-type': 'application/json' } })
    }
    const result = await saveIndicatorsToInvestigation('41', extracted)
    assert.equal(result.saved.length, extracted.length)
    assert.deepEqual(bodies, [
      { ioc_type: 'ip', value: '192.0.2.1', source: 'extractor' },
      { ioc_type: 'domain', value: 'malicious.example.com', source: 'extractor' },
      { ioc_type: 'domain', value: 'malicious.example.com', source: 'extractor' },
      { ioc_type: 'hash', value: 'A'.repeat(64), source: 'extractor' },
      { ioc_type: 'email', value: 'analyst@example.com', source: 'extractor' },
    ])
    assert.deepEqual(extracted.map(({ value }) => value), [
      '192[.]0[.]2[.]1',
      'malicious[.]example[.]com',
      'hxxps://malicious[.]example[.]com/payload.exe',
      'A'.repeat(64),
      'analyst[@]example[.]com',
    ])
  } finally { globalThis.fetch = originalFetch }
})

test('save reports partial and complete failures without hiding backend validation errors', async () => {
  const originalFetch = globalThis.fetch
  try {
    let request = 0
    globalThis.fetch = async () => {
      request += 1
      if (request === 2) return new Response(JSON.stringify({ error: 'IOC value is invalid' }), { status: 400, headers: { 'content-type': 'application/json' } })
      return new Response(JSON.stringify({ item: { id: request, investigation_id: 41, ioc_type: indicators[request - 1].category, value: indicators[request - 1].value, normalized_value: indicators[request - 1].value, source: 'extractor', confidence: null, first_seen: null, last_seen: null, created_at: '2026-01-01T00:00:00Z' } }), { status: 201, headers: { 'content-type': 'application/json' } })
    }
    const partial = await saveIndicatorsToInvestigation('41', indicators)
    assert.deepEqual(partial.saved.map((item) => item.id), [indicators[0].id, indicators[2].id])
    assert.equal(partial.failed.length, 1)
    assert.equal(partial.failed[0].message, 'IOC value is invalid')

    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Invalid IOC source' }), { status: 400, headers: { 'content-type': 'application/json' } })
    const failed = await saveIndicatorsToInvestigation('41', [indicators[0]])
    assert.equal(failed.saved.length, 0)
    assert.equal(failed.failed[0].message, 'Invalid IOC source')
  } finally { globalThis.fetch = originalFetch }
})

test('expired authentication stops remaining writes and reports them as not attempted', async () => {
  const originalFetch = globalThis.fetch
  try {
    let calls = 0
    globalThis.fetch = async () => { calls += 1; return new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'content-type': 'application/json' } }) }
    const result = await saveIndicatorsToInvestigation('41', indicators)
    assert.equal(calls, 1)
    assert.equal(result.authenticationExpired, true)
    assert.equal(result.failed.length, indicators.length)
    assert.match(result.failed[1].message, /not attempted/i)
  } finally { globalThis.fetch = originalFetch }
})
