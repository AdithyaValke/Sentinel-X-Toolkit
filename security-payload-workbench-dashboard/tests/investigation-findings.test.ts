import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError, createInvestigationFinding, FINDING_SEVERITIES, listInvestigationFindings } from '../lib/api.ts'

const finding = {
  id: 3,
  investigation_id: 17,
  title: 'Suspicious outbound connection',
  description: 'The host repeatedly contacted an external IP.',
  severity: 'high',
  status: 'open',
  source: null,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

test('finding list uses authenticated API and validates returned finding records', async () => {
  const originalFetch = globalThis.fetch
  try {
    let url = ''
    globalThis.fetch = async (input, init) => {
      url = String(input)
      assert.equal(init?.credentials, 'include')
      return new Response(JSON.stringify({ items: [finding] }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    assert.deepEqual(await listInvestigationFindings('17'), [finding])
    assert.match(url, /\/api\/investigations\/17\/findings$/)
    globalThis.fetch = async () => new Response(JSON.stringify({ items: [{ ...finding, severity: 'urgent' }] }), { status: 200, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationFindings('17'), /invalid finding response/i)
  } finally { globalThis.fetch = originalFetch }
})

test('finding creation sends only supported fields and returns validated finding', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async (_input, init) => {
      assert.equal(init?.method, 'POST')
      assert.equal(init?.credentials, 'include')
      assert.deepEqual(JSON.parse(String(init?.body)), { title: finding.title, description: finding.description, severity: 'high' })
      return new Response(JSON.stringify({ item: finding }), { status: 201, headers: { 'content-type': 'application/json' } })
    }
    assert.deepEqual(await createInvestigationFinding('17', { title: finding.title, description: finding.description, severity: 'high' }), finding)
  } finally { globalThis.fetch = originalFetch }
})

test('finding severities match backend allowlist and API errors are preserved', async () => {
  const originalFetch = globalThis.fetch
  try {
    assert.deepEqual(FINDING_SEVERITIES, ['info', 'low', 'medium', 'high', 'critical'])
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Invalid finding severity' }), { status: 400, headers: { 'content-type': 'application/json' } })
    await assert.rejects(createInvestigationFinding('17', { title: 'Finding', severity: 'info' }), (error: unknown) => error instanceof ApiError && error.status === 400 && error.message === 'Invalid finding severity')
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationFindings('17'), (error: unknown) => error instanceof ApiError && error.status === 401)
  } finally { globalThis.fetch = originalFetch }
})
