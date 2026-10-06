import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError, listInvestigationTimeline } from '../lib/api.ts'

const events = [
  { id: 5, investigation_id: 17, event_type: 'evidence_added', message: 'Evidence added', created_at: '2026-01-03T00:00:00Z' },
  { id: 4, investigation_id: 17, event_type: 'ioc_added', message: 'IOC added (ip)', created_at: '2026-01-02T00:00:00Z' },
]

test('timeline request uses authenticated API, requests pagination, and preserves backend ordering metadata', async () => {
  const originalFetch = globalThis.fetch
  try {
    let requestedUrl = ''
    globalThis.fetch = async (input, init) => {
      requestedUrl = String(input)
      assert.equal(init?.credentials, 'include')
      return new Response(JSON.stringify({ items: events, limit: 2, offset: 4 }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    const page = await listInvestigationTimeline('17', { limit: 2, offset: 4 })
    assert.match(requestedUrl, /\/api\/investigations\/17\/timeline\?limit=2&offset=4$/)
    assert.deepEqual(page, { items: events, limit: 2, offset: 4 })
    assert.deepEqual(page.items.map((event) => event.event_type), ['evidence_added', 'ioc_added'])
  } finally { globalThis.fetch = originalFetch }
})

test('timeline validates event fields, known event types, and pagination metadata', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ items: [{ ...events[0], message: 3 }], limit: 20, offset: 0 }), { status: 200, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationTimeline('17'), /invalid timeline response/i)
    globalThis.fetch = async () => new Response(JSON.stringify({ items: [{ ...events[0], event_type: 'manual_note' }], limit: 20, offset: 0 }), { status: 200, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationTimeline('17'), /invalid timeline response/i)
    globalThis.fetch = async () => new Response(JSON.stringify({ items: events, limit: 101, offset: 0 }), { status: 200, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationTimeline('17'), /invalid timeline response/i)
  } finally { globalThis.fetch = originalFetch }
})

test('timeline surfaces backend authorization and pagination errors', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'limit must be between 1 and 100' }), { status: 400, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationTimeline('17', { limit: 101 }), (error: unknown) => error instanceof ApiError && error.status === 400 && error.message === 'limit must be between 1 and 100')
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationTimeline('17'), (error: unknown) => error instanceof ApiError && error.status === 401)
  } finally { globalThis.fetch = originalFetch }
})
