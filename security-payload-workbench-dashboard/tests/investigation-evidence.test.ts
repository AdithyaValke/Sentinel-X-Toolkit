import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError, createInvestigationEvidence, listInvestigationEvidence } from '../lib/api.ts'
import type { InvestigationEvidence } from '../lib/api.ts'

const evidence: InvestigationEvidence = {
  id: 8,
  investigation_id: 17,
  finding_id: null,
  evidence_type: 'log_snippet',
  title: 'DNS query log',
  content: 'A lookup was observed for example.test.',
  source: null,
  created_at: '2026-01-01T00:00:00Z',
}

test('evidence list uses authenticated request and validates returned records', async () => {
  const originalFetch = globalThis.fetch
  try {
    let requestedUrl = ''
    globalThis.fetch = async (input, init) => {
      requestedUrl = String(input)
      assert.equal(init?.credentials, 'include')
      return new Response(JSON.stringify({ items: [evidence] }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    assert.deepEqual(await listInvestigationEvidence('17'), [evidence])
    assert.match(requestedUrl, /\/api\/investigations\/17\/evidence$/)

    globalThis.fetch = async () => new Response(JSON.stringify({ items: [{ ...evidence, evidence_type: 'Bad Type' }] }), { status: 200, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationEvidence('17'), /invalid evidence response/i)
    globalThis.fetch = async () => new Response(JSON.stringify({ items: [{ ...evidence, content: null }] }), { status: 200, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationEvidence('17'), /invalid evidence response/i)
  } finally { globalThis.fetch = originalFetch }
})

test('evidence creation sends only required fields and validates returned evidence', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async (input, init) => {
      assert.match(String(input), /\/api\/investigations\/17\/evidence$/)
      assert.equal(init?.method, 'POST')
      assert.equal(init?.credentials, 'include')
      assert.deepEqual(JSON.parse(String(init?.body)), {
        evidence_type: 'log_snippet', title: evidence.title, content: evidence.content,
      })
      return new Response(JSON.stringify({ item: evidence }), { status: 201, headers: { 'content-type': 'application/json' } })
    }
    assert.deepEqual(await createInvestigationEvidence('17', {
      evidence_type: 'log_snippet', title: evidence.title, content: evidence.content,
    }), evidence)
  } finally { globalThis.fetch = originalFetch }
})

test('evidence API reports validation and authentication errors from backend', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'content is required' }), { status: 400, headers: { 'content-type': 'application/json' } })
    await assert.rejects(createInvestigationEvidence('17', { evidence_type: 'note', title: 'Note', content: '' }), (error: unknown) => error instanceof ApiError && error.status === 400 && error.message === 'content is required')
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'content-type': 'application/json' } })
    await assert.rejects(listInvestigationEvidence('17'), (error: unknown) => error instanceof ApiError && error.status === 401)
  } finally { globalThis.fetch = originalFetch }
})
