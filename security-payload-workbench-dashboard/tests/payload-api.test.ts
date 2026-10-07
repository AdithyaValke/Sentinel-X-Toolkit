import assert from 'node:assert/strict'
import test from 'node:test'
import { callBackend, callChain, checkBackendHealth, createInvestigation, extractIocs } from '../lib/api.ts'
import { HASH_ALGORITHM_OPTIONS } from '../lib/hash-algorithms.ts'
import { addChainStep, CHAIN_MAX_STEPS, CHAIN_OPERATION_DESCRIPTIONS, CHAIN_OPERATION_LABELS, CHAIN_REQUEST_MAX_BYTES, isChainResponse, moveChainStep, PAYLOAD_OPERATION_MAP, removeChainStep, serializedChainRequestBytes } from '../lib/payload-operations.ts'

test('chain helpers add, remove, reorder, and enforce the step limit', () => {
  const steps = [{ operation: 'url_encode' }, { operation: 'hex_encode' }]
  assert.deepEqual(moveChainStep(steps, 1, -1), [{ operation: 'hex_encode' }, { operation: 'url_encode' }])
  assert.deepEqual(removeChainStep(steps, 0), [{ operation: 'hex_encode' }])
  assert.equal(addChainStep(Array.from({ length: CHAIN_MAX_STEPS }, () => ({ operation: 'hex_encode' })), 'url_decode').length, CHAIN_MAX_STEPS)
  assert.equal(addChainStep(steps, 'url_decode').length, 3)
  assert.equal(isChainResponse({ steps: [{ operation: 'url_encode', output: 'hi' }], final: 'hi' }), true)
  assert.equal(isChainResponse({ steps: [{ operation: 7, output: 'hi' }], final: 'hi' }), false)
})

test('chain labels and request size use the API operation names and serialized JSON bytes', () => {
  assert.equal(CHAIN_OPERATION_LABELS.base64_encode, 'Base64 Encode')
  assert.equal(CHAIN_OPERATION_LABELS.url_decode, 'URL Decode')
  assert.equal(CHAIN_OPERATION_LABELS.hex_encode, 'Hex Encode')
  assert.equal(CHAIN_OPERATION_DESCRIPTIONS.hex_decode, 'Decode Hex to text')
  assert.equal(serializedChainRequestBytes('☃', [{ operation: 'url_encode' }]), new TextEncoder().encode(JSON.stringify({ input_text: '☃', steps: [{ operation: 'url_encode' }] })).byteLength)
  assert.equal(CHAIN_REQUEST_MAX_BYTES, 10 * 1024)
})

test('IoC API sends categories and validates structured responses', async () => {
  const originalFetch = globalThis.fetch
  installBrowserTimerShim()
  try {
    globalThis.fetch = async (_input, init) => {
      assert.deepEqual(JSON.parse(String(init?.body)), { input_text: 'alert', categories: ['ip'] })
      return new Response(JSON.stringify({ success: true, results: [{ category: 'ip', value: '192.0.2.1', occurrences: 1, context: 'alert 192.0.2.1' }], summary: { unique: 1, occurrences: 1, by_category: { ip: 1, domain: 0, hash: 0, email: 0 } }, error: null }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    assert.equal((await extractIocs('alert', ['ip'])).results[0].value, '192.0.2.1')
    globalThis.fetch = async () => new Response(JSON.stringify({ success: true, results: 'bad', summary: {}, error: null }), { status: 200, headers: { 'content-type': 'application/json' } })
    await assert.rejects(extractIocs('alert', ['ip']), /invalid response/i)
  } finally { globalThis.fetch = originalFetch; Reflect.deleteProperty(globalThis, 'window') }
})

test('investigation creation sends only fields accepted by the create endpoint', async () => {
  const originalFetch = globalThis.fetch
  installBrowserTimerShim()
  try {
    globalThis.fetch = async (_input, init) => {
      assert.equal(init?.method, 'POST')
      assert.equal(init?.credentials, 'include')
      assert.deepEqual(JSON.parse(String(init?.body)), { title: 'Suspicious activity', description: 'Review sign-in logs' })
      return new Response(JSON.stringify({ item: { id: 17, title: 'Suspicious activity', description: 'Review sign-in logs', status: 'open', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', closed_at: null } }), { status: 201, headers: { 'content-type': 'application/json' } })
    }
    const created = await createInvestigation({ title: 'Suspicious activity', description: 'Review sign-in logs' })
    assert.equal(created.id, 17)
    assert.equal(created.status, 'open')
  } finally { globalThis.fetch = originalFetch; Reflect.deleteProperty(globalThis, 'window') }
})

test('chain client sends the ordered operations and validates response shape', async () => {
  const originalFetch = globalThis.fetch
  installBrowserTimerShim()
  try {
    let body = ''
    globalThis.fetch = async (_input, init) => {
      body = String(init?.body)
      return new Response(JSON.stringify({ steps: [{ operation: 'url_encode', output: 'hello' }], final: 'hello' }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    const response = await callChain('input', [{ operation: 'url_encode' }])
    assert.deepEqual(JSON.parse(body), { input_text: 'input', steps: [{ operation: 'url_encode' }] })
    assert.equal(response.final, 'hello')
    globalThis.fetch = async () => new Response(JSON.stringify({ steps: [], final: 7 }), { status: 200, headers: { 'content-type': 'application/json' } })
    await assert.rejects(callChain('input', [{ operation: 'url_encode' }]), /invalid response/i)
  } finally { globalThis.fetch = originalFetch; Reflect.deleteProperty(globalThis, 'window') }
})

function installBrowserTimerShim() {
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: {
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
    },
  })
}

test('sends each payload operation to the existing Flask API and returns its result', async () => {
  const originalFetch = globalThis.fetch
  installBrowserTimerShim()

  try {
    for (const [operation, apiOperation] of Object.entries(PAYLOAD_OPERATION_MAP)) {
      let requestBody: { operation?: string; input_text?: string } | undefined
      globalThis.fetch = async (_input, init) => {
        requestBody = JSON.parse(String(init?.body))
        return new Response(JSON.stringify({ success: true, result: 'encoded result', error: null }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }

      const response = await callBackend(apiOperation, 'sample input')
      assert.equal(requestBody?.operation, apiOperation, operation)
      assert.equal(requestBody?.input_text, 'sample input', operation)
      assert.equal(response.result, 'encoded result', operation)
    }
  } finally {
    globalThis.fetch = originalFetch
    Reflect.deleteProperty(globalThis, 'window')
  }
})

test('sends each Hash Converter selection unchanged as the backend hash identifier', async () => {
  const originalFetch = globalThis.fetch
  installBrowserTimerShim()
  try {
    for (const { value } of HASH_ALGORITHM_OPTIONS) {
      globalThis.fetch = async (_input, init) => {
        assert.deepEqual(JSON.parse(String(init?.body)), {
          input_text: 'abc',
          operation: 'hash',
          hash_algorithm: value,
        })
        return new Response(JSON.stringify({ success: true, result: 'verified digest', error: null }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      const response = await callBackend('hash', 'abc', value)
      assert.equal(response.success, true, value)
      assert.equal(response.result, 'verified digest', value)
    }
  } finally {
    globalThis.fetch = originalFetch
    Reflect.deleteProperty(globalThis, 'window')
  }
})

test('turns backend and network failures into useful errors', async () => {
  const originalFetch = globalThis.fetch
  installBrowserTimerShim()

  try {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ success: false, result: '', error: 'Invalid encoded value' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      })
    await assert.rejects(callBackend('base64_decode', '%%%'), /Invalid encoded value/)

    globalThis.fetch = async () => {
      throw new TypeError('fetch failed')
    }
    await assert.rejects(callBackend('hex_decode', 'ff'), /Could not reach the Flask API/)
  } finally {
    globalThis.fetch = originalFetch
    Reflect.deleteProperty(globalThis, 'window')
  }
})

test('preserves caller aborts as cancellations instead of reporting timeouts', async () => {
  const originalFetch = globalThis.fetch
  installBrowserTimerShim()
  const controller = new AbortController()
  try {
    globalThis.fetch = async (_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true })
    })
    const request = callBackend('base64_encode', 'superseded input', null, controller.signal)
    controller.abort()
    await assert.rejects(request, (error: unknown) => error instanceof DOMException && error.name === 'AbortError')
  } finally {
    globalThis.fetch = originalFetch
    Reflect.deleteProperty(globalThis, 'window')
  }
})

test('rejects malformed optional hash analysis fields before rendering', async () => {
  const originalFetch = globalThis.fetch
  installBrowserTimerShim()
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({
      success: true,
      result: 'candidate list',
      error: null,
      candidates: [{ algorithm: 7, evidence: null, explanation: [] }],
    }), { status: 200, headers: { 'content-type': 'application/json' } })
    await assert.rejects(callBackend('identify_hash', 'abc'), /invalid response/i)
  } finally {
    globalThis.fetch = originalFetch
    Reflect.deleteProperty(globalThis, 'window')
  }
})

test('health check reports only an explicit successful backend status', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ status: 'ok' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    assert.equal(await checkBackendHealth(), true)

    globalThis.fetch = async () => new Response('{}', { status: 503 })
    assert.equal(await checkBackendHealth(), false)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('API base URL requires HTTPS in production and preserves local HTTP development', async () => {
  const originalFetch = globalThis.fetch
  const originalNodeEnv = process.env.NODE_ENV
  const originalApiUrl = process.env.NEXT_PUBLIC_API_URL
  installBrowserTimerShim()
  try {
    Reflect.set(process.env, 'NODE_ENV', 'production')
    Reflect.set(process.env, 'NEXT_PUBLIC_API_URL', '')
    await assert.rejects(callBackend('base64_encode', 'hello'), /not configured/i)
    Reflect.set(process.env, 'NEXT_PUBLIC_API_URL', 'http://api.example.test')
    await assert.rejects(callBackend('base64_encode', 'hello'), /must use HTTPS in production/i)
    for (const invalid of ['https://', 'file:///tmp/api', 'not a URL']) {
      Reflect.set(process.env, 'NEXT_PUBLIC_API_URL', invalid)
      await assert.rejects(callBackend('base64_encode', 'hello'), /absolute HTTP\(S\) URL|must use HTTP or HTTPS/i)
    }

    let requestedUrl = ''
    globalThis.fetch = async (input) => {
      requestedUrl = String(input)
      return new Response(JSON.stringify({ success: true, result: 'aGVsbG8=', error: null }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    Reflect.set(process.env, 'NEXT_PUBLIC_API_URL', 'https://api.example.test/')
    assert.equal((await callBackend('base64_encode', 'hello')).result, 'aGVsbG8=')
    assert.equal(requestedUrl, 'https://api.example.test/api/process')

    Reflect.set(process.env, 'NODE_ENV', 'development')
    Reflect.set(process.env, 'NEXT_PUBLIC_API_URL', 'http://api.example.test')
    await assert.rejects(callBackend('base64_encode', 'hello'), /HTTP only for localhost/i)
    Reflect.set(process.env, 'NEXT_PUBLIC_API_URL', 'http://localhost:8000')
    assert.equal((await callBackend('base64_encode', 'hello')).success, true)
    assert.equal(requestedUrl, 'http://localhost:8000/api/process')
  } finally {
    globalThis.fetch = originalFetch
    Reflect.deleteProperty(globalThis, 'window')
    if (originalNodeEnv === undefined) Reflect.deleteProperty(process.env, 'NODE_ENV')
    else Reflect.set(process.env, 'NODE_ENV', originalNodeEnv)
    if (originalApiUrl === undefined) Reflect.deleteProperty(process.env, 'NEXT_PUBLIC_API_URL')
    else Reflect.set(process.env, 'NEXT_PUBLIC_API_URL', originalApiUrl)
  }
})
