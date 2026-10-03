import assert from 'node:assert/strict'
import test from 'node:test'
import { callBackend, checkBackendHealth } from '../lib/api.ts'
import { PAYLOAD_OPERATION_MAP } from '../lib/payload-operations.ts'

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
