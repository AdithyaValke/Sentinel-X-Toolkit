import assert from 'node:assert/strict'
import test from 'node:test'
import { getLegacyDestination } from '../lib/legacy-routes.ts'
import { PAYLOAD_OPERATION_MAP } from '../lib/payload-operations.ts'

test('routes legacy hash operations to their dedicated pages and retains other parameters', () => {
  assert.equal(
    getLegacyDestination({ operation: 'hash', source: 'bookmark', view: ['compact', 'wide'] }),
    '/hash-tools?operation=hash&source=bookmark&view=compact&view=wide',
  )
  assert.equal(
    getLegacyDestination({ operation: 'identify-hash', q: 'abc123' }),
    '/identify-hash?operation=identify-hash&q=abc123',
  )
})

test('routes all supported payload operations and retains the selected operation', () => {
  for (const operation of [
    'base64-encode',
    'base64-decode',
    'url-encode',
    'url-decode',
    'hex-encode',
    'hex-decode',
  ]) {
    assert.equal(
      getLegacyDestination({ operation, source: 'legacy' }),
      `/payload-tools?operation=${operation}&source=legacy`,
    )
  }
  assert.deepEqual(PAYLOAD_OPERATION_MAP, {
    'base64-encode': 'base64_encode',
    'base64-decode': 'base64_decode',
    'url-encode': 'url_encode',
    'url-decode': 'url_decode',
    'hex-encode': 'hex_encode',
    'hex-decode': 'hex_decode',
  })
})

test('routes an unqualified or unknown root request to the dashboard', () => {
  assert.equal(getLegacyDestination({}), '/dashboard')
  assert.equal(getLegacyDestination({ operation: 'unknown', keep: 'yes' }), '/dashboard?operation=unknown&keep=yes')
})
