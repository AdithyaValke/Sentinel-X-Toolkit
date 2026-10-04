import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeJwt, createSampleJwt, formatJsonForDisplay, verifyHmac } from '../lib/jwt-utils.ts'

function base64Url(value: string) {
  const bytes = new TextEncoder().encode(value)
  let binary = ''
  bytes.forEach((byte) => { binary += String.fromCharCode(byte) })
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

function token(header: unknown = { alg: 'none', typ: 'JWT' }, payload: unknown = { iss: 'issuer', aud: 'audience', sub: 'subject' }, signature = '') {
  return `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(payload))}.${signature}`
}

function signWithSecret(value: string, secret: string, algorithm: 'HS256' | 'HS384' | 'HS512') {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: `SHA-${algorithm.slice(2)}` }, false, ['sign'])
    .then(async (key) => {
      const signed = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value))
      const bytes = new Uint8Array(signed)
      let binary = ''
      bytes.forEach((byte) => { binary += String.fromCharCode(byte) })
      return `${value}.${btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')}`
    })
}

test('parses three-part JWTs and two-part alg none tokens', () => {
  const standard = analyzeJwt(token({ alg: 'HS256', typ: 'JWT' }, { iss: 'i', aud: 'a', sub: 's', exp: 2_000_000_000 }, 'c2ln'))
  assert.equal(standard.ok, true)
  if (standard.ok) assert.equal(standard.analysis.payload.iss, 'i')
  const twoPart = `${base64Url('{"alg":"none","typ":"JWT"}')}.${base64Url('{"iss":"i","aud":"a","sub":"s"}')}`
  const none = analyzeJwt(twoPart)
  assert.equal(none.ok, true)
  if (none.ok) assert.ok(none.analysis.findings.some(({ title }) => title === 'Unsigned token algorithm'))
})

test('normalizes Bearer and newline-wrapped token input', () => {
  const raw = token()
  const parsed = analyzeJwt(`  bEaReR  \n${raw}\n `)
  assert.equal(parsed.ok, true)
  if (parsed.ok) assert.equal(parsed.analysis.token, raw)
})

test('detects none algorithms case-insensitively and empty signatures for other algorithms', () => {
  for (const alg of ['none', 'None', 'NONE']) {
    const parsed = analyzeJwt(token({ alg }, {}))
    assert.equal(parsed.ok, true)
    if (parsed.ok) assert.ok(parsed.analysis.findings.some(({ severity, title }) => severity === 'critical' && title === 'Unsigned token algorithm'))
  }
  const emptySignature = analyzeJwt(token({ alg: 'RS256' }, {}))
  assert.equal(emptySignature.ok, true)
  if (emptySignature.ok) assert.ok(emptySignature.analysis.findings.some(({ title }) => title === 'Empty signature'))
})

test('reports expiration, future times, missing exp, and malformed timestamps', () => {
  const now = 1_700_000_000_000
  const expired = analyzeJwt(token({ alg: 'none' }, { iss: 'i', aud: 'a', sub: 's', exp: 1_600_000_000, iat: 1_500_000_000 }), now)
  assert.equal(expired.ok, true)
  if (expired.ok) {
    assert.ok(expired.analysis.findings.some(({ title }) => title === 'Token is expired'))
    assert.ok(expired.analysis.findings.some(({ title }) => title === 'Long token lifetime'))
    assert.match(expired.analysis.timestamps.find(({ claim }) => claim === 'exp')?.utc ?? '', /UTC$/)
    assert.equal(expired.analysis.timestamps.find(({ claim }) => claim === 'exp')?.relative, '3 years ago')
  }
  const future = analyzeJwt(token({ alg: 'none' }, { exp: 1_800_000_000, nbf: 1_800_000_000, iat: 1_800_000_000 }), now)
  assert.equal(future.ok, true)
  if (future.ok) {
    assert.ok(future.analysis.findings.some(({ title }) => title === 'Token is not active yet'))
    assert.ok(future.analysis.findings.some(({ title }) => title === 'Issued-at time is in the future'))
    assert.ok(future.analysis.findings.some(({ title }) => title === 'No expiration claim') === false)
  }
  const missingExp = analyzeJwt(token({ alg: 'none' }, { iss: 'i', aud: 'a', sub: 's' }), now)
  assert.equal(missingExp.ok, true)
  if (missingExp.ok) assert.ok(missingExp.analysis.findings.some(({ title }) => title === 'No expiration claim'))
  const malformed = analyzeJwt(token({ alg: 'none' }, { exp: 'tomorrow' }), now)
  assert.equal(malformed.ok, true)
  if (malformed.ok) assert.ok(malformed.analysis.findings.some(({ title }) => title === 'Invalid exp claim'))
  const outOfRange = analyzeJwt(token({ alg: 'none' }, { exp: 1e100 }), now)
  assert.equal(outOfRange.ok, true)
  if (outOfRange.ok) assert.ok(outOfRange.analysis.findings.some(({ title }) => title === 'Invalid exp claim'))
})

test('handles valid unpadded Base64URL segments across padding remainders', () => {
  for (let length = 0; length < 16; length += 1) {
    const parsed = analyzeJwt(token({ alg: 'none' }, { text: 'x'.repeat(length) }))
    assert.equal(parsed.ok, true, `payload fill length ${length}`)
  }
  for (const remainder of [2, 3]) {
    let payloadPart = ''
    for (let fill = 0; fill < 8; fill += 1) {
      const candidate = base64Url(JSON.stringify({ data: 'x'.repeat(fill) }))
      if (candidate.length % 4 === remainder) { payloadPart = candidate; break }
    }
    assert.ok(payloadPart)
    const padded = `${base64Url('{"alg":"none"}')}.${payloadPart}${'='.repeat(4 - remainder)}.`
    assert.equal(analyzeJwt(padded).ok, true, `${4 - remainder} required padding characters`)
  }
  assert.deepEqual(analyzeJwt(`A.${base64Url('{}')}.`), { ok: false, error: 'Header is not valid Base64URL' })
})

test('decodes Unicode payload text', () => {
  const parsed = analyzeJwt(token({ alg: 'none' }, { message: 'snowman ☃ and café' }))
  assert.equal(parsed.ok, true)
  if (parsed.ok) assert.equal(parsed.analysis.payload.message, 'snowman ☃ and café')
})

test('returns specific errors for malformed token segments and JSON shapes', () => {
  assert.deepEqual(analyzeJwt('one'), { ok: false, error: 'Token must have 3 parts' })
  assert.deepEqual(analyzeJwt('a.b.c.d'), { ok: false, error: 'Token must have 3 parts' })
  assert.deepEqual(analyzeJwt('@@@.e30.'), { ok: false, error: 'Header is not valid Base64URL' })
  assert.deepEqual(analyzeJwt(`${base64Url('not json')}.${base64Url('{}')}.`), { ok: false, error: 'Header is not valid JSON' })
  assert.deepEqual(analyzeJwt(`${base64Url('{}')}.${base64Url('not json')}.`), { ok: false, error: 'Payload is not valid JSON' })
  assert.deepEqual(analyzeJwt(`${base64Url('[]')}.${base64Url('{}')}.`), { ok: false, error: 'Header must be a JSON object' })
  assert.deepEqual(analyzeJwt(`${base64Url('{}')}.${base64Url('[]')}.`), { ok: false, error: 'Payload must be a JSON object' })
  assert.deepEqual(analyzeJwt('a'.repeat(8193)), { ok: false, error: 'Token exceeds the 8 KiB size limit.' })
})

test('finds risky key sources, kid, and sensitive-looking payload claims', () => {
  const parsed = analyzeJwt(token({ alg: 'RS256', jku: 'https://keys.invalid', kid: '../../key', x5u: 'x', jwk: {}, x5c: [] }, { profile: { password: 'hidden', cardNumber: 'hidden', ssn: 'hidden' } }))
  assert.equal(parsed.ok, true)
  if (parsed.ok) {
    const titles = parsed.analysis.findings.map(({ title }) => title)
    for (const title of ['Key source in header: jku', 'Key source in header: x5u', 'Key source in header: jwk', 'Key source in header: x5c', 'Key ID is user-controlled', 'Sensitive-looking payload keys', 'Asymmetric algorithm']) assert.ok(titles.includes(title), title)
  }
})

test('reports missing identity claims and a token type other than the exact JWT label', () => {
  const parsed = analyzeJwt(token({ alg: 'custom', typ: 'jwt' }, {}))
  assert.equal(parsed.ok, true)
  if (parsed.ok) {
    const titles = parsed.analysis.findings.map(({ title }) => title)
    for (const title of ['Missing iss claim', 'Missing aud claim', 'Missing sub claim', 'Unexpected token type']) assert.ok(titles.includes(title))
  }
})

test('verifies HS256, HS384, and HS512 signatures and rejects wrong secrets', async () => {
  for (const algorithm of ['HS256', 'HS384', 'HS512'] as const) {
    const source = `${base64Url(JSON.stringify({ alg: algorithm, typ: 'JWT' }))}.${base64Url(JSON.stringify({ iss: 'i', aud: 'a', sub: 's' }))}`
    const signed = await signWithSecret(source, 'strong demo key', algorithm)
    assert.equal((await verifyHmac(signed, 'strong demo key')).status, 'valid', algorithm)
    assert.equal((await verifyHmac(signed, 'wrong key')).status, 'invalid', algorithm)
  }
  assert.equal((await verifyHmac(token({ alg: 'RS256' }, {}), 'secret')).status, 'unsupported')
  assert.equal((await verifyHmac('bad input', 'secret')).status, 'invalid')
})

test('generates a signed demo token and bounds displayed JSON size and depth', async () => {
  const sample = await createSampleJwt()
  assert.equal((await verifyHmac(sample, 'demo-secret')).status, 'valid')
  const deep = { a: { b: { c: { d: { e: 'value' } } } } }
  assert.match(formatJsonForDisplay(deep, 1000, 2), /Nested content omitted/)
  assert.ok(formatJsonForDisplay({ content: 'x'.repeat(1000) }, 100).length < 150)
})
