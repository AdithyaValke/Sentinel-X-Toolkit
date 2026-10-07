import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { HASH_ALGORITHM_OPTIONS } from '../lib/hash-algorithms.ts'

test('Hash Converter exposes each supported backend algorithm', () => {
  assert.deepEqual(HASH_ALGORITHM_OPTIONS.map(({ value }) => value), [
    'MD5',
    'SHA-1',
    'SHA-224',
    'SHA-256',
    'SHA-384',
    'SHA-512',
    'SHA-512/224',
    'SHA-512/256',
    'SHA3-224',
    'SHA3-256',
    'SHA3-384',
    'SHA3-512',
    'SHAKE-128',
    'SHAKE-256',
  ])
})

test('SHAKE choices disclose their fixed output length', () => {
  const shakeOptions = HASH_ALGORITHM_OPTIONS.filter(({ value }) => value.startsWith('SHAKE'))
  assert.equal(shakeOptions.length, 2)
  assert.ok(shakeOptions.every(({ detail }) => detail.includes('32-byte output')))
})

test('algorithm list is bounded, keyboard reachable, and theme-aware', () => {
  const css = readFileSync(new URL('../app/globals.css', import.meta.url), 'utf8')
  const component = readFileSync(new URL('../components/hash-converter.tsx', import.meta.url), 'utf8')
  assert.match(css, /\.hash-option-list\s*\{[^}]*max-h-\[24rem\][^}]*overflow-y-auto/)
  assert.match(css, /html\.light \.hash-option-list \{[^}]*scrollbar-color/)
  assert.match(css, /\.hash-option-list::-webkit-scrollbar-thumb/)
  assert.match(component, /className="hash-option-list" role="region" aria-label="Hash algorithms" tabIndex=\{0\}/)
  assert.match(component, /HASH_ALGORITHM_OPTIONS\.map/)
})
