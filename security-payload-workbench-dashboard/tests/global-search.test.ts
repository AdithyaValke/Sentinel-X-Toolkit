import assert from 'node:assert/strict'
import test from 'node:test'
import { GLOBAL_SEARCH_INDEX, searchGlobal } from '../lib/global-search.ts'
import { PAYLOAD_GENERATOR_CATALOG_ENTRY } from '../lib/security-lab-catalog.ts'

test('indexes all main destinations and offers concise empty-query suggestions', () => {
  assert.deepEqual(GLOBAL_SEARCH_INDEX.map(({ href }) => href), [
    '/dashboard', '/security-lab?tab=payload-generator', '/payload-tools', '/hash-tools', '/identify-hash', '/security-lab',
  ])
  assert.deepEqual(searchGlobal('').map(({ href }) => href), [
    '/dashboard', '/security-lab?tab=payload-generator', '/payload-tools', '/hash-tools',
  ])
})

test('matches titles case-insensitively, partially, and after trimming whitespace', () => {
  assert.equal(searchGlobal('  PAYLOAD  ')[0]?.href, PAYLOAD_GENERATOR_CATALOG_ENTRY.href)
  assert.equal(searchGlobal('dash')[0]?.href, '/dashboard')
})

test('exposes the existing safe Payload Generator in the Security Lab catalog and search', () => {
  const generator = GLOBAL_SEARCH_INDEX.find(({ title }) => title === 'Payload Generator')
  assert.ok(generator)
  assert.equal(generator.href, '/security-lab?tab=payload-generator')
  assert.match(generator.description, /non-executable/i)
  assert.equal(searchGlobal('Payload Generator')[0]?.href, generator.href)
  assert.equal(searchGlobal('payload')[0]?.href, generator.href)
  assert.equal(searchGlobal('Payload Tools')[0]?.href, '/payload-tools')
  assert.equal(searchGlobal('connectivity test')[0]?.href, generator.href)
})

test('matches descriptions and verified tool synonyms', () => {
  assert.equal(searchGlobal('sha-512')[0]?.href, '/hash-tools')
  assert.equal(searchGlobal('likely algorithms')[0]?.href, '/identify-hash')
  assert.equal(searchGlobal('defang')[0]?.href, '/security-lab')
})

test('ranks title matches first, limits results, and returns no duplicates or false matches', () => {
  const results = searchGlobal('hash')
  assert.equal(results[0]?.href, '/hash-tools')
  assert.ok(results.length <= 5)
  assert.equal(new Set(results.map(({ href }) => href)).size, results.length)
  assert.deepEqual(searchGlobal('nothing matches'), [])
})
