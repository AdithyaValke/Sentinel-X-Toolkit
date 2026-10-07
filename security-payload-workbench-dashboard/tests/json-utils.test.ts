import assert from 'node:assert/strict'
import test from 'node:test'
import { formatJsonInput, minifyJsonInput, validateAndFormatJson } from '../lib/json-utils.ts'

test('validates and formats JSON with preserved types', () => {
  const result = validateAndFormatJson('{"enabled":true,"count":2}', 2)
  assert.equal(result.valid, true)
  if (result.valid) assert.equal(result.formatted, '{\n  "enabled": true,\n  "count": 2\n}')
})

test('reports invalid and empty JSON without throwing', () => {
  assert.equal(validateAndFormatJson('{bad', 2).valid, false)
  assert.equal(validateAndFormatJson('   ', 2).valid, false)
})

test('supports tabs and compact minification', () => {
  assert.equal(formatJsonInput('{"a":{"b":1}}', 'tab'), '{\n\t"a": {\n\t\t"b": 1\n\t}\n}')
  assert.equal(minifyJsonInput('{ "a": true, "items": [1, 2] }'), '{"a":true,"items":[1,2]}')
})
