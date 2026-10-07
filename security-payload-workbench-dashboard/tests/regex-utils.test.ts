import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeRegex, countLines, MAX_REGEX_INPUT_LENGTH, REGEX_PRESETS } from '../lib/regex-utils.ts'

test('analyzes matches, positions, flags, and capture groups', () => {
  const result = analyzeRegex('(error|warn): (\\w+)', 'ERROR: disk\nwarn: auth', 'gim')
  assert.equal(result.matches.length, 2)
  assert.equal(result.matches[0].line, 1)
  assert.equal(result.matches[1].line, 2)
  assert.deepEqual(result.matches[0].groups, ['ERROR', 'disk'])
})
test('returns a friendly invalid-regex error', () => assert.match(analyzeRegex('[', 'text', 'g').error ?? '', /Invalid regular expression|unterminated/i))
test('empty pattern returns no matches for non-empty input', () => assert.deepEqual(analyzeRegex('', 'some input', 'g').matches, []))
test('whitespace-only pattern returns no matches for non-empty input', () => assert.deepEqual(analyzeRegex(' \t\n ', 'some input', 'g').matches, []))
test('empty pattern returns no matches for empty input', () => assert.deepEqual(analyzeRegex('', '', 'g').matches, []))
test('invalid regex still reports the existing error behavior', () => assert.match(analyzeRegex('[', 'text', 'g').error ?? '', /Invalid regular expression|unterminated/i))
test('supports presets and no-match states', () => {
  const preset = REGEX_PRESETS.Email
  assert.equal(analyzeRegex(preset.pattern, 'analyst@example.com', preset.flags).matches[0].value, 'analyst@example.com')
  assert.deepEqual(analyzeRegex('xyz', 'abc', 'g').matches, [])
})
test('counts lines and bounds large input', () => {
  assert.equal(countLines('one\ntwo\nthree'), 3)
  assert.match(analyzeRegex('.', 'x'.repeat(MAX_REGEX_INPUT_LENGTH + 1), 'g').error ?? '', /limited/)
})
