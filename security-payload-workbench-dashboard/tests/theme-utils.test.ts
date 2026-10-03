import assert from 'node:assert/strict'
import test from 'node:test'
import { isDarkTheme, parseThemePreference } from '../lib/theme-utils.ts'

test('uses system preference on first visit and rejects invalid stored preferences', () => {
  assert.equal(parseThemePreference(null), 'system')
  assert.equal(parseThemePreference('not-a-theme'), 'system')
  assert.equal(isDarkTheme(parseThemePreference(null), true), true)
  assert.equal(isDarkTheme(parseThemePreference(null), false), false)
})

test('resolves and persists explicit light and dark preferences independently of system settings', () => {
  assert.equal(parseThemePreference('light'), 'light')
  assert.equal(parseThemePreference('dark'), 'dark')
  assert.equal(isDarkTheme('light', true), false)
  assert.equal(isDarkTheme('dark', false), true)
})
