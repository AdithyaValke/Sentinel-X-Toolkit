import assert from 'node:assert/strict'
import test from 'node:test'
import { formatHttpUrl, validateIP, validateIPv6 } from '../lib/security-lab-utils.ts'

test('validates full, compressed, and IPv4-mapped IPv6 addresses', () => {
  for (const address of ['2001:0db8:0000:0000:0000:ff00:0042:8329', '2001:db8::ff00:42:8329', '::1', '::', '::ffff:192.0.2.1']) {
    assert.equal(validateIPv6(address), true, address)
    assert.equal(validateIP(address).valid, true, address)
  }
})

test('rejects malformed, bracketed, and scoped IPv6 input', () => {
  for (const address of ['2001:db8:::1', '2001:db8::g', '1:2:3:4:5:6:7:8:9', '[::1]', 'fe80::1%eth0']) {
    assert.equal(validateIPv6(address), false, address)
    assert.equal(validateIP(address).valid, false, address)
  }
})

test('formats IPv4 and IPv6 HTTP URLs correctly', () => {
  assert.equal(formatHttpUrl('192.0.2.10', 8080), 'http://192.0.2.10:8080/')
  assert.equal(formatHttpUrl('2001:db8::1', 8080), 'http://[2001:db8::1]:8080/')
})
