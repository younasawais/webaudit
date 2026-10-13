import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isPrivateIp, parseAuditUrl } from '../src/index.js'

test('parseAuditUrl adds https to bare domains', () => {
  const url = parseAuditUrl('example.com')
  assert.equal(url.protocol, 'https:')
  assert.equal(url.hostname, 'example.com')
})

test('parseAuditUrl keeps an explicit scheme and path', () => {
  const url = parseAuditUrl('http://example.com/pricing')
  assert.equal(url.protocol, 'http:')
  assert.equal(url.pathname, '/pricing')
})

test('parseAuditUrl rejects empty and non-URL input', () => {
  assert.throws(() => parseAuditUrl('   '))
  assert.throws(() => parseAuditUrl('not a url'))
  assert.throws(() => parseAuditUrl('singleword'))
})

test('private and reserved IPv4 ranges are flagged', () => {
  for (const ip of ['10.0.0.1', '127.0.0.1', '192.168.1.1', '172.16.0.1', '169.254.1.1', '100.64.0.1', '0.0.0.0', '224.0.0.1']) {
    assert.equal(isPrivateIp(ip), true, ip)
  }
})

test('public IPv4 addresses are not flagged', () => {
  for (const ip of ['1.1.1.1', '8.8.8.8', '93.184.216.34']) {
    assert.equal(isPrivateIp(ip), false, ip)
  }
})

test('private IPv6 forms are flagged, including IPv4-mapped', () => {
  for (const ip of ['::1', 'fe80::1', 'fd00::1', '::ffff:192.168.0.1', '2001:db8::1']) {
    assert.equal(isPrivateIp(ip), true, ip)
  }
  assert.equal(isPrivateIp('2606:4700:4700::1111'), false)
})
