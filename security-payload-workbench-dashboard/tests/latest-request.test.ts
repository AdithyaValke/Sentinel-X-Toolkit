import assert from 'node:assert/strict'
import test from 'node:test'
import { LatestRequest } from '../lib/latest-request.ts'

test('only the newest request can publish a result', async () => {
  const latest = new LatestRequest()
  const first = latest.begin()
  let releaseFirst!: (value: string) => void
  const firstResult = new Promise<string>((resolve) => { releaseFirst = resolve })
  const second = latest.begin()
  assert.equal(first.signal.aborted, true)
  assert.equal(latest.isCurrent(first.id), false)

  releaseFirst('older result')
  assert.equal(await firstResult, 'older result')
  assert.equal(latest.isCurrent(second.id), true)
})

test('cancelling on unmount invalidates the active request', () => {
  const latest = new LatestRequest()
  const request = latest.begin()
  latest.cancel()
  assert.equal(request.signal.aborted, true)
  assert.equal(latest.isCurrent(request.id), false)
})
