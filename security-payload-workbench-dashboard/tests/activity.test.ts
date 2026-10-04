import assert from 'node:assert/strict'
import test from 'node:test'
import { getActivitySnapshot, localActivityStore, recordActivity, type ActivityRecord } from '../lib/activity.ts'

function installStorage(initial: Record<string, string> = {}, failWrites = false) {
  const values = new Map(Object.entries(initial))
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { if (failWrites) throw new Error('quota'); values.set(key, value) },
    removeItem: (key: string) => { values.delete(key) },
  }
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { localStorage: storage, addEventListener() {}, removeEventListener() {} } })
  return values
}

test('activity storage validates malformed records and retains at most 50 newest events', () => {
  const values = Array.from({ length: 55 }, (_, index) => ({
    id: String(index), timestamp: new Date(index * 1000).toISOString(), tool: 'Test', operation: 'run', outcome: 'success', description: 'Completed',
  }))
  const storage = installStorage({ 'payload-workbench:recent-activity:v1': JSON.stringify([...values, { id: 'bad' }]) })
  assert.equal(localActivityStore.read().length, 50)
  const newRecord: ActivityRecord = { ...values[54], outcome: 'success', id: 'new', timestamp: new Date().toISOString() }
  localActivityStore.add(newRecord)
  assert.equal(JSON.parse(storage.get('payload-workbench:recent-activity:v1')!).length, 50)
  assert.equal(localActivityStore.read()[0].id, 'new')
})

test('malformed stored JSON and unavailable storage return an empty list', () => {
  installStorage({ 'payload-workbench:recent-activity:v1': '{broken' })
  assert.deepEqual(localActivityStore.read(), [])
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { get localStorage() { throw new Error('blocked') } } })
  assert.deepEqual(localActivityStore.read(), [])
})

test('recording survives quota errors in memory and does not touch unrelated keys', () => {
  const values = installStorage({ preference: 'dark' }, true)
  recordActivity('Test', 'run', 'success', 'Completed')
  assert.equal(getActivitySnapshot()[0]?.description, 'Completed')
  assert.equal(values.get('preference'), 'dark')
})
