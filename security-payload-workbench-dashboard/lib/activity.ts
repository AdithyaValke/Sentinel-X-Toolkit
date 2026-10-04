export type ActivityOutcome = 'success' | 'failure'

export type ActivityRecord = {
  id: string
  timestamp: string
  tool: string
  operation: string
  outcome: ActivityOutcome
  description: string
}

export interface ActivityStore {
  read(): ActivityRecord[]
  add(record: ActivityRecord): void
  clear(): void
  subscribe(listener: () => void): () => void
}

const STORAGE_KEY = 'payload-workbench:recent-activity:v1'
const MAX_EVENTS = 50
const listeners = new Set<() => void>()
const EMPTY: ActivityRecord[] = []
let snapshot: ActivityRecord[] = EMPTY
let hydrated = false

function validRecord(value: unknown): value is ActivityRecord {
  if (!value || typeof value !== 'object') return false
  const item = value as Record<string, unknown>
  return typeof item.id === 'string' && item.id.length <= 100
    && typeof item.timestamp === 'string' && Number.isFinite(Date.parse(item.timestamp))
    && typeof item.tool === 'string' && item.tool.length <= 80
    && typeof item.operation === 'string' && item.operation.length <= 100
    && (item.outcome === 'success' || item.outcome === 'failure')
    && typeof item.description === 'string' && item.description.length <= 160
}

function notify() { for (const listener of listeners) listener() }

export const localActivityStore: ActivityStore = {
  read() {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY)
      if (!raw) return EMPTY
      const parsed: unknown = JSON.parse(raw)
      if (!Array.isArray(parsed)) return EMPTY
      return parsed.filter(validRecord).sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp)).slice(0, MAX_EVENTS)
    } catch { return EMPTY }
  },
  add(record) {
    const current = getActivitySnapshot()
    snapshot = [record, ...current.filter((item) => item.id !== record.id)].slice(0, MAX_EVENTS)
    hydrated = true
    try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(snapshot)) } catch { /* Storage must never interrupt a tool operation. */ }
    notify()
  },
  clear() {
    snapshot = EMPTY
    hydrated = true
    try { window.localStorage.removeItem(STORAGE_KEY) } catch { /* Storage may be unavailable. */ }
    notify()
  },
  subscribe(listener) {
    listeners.add(listener)
    const onStorage = (event: StorageEvent) => {
      if (event.key === STORAGE_KEY || event.key === null) {
        snapshot = localActivityStore.read()
        hydrated = true
        listener()
      }
    }
    window.addEventListener('storage', onStorage)
    return () => { listeners.delete(listener); window.removeEventListener('storage', onStorage) }
  },
}

export function recordActivity(tool: string, operation: string, outcome: ActivityOutcome, description: string) {
  if (typeof window === 'undefined') return
  localActivityStore.add({ id: globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`, timestamp: new Date().toISOString(), tool, operation, outcome, description })
}

export function getActivitySnapshot() {
  if (typeof window === 'undefined') return EMPTY
  if (!hydrated) { snapshot = localActivityStore.read(); hydrated = true }
  return snapshot
}
export function getActivityServerSnapshot() { return EMPTY }

const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>()
export function recordActivityDebounced(key: string, tool: string, operation: string, outcome: ActivityOutcome, description: string, delay = 500) {
  const previous = debounceTimers.get(key)
  if (previous) clearTimeout(previous)
  debounceTimers.set(key, setTimeout(() => {
    debounceTimers.delete(key)
    recordActivity(tool, operation, outcome, description)
  }, delay))
}
export function cancelActivityDebounce(key: string) {
  const timer = debounceTimers.get(key)
  if (timer) clearTimeout(timer)
  debounceTimers.delete(key)
}
