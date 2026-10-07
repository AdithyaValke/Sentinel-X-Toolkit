import { isChainResponse } from './payload-operations.ts'
import type { HashAlgorithm } from './hash-algorithms.ts'

export type { HashAlgorithm } from './hash-algorithms.ts'

export interface HashCandidate {
  algorithm: string;
  hashcat_mode?: string | null;
  evidence: string;
  explanation: string;
}

export interface HashLineAnalysis {
  input_summary?: string;
  input_length: number;
  character_format: string;
  candidates: HashCandidate[];
  is_ambiguous: boolean;
  warning?: string | null;
  recommendation?: string | null;
  result: string;
}

export interface BackendResponse {
  success: boolean;
  result: string;
  error: string | null;
  input_length?: number;
  character_format?: string;
  candidates?: HashCandidate[];
  is_ambiguous?: boolean;
  warning?: string | null;
  recommendation?: string | null;
  lines?: HashLineAnalysis[];
}

function isHashCandidate(value: unknown): value is HashCandidate {
  return Boolean(
    value && typeof value === 'object' &&
    'algorithm' in value && typeof value.algorithm === 'string' &&
    'evidence' in value && typeof value.evidence === 'string' &&
    'explanation' in value && typeof value.explanation === 'string' &&
    (!('hashcat_mode' in value) || value.hashcat_mode === null || typeof value.hashcat_mode === 'string'),
  )
}

function isHashLineAnalysis(value: unknown): value is HashLineAnalysis {
  return Boolean(
    value && typeof value === 'object' &&
    'input_length' in value && typeof value.input_length === 'number' && Number.isFinite(value.input_length) &&
    'character_format' in value && typeof value.character_format === 'string' &&
    'candidates' in value && Array.isArray(value.candidates) && value.candidates.every(isHashCandidate) &&
    'is_ambiguous' in value && typeof value.is_ambiguous === 'boolean' &&
    'result' in value && typeof value.result === 'string',
  )
}

function getApiBaseUrl(): string {
  const configuredUrl = process.env.NEXT_PUBLIC_API_URL?.trim()
  if (!configuredUrl && process.env.NODE_ENV === 'production') {
    throw new Error('NEXT_PUBLIC_API_URL is not configured.')
  }
  const baseUrl = configuredUrl || 'http://localhost:8000'
  let parsedUrl: URL
  try {
    parsedUrl = new URL(baseUrl)
  } catch {
    throw new Error('NEXT_PUBLIC_API_URL must be an absolute HTTP(S) URL.')
  }
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    throw new Error('NEXT_PUBLIC_API_URL must use HTTP or HTTPS.')
  }
  if (process.env.NODE_ENV === 'production' && parsedUrl.protocol !== 'https:') {
    throw new Error('NEXT_PUBLIC_API_URL must use HTTPS in production.')
  }
  if (process.env.NODE_ENV !== 'production' && parsedUrl.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(parsedUrl.hostname)) {
    throw new Error('NEXT_PUBLIC_API_URL may use HTTP only for localhost development.')
  }
  return baseUrl.replace(/\/+$/, '')
}

export interface AuthApiUser {
  id?: string | number
  display_name?: string | null
  name?: string | null
  email: string
}

export interface Investigation {
  id: number
  title: string
  description: string | null
  status: 'open' | 'investigating' | 'resolved' | 'closed'
  created_at: string
  updated_at: string
  closed_at: string | null
}

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function investigationRequest(path: string, options: RequestInit = {}) {
  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    ...options,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...options.headers },
  })
  const data: unknown = await response.json().catch(() => null)
  if (!response.ok) throw new ApiError(
    response.status === 503 ? 'Investigation service is temporarily unavailable. Try again shortly.' : getErrorMessage(data, 'Investigation request failed.'),
    response.status,
  )
  return data
}

function isInvestigation(value: unknown): value is Investigation {
  if (!value || typeof value !== 'object') return false
  const item = value as Record<string, unknown>
  return Number.isInteger(item.id) && typeof item.title === 'string' &&
    (item.description === null || typeof item.description === 'string') &&
    ['open', 'investigating', 'resolved', 'closed'].includes(String(item.status)) &&
    typeof item.created_at === 'string' && typeof item.updated_at === 'string' &&
    (item.closed_at === null || typeof item.closed_at === 'string')
}

export interface InvestigationListPage {
  items: Investigation[]
  limit: number
  offset: number
}

export async function listInvestigationsPage(page: { limit?: number; offset?: number } = {}): Promise<InvestigationListPage> {
  const limit = page.limit ?? 20
  const offset = page.offset ?? 0
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  const data = await investigationRequest(`/api/investigations?${query}`)
  if (!data || typeof data !== 'object') throw new ApiError('Invalid investigations response.', 502)
  const response = data as Record<string, unknown>
  if (!Array.isArray(response.items) || !response.items.every(isInvestigation) ||
    !Number.isInteger(response.limit) || (response.limit as number) < 1 || (response.limit as number) > 100 ||
    !Number.isInteger(response.offset) || (response.offset as number) < 0) {
    throw new ApiError('Invalid investigations response.', 502)
  }
  return { items: response.items, limit: response.limit as number, offset: response.offset as number }
}

export async function listInvestigations(): Promise<Investigation[]> {
  return (await listInvestigationsPage()).items
}

export async function getInvestigation(id: string): Promise<Investigation> {
  const data = await investigationRequest(`/api/investigations/${encodeURIComponent(id)}`)
  if (!data || typeof data !== 'object' || !('item' in data)) throw new ApiError('Invalid investigation response.', 502)
  return (data as { item: Investigation }).item
}

export interface InvestigationIOC {
  id: number
  investigation_id: number
  ioc_type: 'ip' | 'domain' | 'hash' | 'email'
  value: string
  normalized_value: string
  source: 'manual' | 'extractor' | 'log_analyzer' | 'integration'
  confidence: number | null
  first_seen: string | null
  last_seen: string | null
  created_at: string
}

function isInvestigationIOC(value: unknown): value is InvestigationIOC {
  if (!value || typeof value !== 'object') return false
  const item = value as Record<string, unknown>
  return Number.isInteger(item.id) && Number.isInteger(item.investigation_id) &&
    ['ip', 'domain', 'hash', 'email'].includes(String(item.ioc_type)) &&
    typeof item.value === 'string' && typeof item.normalized_value === 'string' &&
    ['manual', 'extractor', 'log_analyzer', 'integration'].includes(String(item.source)) &&
    (item.confidence === null || (Number.isInteger(item.confidence) && (item.confidence as number) >= 0 && (item.confidence as number) <= 100)) &&
    (item.first_seen === null || typeof item.first_seen === 'string') &&
    (item.last_seen === null || typeof item.last_seen === 'string') && typeof item.created_at === 'string'
}

export const FINDING_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const
export type FindingSeverity = typeof FINDING_SEVERITIES[number]

export interface InvestigationFinding {
  id: number
  investigation_id: number
  title: string
  description: string | null
  severity: FindingSeverity
  status: 'open' | 'confirmed' | 'dismissed' | 'resolved'
  source: string | null
  created_at: string
  updated_at: string
}

function isInvestigationFinding(value: unknown): value is InvestigationFinding {
  if (!value || typeof value !== 'object') return false
  const item = value as Record<string, unknown>
  return Number.isInteger(item.id) && Number.isInteger(item.investigation_id) &&
    typeof item.title === 'string' && (item.description === null || typeof item.description === 'string') &&
    FINDING_SEVERITIES.includes(item.severity as FindingSeverity) &&
    ['open', 'confirmed', 'dismissed', 'resolved'].includes(String(item.status)) &&
    (item.source === null || typeof item.source === 'string') &&
    typeof item.created_at === 'string' && typeof item.updated_at === 'string'
}

export async function createInvestigation(payload: { title: string; description?: string }): Promise<Investigation> {
  const data = await investigationRequest('/api/investigations', { method: 'POST', body: JSON.stringify(payload) })
  if (!data || typeof data !== 'object' || !('item' in data)) throw new ApiError('Invalid investigation response.', 502)
  return (data as { item: Investigation }).item
}

export type UpdateInvestigationPayload = Partial<Pick<Investigation, 'title' | 'description' | 'status'>>

export async function updateInvestigation(id: string, payload: UpdateInvestigationPayload): Promise<Investigation> {
  const data = await investigationRequest(`/api/investigations/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(payload) })
  if (!data || typeof data !== 'object' || !('item' in data) || !isInvestigation((data as { item: unknown }).item)) throw new ApiError('Invalid investigation response.', 502)
  return (data as { item: Investigation }).item
}

export async function deleteInvestigation(id: string): Promise<void> {
  await investigationRequest(`/api/investigations/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export async function listInvestigationIOCs(id: string): Promise<InvestigationIOC[]> {
  const data = await investigationRequest(`/api/investigations/${encodeURIComponent(id)}/iocs`)
  if (!data || typeof data !== 'object' || !Array.isArray((data as { items?: unknown }).items) ||
    !(data as { items: unknown[] }).items.every(isInvestigationIOC)) {
    throw new ApiError('Invalid IOC response.', 502)
  }
  return (data as { items: InvestigationIOC[] }).items
}

export async function createInvestigationIOC(id: string, payload: { ioc_type: InvestigationIOC['ioc_type']; value: string; source?: InvestigationIOC['source'] }): Promise<InvestigationIOC> {
  const data = await investigationRequest(`/api/investigations/${encodeURIComponent(id)}/iocs`, {
    method: 'POST',
    body: JSON.stringify(payload),
  })
  if (!data || typeof data !== 'object' || !('item' in data) || !isInvestigationIOC(data.item)) throw new ApiError('Invalid IOC response.', 502)
  return (data as { item: InvestigationIOC }).item
}

export async function listInvestigationFindings(id: string): Promise<InvestigationFinding[]> {
  const data = await investigationRequest(`/api/investigations/${encodeURIComponent(id)}/findings`)
  if (!data || typeof data !== 'object' || !Array.isArray((data as { items?: unknown }).items) ||
    !(data as { items: unknown[] }).items.every(isInvestigationFinding)) {
    throw new ApiError('Invalid finding response.', 502)
  }
  return (data as { items: InvestigationFinding[] }).items
}

export async function createInvestigationFinding(
  id: string,
  payload: { title: string; description?: string; severity: FindingSeverity },
): Promise<InvestigationFinding> {
  const data = await investigationRequest(`/api/investigations/${encodeURIComponent(id)}/findings`, {
    method: 'POST', body: JSON.stringify(payload),
  })
  if (!data || typeof data !== 'object' || !('item' in data) || !isInvestigationFinding(data.item)) {
    throw new ApiError('Invalid finding response.', 502)
  }
  return data.item
}

export interface InvestigationEvidence {
  id: number
  investigation_id: number
  finding_id: number | null
  evidence_type: string
  title: string
  content: string
  source: string | null
  created_at: string
}

function isInvestigationEvidence(value: unknown): value is InvestigationEvidence {
  if (!value || typeof value !== 'object') return false
  const item = value as Record<string, unknown>
  return Number.isInteger(item.id) && Number.isInteger(item.investigation_id) &&
    (item.finding_id === null || Number.isInteger(item.finding_id)) &&
    typeof item.evidence_type === 'string' && /^[a-z][a-z0-9_]*$/.test(item.evidence_type) &&
    typeof item.title === 'string' && typeof item.content === 'string' &&
    (item.source === null || typeof item.source === 'string') && typeof item.created_at === 'string'
}

export async function listInvestigationEvidence(id: string): Promise<InvestigationEvidence[]> {
  const data = await investigationRequest(`/api/investigations/${encodeURIComponent(id)}/evidence`)
  if (!data || typeof data !== 'object' || !Array.isArray((data as { items?: unknown }).items) ||
    !(data as { items: unknown[] }).items.every(isInvestigationEvidence)) {
    throw new ApiError('Invalid evidence response.', 502)
  }
  return (data as { items: InvestigationEvidence[] }).items
}

export async function createInvestigationEvidence(
  id: string,
  payload: { evidence_type: string; title: string; content: string },
): Promise<InvestigationEvidence> {
  const data = await investigationRequest(`/api/investigations/${encodeURIComponent(id)}/evidence`, {
    method: 'POST', body: JSON.stringify(payload),
  })
  if (!data || typeof data !== 'object' || !('item' in data) || !isInvestigationEvidence(data.item)) {
    throw new ApiError('Invalid evidence response.', 502)
  }
  return data.item
}

export type InvestigationTimelineEventType = 'created' | 'status_changed' | 'ioc_added' | 'finding_created' | 'evidence_added'

export interface InvestigationTimelineEvent {
  id: number
  investigation_id: number
  event_type: InvestigationTimelineEventType
  message: string
  created_at: string
}

export interface InvestigationTimelinePage {
  items: InvestigationTimelineEvent[]
  limit: number
  offset: number
}

const investigationTimelineEventTypes: InvestigationTimelineEventType[] = [
  'created', 'status_changed', 'ioc_added', 'finding_created', 'evidence_added',
]

function isInvestigationTimelineEvent(value: unknown): value is InvestigationTimelineEvent {
  if (!value || typeof value !== 'object') return false
  const item = value as Record<string, unknown>
  return Number.isInteger(item.id) && Number.isInteger(item.investigation_id) &&
    investigationTimelineEventTypes.includes(item.event_type as InvestigationTimelineEventType) &&
    typeof item.message === 'string' && typeof item.created_at === 'string'
}

export async function listInvestigationTimeline(
  id: string,
  page: { limit?: number; offset?: number } = {},
): Promise<InvestigationTimelinePage> {
  const limit = page.limit ?? 20
  const offset = page.offset ?? 0
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  const data = await investigationRequest(`/api/investigations/${encodeURIComponent(id)}/timeline?${query}`)
  if (!data || typeof data !== 'object') throw new ApiError('Invalid timeline response.', 502)
  const response = data as Record<string, unknown>
  if (!Array.isArray(response.items) || !response.items.every(isInvestigationTimelineEvent) ||
    !Number.isInteger(response.limit) || (response.limit as number) < 1 || (response.limit as number) > 100 ||
    !Number.isInteger(response.offset) || (response.offset as number) < 0) {
    throw new ApiError('Invalid timeline response.', 502)
  }
  return { items: response.items, limit: response.limit as number, offset: response.offset as number }
}

function getErrorMessage(data: unknown, fallback: string) {
  if (!data || typeof data !== 'object') return fallback
  const value = data as Record<string, unknown>
  const message = value.error ?? value.message ?? value.detail
  return typeof message === 'string' && message.trim() ? message : fallback
}

async function authRequest(path: string, options: RequestInit = {}) {
  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    ...options,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...options.headers },
  })
  const data: unknown = await response.json().catch(() => null)
  if (!response.ok) throw new ApiError(getErrorMessage(data, 'Authentication request failed.'), response.status)
  return data
}

export async function getCurrentUser(): Promise<AuthApiUser | null> {
  const response = await fetch(`${getApiBaseUrl()}/api/auth/me`, { credentials: 'include' })
  if (response.status === 401 || response.status === 403) return null
  const data: unknown = await response.json().catch(() => null)
  if (!response.ok) throw new ApiError(getErrorMessage(data, 'Could not check your session.'), response.status)
  if (!data || typeof data !== 'object') return null
  const value = data as Record<string, unknown>
  const user = (value.user && typeof value.user === 'object' ? value.user : value) as Record<string, unknown>
  return typeof user.email === 'string' ? user as unknown as AuthApiUser : null
}

export async function registerAccount(payload: { display_name: string; email: string; password: string }) {
  return authRequest('/api/auth/register', { method: 'POST', body: JSON.stringify(payload) })
}

export async function login(payload: { email: string; password: string }) {
  return authRequest('/api/auth/login', { method: 'POST', body: JSON.stringify(payload) })
}

export async function logout() {
  await authRequest('/api/auth/logout', { method: 'POST', body: JSON.stringify({}) })
}

export async function checkBackendHealth(signal?: AbortSignal) {
  const controller = new AbortController()
  const abort = () => controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) abort()
  const timeout = setTimeout(() => controller.abort(), 5000)
  try {
    const response = await fetch(`${getApiBaseUrl()}/health`, { signal: controller.signal })
    if (!response.ok) return false
    const data: unknown = await response.json()
    return Boolean(data && typeof data === 'object' && 'status' in data && data.status === 'ok')
  } catch {
    return false
  } finally {
    signal?.removeEventListener('abort', abort)
    clearTimeout(timeout)
  }
}

export async function callBackend(
  operation: string,
  inputText: string,
  hashAlgo: HashAlgorithm | null = null,
  signal?: AbortSignal
): Promise<BackendResponse> {
  const baseUrl = getApiBaseUrl();
  const url = `${baseUrl}/api/process`;
  const payload: Record<string, string> = {
    input_text: inputText,
    operation,
  };
  if (hashAlgo) {
    payload.hash_algorithm = hashAlgo;
  }

  const controller = new AbortController();
  const abort = () => controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) abort()
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const contentType = response.headers.get('content-type') ?? '';
    if (!contentType.includes('application/json')) {
      throw new Error(`The API returned an unexpected response (HTTP ${response.status}).`);
    }
    const data: unknown = await response.json();
    if (
      !data ||
      typeof data !== 'object' ||
      !('success' in data) ||
      typeof data.success !== 'boolean' ||
      !('result' in data) ||
      typeof data.result !== 'string' ||
      ('error' in data && data.error !== null && typeof data.error !== 'string') ||
      ('input_length' in data && (typeof data.input_length !== 'number' || !Number.isFinite(data.input_length))) ||
      ('character_format' in data && typeof data.character_format !== 'string') ||
      ('candidates' in data && (!Array.isArray(data.candidates) || !data.candidates.every(isHashCandidate))) ||
      ('is_ambiguous' in data && typeof data.is_ambiguous !== 'boolean') ||
      ('warning' in data && data.warning !== null && typeof data.warning !== 'string') ||
      ('recommendation' in data && data.recommendation !== null && typeof data.recommendation !== 'string') ||
      ('lines' in data && (!Array.isArray(data.lines) || !data.lines.every(isHashLineAnalysis)))
    ) {
      throw new Error('The API returned an invalid response.');
    }
    const parsed = data as BackendResponse;
    if (!response.ok) {
      throw new Error(parsed.error || `The API returned HTTP ${response.status}.`);
    }
    return {
      success: parsed.success,
      result: parsed.result,
      error: parsed.error ?? null,
      input_length: parsed.input_length,
      character_format: parsed.character_format,
      candidates: parsed.candidates,
      is_ambiguous: parsed.is_ambiguous,
      warning: parsed.warning,
      recommendation: parsed.recommendation,
      lines: parsed.lines,
    };
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      if (signal?.aborted) throw error
      throw new Error('The request timed out. Check that the Flask API is running and reachable.');
    }
    if (error instanceof TypeError) {
      throw new Error('Could not reach the Flask API. Check its URL and CORS settings.');
    }
    throw error;
  } finally {
    signal?.removeEventListener('abort', abort)
    clearTimeout(timeout);
  }
}

export type IndicatorCategory = 'ip' | 'domain' | 'hash' | 'email'
export interface IocResult { category: IndicatorCategory; value: string; occurrences: number; context: string }
export interface IocResponse {
  success: boolean
  results: IocResult[]
  summary: { unique: number; occurrences: number; by_category: Record<IndicatorCategory, number> }
  error: string | null
}

function isIocResponse(value: unknown): value is IocResponse {
  if (!value || typeof value !== 'object') return false
  const data = value as Record<string, unknown>
  const summary = data.summary as Record<string, unknown> | null
  const counts = summary?.by_category as Record<string, unknown> | null
  return typeof data.success === 'boolean' && Array.isArray(data.results) && data.results.every((item) => {
    if (!item || typeof item !== 'object') return false
    const result = item as Record<string, unknown>
    return ['ip', 'domain', 'hash', 'email'].includes(String(result.category)) && typeof result.value === 'string' && Number.isInteger(result.occurrences) && (result.occurrences as number) > 0 && typeof result.context === 'string'
  }) && !!summary && Number.isInteger(summary.unique) && Number.isInteger(summary.occurrences) && !!counts && ['ip', 'domain', 'hash', 'email'].every((key) => Number.isInteger(counts[key])) && (data.error === null || typeof data.error === 'string')
}

export async function extractIocs(inputText: string, categories: IndicatorCategory[], signal?: AbortSignal): Promise<IocResponse> {
  const controller = new AbortController()
  const abort = () => controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) abort()
  const timeout = setTimeout(() => controller.abort(), 10000)
  try {
    const response = await fetch(`${getApiBaseUrl()}/api/extract-iocs`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input_text: inputText, categories }), signal: controller.signal,
    })
    if (!(response.headers.get('content-type') ?? '').includes('application/json')) throw new Error(`The API returned an unexpected response (HTTP ${response.status}).`)
    const data: unknown = await response.json()
    if (!isIocResponse(data)) throw new Error('The API returned an invalid response.')
    if (!response.ok || !data.success) throw new Error(data.error || `The API returned HTTP ${response.status}.`)
    return data
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      if (signal?.aborted) throw error
      throw new Error('The request timed out. Check that the Flask API is running and reachable.')
    }
    if (error instanceof TypeError) throw new Error('Could not reach the Flask API. Check its URL and CORS settings.')
    throw error
  } finally {
    signal?.removeEventListener('abort', abort)
    clearTimeout(timeout)
  }
}

export interface ChainResponse {
  steps: { operation: string; output: string }[]
  final: string
}

export async function callChain(inputText: string, steps: { operation: string }[], signal?: AbortSignal): Promise<ChainResponse> {
  const controller = new AbortController()
  const abort = () => controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) abort()
  const timeout = setTimeout(() => controller.abort(), 10000)
  try {
    const response = await fetch(`${getApiBaseUrl()}/api/chain`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input_text: inputText, steps }), signal: controller.signal,
    })
    if (!(response.headers.get('content-type') ?? '').includes('application/json')) {
      throw new Error(`The API returned an unexpected response (HTTP ${response.status}).`)
    }
    const data: unknown = await response.json()
    const validSteps = (value: unknown): value is ChainResponse['steps'] => Array.isArray(value) && value.every((step) =>
      Boolean(step && typeof step === 'object' && 'operation' in step && typeof step.operation === 'string' && 'output' in step && typeof step.output === 'string'))
    if (!isChainResponse(data)) {
      if (data && typeof data === 'object' && 'error' in data && typeof data.error === 'string' && !response.ok) {
        const partial = 'steps' in data && validSteps(data.steps) ? data.steps : []
        if ('failed_step' in data && typeof data.failed_step === 'number' && Number.isInteger(data.failed_step)) {
          throw Object.assign(new Error(data.error), { partialSteps: partial, failedStep: data.failed_step })
        }
        throw new Error(data.error)
      }
      throw new Error('The API returned an invalid response.')
    }
    if (!response.ok) throw new Error('The chain request failed.')
    return { steps: data.steps, final: data.final }
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      if (signal?.aborted) throw error
      throw new Error('The request timed out. Check that the Flask API is running and reachable.')
    }
    if (error instanceof TypeError) throw new Error('Could not reach the Flask API. Check its URL and CORS settings.')
    throw error
  } finally {
    signal?.removeEventListener('abort', abort)
    clearTimeout(timeout)
  }
}
