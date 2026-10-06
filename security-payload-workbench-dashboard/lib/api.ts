import { isChainResponse } from './payload-operations.ts'

export type HashAlgorithm = 'MD5' | 'SHA-256' | 'SHA-512';

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
  if (!response.ok) throw new ApiError(getErrorMessage(data, 'Investigation request failed.'), response.status)
  return data
}

export async function listInvestigations(): Promise<Investigation[]> {
  const data = await investigationRequest('/api/investigations')
  return data && typeof data === 'object' && Array.isArray((data as { items?: unknown }).items)
    ? (data as { items: Investigation[] }).items
    : []
}

export async function getInvestigation(id: string): Promise<Investigation> {
  const data = await investigationRequest(`/api/investigations/${encodeURIComponent(id)}`)
  if (!data || typeof data !== 'object' || !('item' in data)) throw new ApiError('Invalid investigation response.', 502)
  return (data as { item: Investigation }).item
}

export async function createInvestigation(payload: { title: string; description?: string }): Promise<Investigation> {
  const data = await investigationRequest('/api/investigations', { method: 'POST', body: JSON.stringify(payload) })
  if (!data || typeof data !== 'object' || !('item' in data)) throw new ApiError('Invalid investigation response.', 502)
  return (data as { item: Investigation }).item
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
  if (!response.ok) throw new Error(getErrorMessage(data, 'Authentication request failed.'))
  return data
}

export async function getCurrentUser(): Promise<AuthApiUser | null> {
  const response = await fetch(`${getApiBaseUrl()}/api/auth/me`, { credentials: 'include' })
  if (response.status === 401 || response.status === 403) return null
  const data: unknown = await response.json().catch(() => null)
  if (!response.ok) throw new Error(getErrorMessage(data, 'Could not check your session.'))
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
