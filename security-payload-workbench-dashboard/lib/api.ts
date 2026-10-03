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

function getApiBaseUrl(): string {
  const configuredUrl = process.env.NEXT_PUBLIC_API_URL?.trim()
  if (!configuredUrl && process.env.NODE_ENV === 'production') {
    throw new Error('NEXT_PUBLIC_API_URL is not configured.')
  }
  return (configuredUrl || 'http://localhost:8000').replace(/\/+$/, '')
}

export async function checkBackendHealth(): Promise<boolean> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 5000)
  try {
    const response = await fetch(`${getApiBaseUrl()}/health`, { signal: controller.signal })
    if (!response.ok) return false
    const data: unknown = await response.json()
    return Boolean(data && typeof data === 'object' && 'status' in data && data.status === 'ok')
  } catch {
    return false
  } finally {
    clearTimeout(timeout)
  }
}

export async function callBackend(
  operation: string,
  inputText: string,
  hashAlgo: HashAlgorithm | null = null
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
  const timeout = window.setTimeout(() => controller.abort(), 10000);
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
      ('error' in data && data.error !== null && typeof data.error !== 'string')
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
      throw new Error('The request timed out. Check that the Flask API is running and reachable.');
    }
    if (error instanceof TypeError) {
      throw new Error('Could not reach the Flask API. Check its URL and CORS settings.');
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}
