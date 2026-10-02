import type { HashAlgorithm } from '@/app/page';

export async function callBackend(
  operation: string,
  inputText: string,
  hashAlgo: HashAlgorithm | null = null
): Promise<{ success: boolean; result: string; error: string | null }> {
  const configuredUrl = process.env.NEXT_PUBLIC_API_URL?.trim();
  if (!configuredUrl && process.env.NODE_ENV === 'production') {
    throw new Error('NEXT_PUBLIC_API_URL is not configured.');
  }
  const baseUrl = (configuredUrl || 'http://localhost:8000').replace(/\/+$/, '');
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
    const result = data as { success: boolean; result: string; error?: string | null };
    if (!response.ok) {
      throw new Error(result.error || `The API returned HTTP ${response.status}.`);
    }
    return { success: result.success, result: result.result, error: result.error ?? null };
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
