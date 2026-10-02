import type { HashAlgorithm } from '@/app/page';

export async function callBackend(
  operation: string,
  inputText: string,
  hashAlgo: HashAlgorithm | null = null
): Promise<{ success: boolean; result: string; error: string | null }> {
  const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
  const url = `${baseUrl}/api/process`;
  const payload: Record<string, any> = {
    input_text: inputText,
    operation,
  };
  if (hashAlgo) {
    payload.hash_algorithm = hashAlgo;
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Server error ${response.status}: ${text}`);
  }
  const data = await response.json();
  return data;
}
