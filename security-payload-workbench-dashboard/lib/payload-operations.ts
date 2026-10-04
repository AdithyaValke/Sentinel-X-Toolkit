export const PAYLOAD_OPERATION_MAP = {
  'base64-encode': 'base64_encode',
  'base64-decode': 'base64_decode',
  'url-encode': 'url_encode',
  'url-decode': 'url_decode',
  'hex-encode': 'hex_encode',
  'hex-decode': 'hex_decode',
} as const

export type PayloadOperation = keyof typeof PAYLOAD_OPERATION_MAP

export const CHAIN_MAX_STEPS = 10
// Keep in sync with Flask's MAX_CONTENT_LENGTH = 10 * 1024 in backend/app.py.
export const CHAIN_REQUEST_MAX_BYTES = 10 * 1024
export const CHAIN_OPERATION_LABELS: Record<string, string> = {
  base64_encode: 'Base64 Encode',
  base64_decode: 'Base64 Decode',
  url_encode: 'URL Encode',
  url_decode: 'URL Decode',
  hex_encode: 'Hex Encode',
  hex_decode: 'Hex Decode',
}
export const CHAIN_OPERATION_DESCRIPTIONS: Record<string, string> = {
  base64_encode: 'Convert to Base64 format',
  base64_decode: 'Decode Base64 to text',
  url_encode: 'Encode for URL usage',
  url_decode: 'Decode percent-encoded text',
  hex_encode: 'Convert to Hex format',
  hex_decode: 'Decode Hex to text',
}
export const CHAIN_OPERATIONS = Object.entries(PAYLOAD_OPERATION_MAP).map(([id, operation]) => ({
  id: operation,
  label: CHAIN_OPERATION_LABELS[operation],
  description: CHAIN_OPERATION_DESCRIPTIONS[operation],
  group: operation.startsWith('base64_') ? 'Base64' : operation.startsWith('url_') ? 'URL' : 'Hex',
}))

export type ChainStep = { operation: string }

export function addChainStep(steps: ChainStep[], operation: string): ChainStep[] {
  return steps.length >= CHAIN_MAX_STEPS ? steps : [...steps, { operation }]
}

export function removeChainStep(steps: ChainStep[], index: number): ChainStep[] {
  return steps.filter((_, stepIndex) => stepIndex !== index)
}

export function moveChainStep(steps: ChainStep[], index: number, direction: -1 | 1): ChainStep[] {
  const target = index + direction
  if (index < 0 || target < 0 || index >= steps.length || target >= steps.length) return steps
  const reordered = [...steps]
  ;[reordered[index], reordered[target]] = [reordered[target], reordered[index]]
  return reordered
}

export function isChainResponse(value: unknown): value is { steps: { operation: string; output: string }[]; final: string } {
  return Boolean(value && typeof value === 'object' && 'steps' in value && Array.isArray(value.steps) &&
    value.steps.every((step) => Boolean(step && typeof step === 'object' && 'operation' in step && typeof step.operation === 'string' && 'output' in step && typeof step.output === 'string')) &&
    'final' in value && typeof value.final === 'string')
}

export function serializedChainRequestBytes(input: string, steps: ChainStep[]): number {
  return new TextEncoder().encode(JSON.stringify({ input_text: input, steps })).byteLength
}
