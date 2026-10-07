export const HASH_ALGORITHM_OPTIONS = [
  { value: 'MD5', label: 'MD5', detail: 'Legacy compatibility' },
  { value: 'SHA-1', label: 'SHA-1', detail: 'SHA-2 family' },
  { value: 'SHA-224', label: 'SHA-224', detail: 'SHA-2 family' },
  { value: 'SHA-256', label: 'SHA-256', detail: 'Recommended default' },
  { value: 'SHA-384', label: 'SHA-384', detail: 'SHA-2 family' },
  { value: 'SHA-512', label: 'SHA-512', detail: 'Extended integrity' },
  { value: 'SHA-512/224', label: 'SHA-512/224', detail: 'Truncated SHA-512' },
  { value: 'SHA-512/256', label: 'SHA-512/256', detail: 'Truncated SHA-512' },
  { value: 'SHA3-224', label: 'SHA3-224', detail: 'SHA-3 family' },
  { value: 'SHA3-256', label: 'SHA3-256', detail: 'SHA-3 family' },
  { value: 'SHA3-384', label: 'SHA3-384', detail: 'SHA-3 family' },
  { value: 'SHA3-512', label: 'SHA3-512', detail: 'SHA-3 family' },
  { value: 'SHAKE-128', label: 'SHAKE-128', detail: 'Fixed 32-byte output' },
  { value: 'SHAKE-256', label: 'SHAKE-256', detail: 'Fixed 32-byte output' },
] as const

export type HashAlgorithm = typeof HASH_ALGORITHM_OPTIONS[number]['value']
