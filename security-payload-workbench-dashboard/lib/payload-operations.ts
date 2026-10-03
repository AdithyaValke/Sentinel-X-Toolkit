export const PAYLOAD_OPERATION_MAP = {
  'base64-encode': 'base64_encode',
  'base64-decode': 'base64_decode',
  'url-encode': 'url_encode',
  'url-decode': 'url_decode',
  'hex-encode': 'hex_encode',
  'hex-decode': 'hex_decode',
} as const

export type PayloadOperation = keyof typeof PAYLOAD_OPERATION_MAP
