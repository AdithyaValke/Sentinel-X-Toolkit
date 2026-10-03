export type LegacySearchParams = Record<string, string | string[] | undefined>

const PAYLOAD_OPERATIONS = new Set([
  'base64-encode',
  'base64-decode',
  'url-encode',
  'url-decode',
  'hex-encode',
  'hex-decode',
])

export function getLegacyDestination(searchParams: LegacySearchParams): string {
  const operationValue = searchParams.operation
  const operation = Array.isArray(operationValue) ? operationValue[0] : operationValue

  let destination = '/dashboard'
  if (operation === 'hash') destination = '/hash-tools'
  else if (operation === 'identify-hash') destination = '/identify-hash'
  else if (operation && PAYLOAD_OPERATIONS.has(operation)) destination = '/payload-tools'

  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(searchParams)) {
    if (Array.isArray(value)) {
      for (const item of value) query.append(key, item)
    } else if (value !== undefined) {
      query.append(key, value)
    }
  }

  const serializedQuery = query.toString()
  return serializedQuery ? `${destination}?${serializedQuery}` : destination
}
