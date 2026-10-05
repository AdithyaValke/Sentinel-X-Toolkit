export const PAYLOAD_GENERATOR_CATALOG_ENTRY = {
  title: 'Payload Generator',
  description:
    'Create local, non-executable TCP and HTTP connectivity checks plus listener and relay reference templates.',
  href: '/security-lab?tab=payload-generator',
  tab: 'payload-generator',
} as const

export const JWT_DECODER_CATALOG_ENTRY = {
  title: 'JWT Decoder',
  description: 'Decode JWT headers and claims locally, review defensive findings, and optionally verify HS256, HS384, or HS512 signatures.',
  href: '/security-lab?tab=jwt-decoder',
  tab: 'jwt-decoder',
} as const

export const IOC_EXTRACTOR_CATALOG_ENTRY = {
  title: 'IoC Extractor',
  description: 'Extract and organize potential indicators of compromise from logs, alerts, and text.',
  href: '/security-lab?tab=ioc-extractor',
  tab: 'ioc-extractor',
} as const

export const SECURITY_HEADERS_CATALOG_ENTRY = {
  title: 'Security Headers Analyzer',
  description: 'Inspect pasted HTTP response headers locally and review potential security configuration gaps.',
  href: '/security-lab?tab=security-headers',
  tab: 'security-headers',
} as const

export const SECURITY_LAB_TAB_IDS = ['overview', 'defanger', 'payload-generator', 'jwt-decoder', 'ioc-extractor', 'security-headers'] as const
export type SecurityLabTabId = typeof SECURITY_LAB_TAB_IDS[number]

export function parseSecurityLabTab(value: unknown): SecurityLabTabId {
  return typeof value === 'string' && (SECURITY_LAB_TAB_IDS as readonly string[]).includes(value)
    ? value as SecurityLabTabId
    : 'overview'
}
