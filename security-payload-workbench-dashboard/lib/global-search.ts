import { JWT_DECODER_CATALOG_ENTRY, PAYLOAD_GENERATOR_CATALOG_ENTRY, REGEX_TESTER_CATALOG_ENTRY, SECURITY_HEADERS_CATALOG_ENTRY } from './security-lab-catalog.ts'

export type SearchEntry = {
  title: string
  description: string
  href: string
  keywords: string[]
  icon: 'dashboard' | 'payload' | 'hash' | 'identify' | 'security' | 'common'
}

export const GLOBAL_SEARCH_INDEX: SearchEntry[] = [
  {
    title: 'Dashboard',
    description: 'Open your security workspace overview.',
    href: '/dashboard',
    keywords: ['home', 'overview', 'main dashboard', 'workspace'],
    icon: 'dashboard',
  },
  {
    title: 'Common Tools',
    description: 'Open everyday encoding, hashing, and identification utilities.',
    href: '/common-tools',
    keywords: ['common utilities', 'everyday tools', 'converters', 'encoding', 'hashing', 'identification'],
    icon: 'common',
  },
  {
    title: 'JSON Formatter',
    description: 'Validate, format, and minify JSON locally in your browser.',
    href: '/json-formatter',
    keywords: ['json', 'json validator', 'pretty print', 'format json', 'minify json', 'formatter'],
    icon: 'common',
  },
  {
    title: REGEX_TESTER_CATALOG_ENTRY.title,
    description: REGEX_TESTER_CATALOG_ENTRY.description,
    href: REGEX_TESTER_CATALOG_ENTRY.href,
    keywords: ['regex', 'regular expression', 'pattern analyzer', 'matches', 'capture groups', 'logs', 'regexp'],
    icon: 'security',
  },
  {
    title: PAYLOAD_GENERATOR_CATALOG_ENTRY.title,
    description: PAYLOAD_GENERATOR_CATALOG_ENTRY.description,
    href: PAYLOAD_GENERATOR_CATALOG_ENTRY.href,
    keywords: [
      'payload', 'reference generator', 'connectivity test', 'tcp check', 'http probe',
      'listener template', 'relay template', 'ip and port', 'non-executable',
    ],
    icon: 'payload',
  },
  {
    title: JWT_DECODER_CATALOG_ENTRY.title,
    description: JWT_DECODER_CATALOG_ENTRY.description,
    href: JWT_DECODER_CATALOG_ENTRY.href,
    keywords: ['jwt', 'json web token', 'token decoder', 'token analyzer', 'claims', 'bearer token', 'signature verification', 'hs256', 'hs384', 'hs512'],
    icon: 'security',
  },
  {
    title: 'Payload Tools',
    description: 'Encode and decode Base64, URL, and Hex data.',
    href: '/payload-tools',
    keywords: ['payload utilities', 'base64', 'url encode', 'url decode', 'hex', 'hexadecimal', 'encoding', 'decoding'],
    icon: 'payload',
  },
  {
    title: 'Hash Tools',
    description: 'Generate MD5, SHA-256, and SHA-512 hashes.',
    href: '/hash-tools',
    keywords: ['hash converter', 'hash generation', 'digest', 'md5', 'sha256', 'sha-256', 'sha512', 'sha-512'],
    icon: 'hash',
  },
  {
    title: 'Identify Hash',
    description: 'Inspect a hash signature and review likely algorithms.',
    href: '/identify-hash',
    keywords: ['hash identification', 'hash type detection', 'algorithm identification', 'md5', 'sha-1', 'sha1', 'sha-256', 'sha256', 'bcrypt'],
    icon: 'identify',
  },
  {
    title: 'Investigations',
    description: 'Create and manage persistent security investigations.',
    href: '/investigations',
    keywords: ['cases', 'incidents', 'persistent investigations', 'new investigation', 'tracking'],
    icon: 'security',
  },
  {
    title: 'New Investigation',
    description: 'Create a persistent security investigation.',
    href: '/investigations?new=1',
    keywords: ['create case', 'new case', 'investigation'],
    icon: 'security',
  },
  {
    title: 'Analysis Lab',
    description: 'Explore defensive security references and utilities.',
    href: '/security-lab',
    keywords: ['security tools', 'security lab', 'ioc sanitization', 'defang', 'refang', 'connectivity', 'tcp', 'http', 'listener', 'relay', 'reference', 'learning'],
    icon: 'security',
  },
  {
    title: SECURITY_HEADERS_CATALOG_ENTRY.title,
    description: SECURITY_HEADERS_CATALOG_ENTRY.description,
    href: SECURITY_HEADERS_CATALOG_ENTRY.href,
    keywords: ['security headers', 'headers analyzer', 'csp', 'hsts', 'content security policy', 'cookies', 'http response'],
    icon: 'security',
  },
]

function normalize(value: string) {
  return value.toLocaleLowerCase().trim().replace(/\s+/g, ' ')
}

function score(entry: SearchEntry, query: string) {
  const title = normalize(entry.title)
  const description = normalize(entry.description)
  const keywords = entry.keywords.map(normalize)
  if (title === query) return 100
  if (title.startsWith(query)) return 80
  if (title.includes(query)) return 70
  if (keywords.some((keyword) => keyword === query)) return 60
  if (keywords.some((keyword) => keyword.startsWith(query))) return 50
  if (keywords.some((keyword) => keyword.includes(query))) return 40
  if (description.includes(query)) return 20

  const words = query.split(' ')
  if (words.length > 1 && words.every((word) => title.includes(word) || description.includes(word) || keywords.some((keyword) => keyword.includes(word)))) return 10
  return 0
}

export function searchGlobal(query: string, limit = 5): SearchEntry[] {
  const normalizedQuery = normalize(query)
  if (!normalizedQuery) return GLOBAL_SEARCH_INDEX.slice(0, 4)

  const seen = new Set<string>()
  return GLOBAL_SEARCH_INDEX
    .map((entry, index) => ({ entry, index, score: score(entry, normalizedQuery) }))
    .filter(({ entry, score: entryScore }) => entryScore > 0 && !seen.has(entry.href) && Boolean(seen.add(entry.href)))
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .slice(0, limit)
    .map(({ entry }) => entry)
}
