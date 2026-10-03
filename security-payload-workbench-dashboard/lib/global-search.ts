export type SearchEntry = {
  title: string
  description: string
  href: string
  keywords: string[]
  icon: 'dashboard' | 'payload' | 'hash' | 'identify' | 'security'
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
    title: 'Payload Tools',
    description: 'Encode and decode Base64, URL, and Hex data.',
    href: '/payload-tools',
    keywords: ['payload generator', 'payload utilities', 'base64', 'url encode', 'url decode', 'hex', 'hexadecimal', 'encoding', 'decoding'],
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
    title: 'Security Lab',
    description: 'Explore defensive security references and utilities.',
    href: '/security-lab',
    keywords: ['security tools', 'ioc sanitization', 'defang', 'refang', 'connectivity', 'tcp', 'http', 'listener', 'relay', 'reference', 'learning'],
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
