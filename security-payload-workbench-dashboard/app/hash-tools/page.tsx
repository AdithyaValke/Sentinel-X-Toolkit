import type { Metadata } from 'next'
import { HashConverter } from '@/components/hash-converter'

export const metadata: Metadata = {
  title: 'Hash Converter | SentinelX',
  description: 'Generate MD5, SHA-256, and SHA-512 hashes with the SentinelX API.',
}

export default function HashToolsPage() {
  return <HashConverter />
}
