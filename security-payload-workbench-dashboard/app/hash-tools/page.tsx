import type { Metadata } from 'next'
import { HashConverter } from '@/components/hash-converter'

export const metadata: Metadata = {
  title: 'Hash Converter | SentinelX',
  description: 'Generate MD5, SHA-1, SHA-2, SHA-3, and SHAKE digests with the SentinelX API.',
}

export default function HashToolsPage() {
  return <HashConverter />
}
