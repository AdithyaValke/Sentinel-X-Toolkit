import type { Metadata } from 'next'
import { HashConverter } from '@/components/hash-converter'

export const metadata: Metadata = {
  title: 'Hash Converter | Payload Workbench',
  description: 'Generate MD5, SHA-256, and SHA-512 hashes with the Payload Workbench Flask API.',
}

export default function HashToolsPage() {
  return <HashConverter />
}
