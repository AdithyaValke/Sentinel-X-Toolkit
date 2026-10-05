import type { Metadata } from 'next'
import { PayloadTools } from '@/components/payload-tools'

export const metadata: Metadata = {
  title: 'Payload Tools | SentinelX',
  description: 'Encode and decode Base64, URL, and Hex data with SentinelX.',
}

export default function PayloadToolsPage() {
  return <PayloadTools />
}
