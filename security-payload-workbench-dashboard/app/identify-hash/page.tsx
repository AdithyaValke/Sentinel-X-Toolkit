import type { Metadata } from 'next'
import { IdentifyHash } from '@/components/identify-hash'

export const metadata: Metadata = {
  title: 'Identify Hash Function | SentinelX',
  description: 'Identify likely hash algorithms using the SentinelX API.',
}

export default function IdentifyHashPage() {
  return <IdentifyHash />
}

