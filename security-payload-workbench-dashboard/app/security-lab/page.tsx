import type { Metadata } from 'next'
import { SecurityLab } from '@/components/security-lab'

export const metadata: Metadata = {
  title: 'Security Lab | SentinelX',
  description:
    'Security workspace for IoC sanitization, JWT decoding, TCP and HTTP connectivity references, and listener or relay templates.',
}

export default function SecurityLabPage() {
  return <SecurityLab />
}
