import type { Metadata } from 'next'
import { InvestigationsPage } from '@/components/investigations/investigations-page'

export const metadata: Metadata = {
  title: 'Investigations | SentinelX',
  description: 'Create and manage persistent security investigations.',
}

export default function Page() {
  return <InvestigationsPage />
}
