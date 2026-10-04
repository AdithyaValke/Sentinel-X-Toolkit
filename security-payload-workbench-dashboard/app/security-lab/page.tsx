import type { Metadata } from 'next'
import { SecurityLab } from '@/components/security-lab'

export const metadata: Metadata = {
  title: 'Security Lab | Payload Workbench',
  description:
    'Defensive security workspace for IoC sanitization, JWT decoding, TCP and HTTP connectivity references, and listener or relay templates.',
}

export default function SecurityLabPage() {
  return <SecurityLab />
}
