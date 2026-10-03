import type { Metadata } from 'next'
import { SecurityLab } from '@/components/security-lab'

export const metadata: Metadata = {
  title: 'Security Lab | Payload Workbench',
  description:
    'Educational reference and defensive security analysis workspace for reverse shell mechanics, IoC sanitization, and threat modeling.',
}

export default function SecurityLabPage() {
  return <SecurityLab />
}
