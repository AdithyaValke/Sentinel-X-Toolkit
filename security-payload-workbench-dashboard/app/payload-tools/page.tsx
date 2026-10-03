import type { Metadata } from 'next'
import { PayloadTools } from '@/components/payload-tools'

export const metadata: Metadata = {
  title: 'Payload Tools | Payload Workbench',
  description: 'Encode and decode Base64, URL, and Hex data with Payload Workbench.',
}

export default function PayloadToolsPage() {
  return <PayloadTools />
}
