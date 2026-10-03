import type { Metadata } from 'next'
import { IdentifyHash } from '@/components/identify-hash'

export const metadata: Metadata = {
  title: 'Identify Hash Function | Payload Workbench',
  description: 'Identify likely hash algorithms using the Payload Workbench Flask API.',
}

export default function IdentifyHashPage() {
  return <IdentifyHash />
}

