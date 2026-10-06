import type { Metadata } from 'next'
import { InvestigationWorkspace } from '@/components/investigations/investigation-workspace'

export const metadata: Metadata = {
  title: 'Investigation | SentinelX',
  description: 'Review a SentinelX security investigation.',
}

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  return <InvestigationWorkspace id={id} />
}
