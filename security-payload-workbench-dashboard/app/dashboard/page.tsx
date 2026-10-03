import type { Metadata } from 'next'
import { DashboardShell } from '@/components/dashboard/dashboard-shell'

export const metadata: Metadata = {
  title: 'Dashboard | Payload Workbench',
  description: 'Your security workspace for payload and hash analysis tools.',
}

export default function DashboardPage() {
  return <DashboardShell />
}


