'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, LockKeyhole, RefreshCw, ShieldAlert } from 'lucide-react'
import { ApiError, getInvestigation, Investigation } from '@/lib/api'
import { useAuth } from '@/lib/auth'

const statusLabels: Record<Investigation['status'], string> = { open: 'Open', investigating: 'Investigating', resolved: 'Resolved', closed: 'Closed' }
const dateFormat = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' })

export function InvestigationWorkspace({ id }: { id: string }) {
  const { status: authStatus } = useAuth()
  const [item, setItem] = useState<Investigation | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const load = () => { setLoading(true); setError(''); getInvestigation(id).then(setItem).catch((cause) => setError(cause instanceof ApiError && cause.status === 404 ? 'Investigation not found.' : 'We could not load this investigation.')).finally(() => setLoading(false)) }
  useEffect(() => { if (authStatus === 'authenticated') load(); else if (authStatus === 'unauthenticated') setLoading(false) }, [authStatus, id])

  if (authStatus === 'loading' || loading) return <main className="dashboard-page"><div className="dashboard-container"><div className="investigation-loading"><span /><span /><span /></div></div></main>
  if (authStatus === 'unauthenticated') return <main className="dashboard-page"><div className="dashboard-container"><section className="investigation-gate"><div className="investigation-gate-icon"><LockKeyhole aria-hidden="true" /></div><h1>Sign in to view investigations</h1><p>This workspace is available to authenticated analysts.</p><Link href="/auth" className="investigation-primary-button">Sign In</Link></section></div></main>
  if (error || !item) return <main className="dashboard-page"><div className="dashboard-container"><section className="investigation-empty"><ShieldAlert aria-hidden="true" /><h1>{error || 'Investigation not found.'}</h1><button className="investigation-secondary-button" type="button" onClick={load}><RefreshCw aria-hidden="true" />Retry</button></section></div></main>

  return <main className="dashboard-page"><div className="dashboard-container"><Link href="/investigations" className="investigation-back"><ArrowLeft aria-hidden="true" />Back to Investigations</Link><section className="investigation-detail-header"><div><p className="dashboard-eyebrow"><span className="dashboard-eyebrow-dot" />Investigation #{item.id}</p><div className="investigation-title-row"><h1>{item.title}</h1><span className={`investigation-status investigation-status-${item.status}`}>{statusLabels[item.status]}</span></div><p>{item.description || 'No description was added to this investigation.'}</p></div></section><section className="investigation-detail-grid"><article className="investigation-panel"><p className="dashboard-section-kicker">Case overview</p><h2>Investigation workspace</h2><p>IOCs, findings, evidence, and timeline events will appear here as this case develops.</p><div className="investigation-placeholder-list"><div><strong>Indicators of compromise</strong><span>Ready for linked IOCs</span></div><div><strong>Findings</strong><span>Ready for analyst findings</span></div><div><strong>Evidence</strong><span>Ready for supporting evidence</span></div></div></article><aside className="investigation-panel"><p className="dashboard-section-kicker">Metadata</p><dl className="investigation-metadata"><div><dt>Created</dt><dd>{dateFormat.format(new Date(item.created_at))}</dd></div><div><dt>Last updated</dt><dd>{dateFormat.format(new Date(item.updated_at))}</dd></div><div><dt>Closed</dt><dd>{item.closed_at ? dateFormat.format(new Date(item.closed_at)) : 'Not closed'}</dd></div></dl></aside></section></div></main>
}
