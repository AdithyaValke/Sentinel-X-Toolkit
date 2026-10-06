'use client'

import { FormEvent, useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, LoaderCircle, LockKeyhole, Plus, RefreshCw, ShieldAlert, X } from 'lucide-react'
import { ApiError, createInvestigationIOC, getInvestigation, Investigation, InvestigationIOC, listInvestigationIOCs } from '@/lib/api'
import { useAuth } from '@/lib/auth'

const statusLabels: Record<Investigation['status'], string> = { open: 'Open', investigating: 'Investigating', resolved: 'Resolved', closed: 'Closed' }
const iocLabels: Record<InvestigationIOC['ioc_type'], string> = { ip: 'IP', domain: 'Domain', hash: 'Hash', email: 'Email' }
const dateFormat = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' })

function formatDate(value: string | null) {
  if (!value) return 'Not recorded'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Not recorded' : dateFormat.format(date)
}

function IocCard({ ioc }: { ioc: InvestigationIOC }) {
  return <article className="investigation-ioc-card">
    <div className="investigation-ioc-main"><div className="investigation-ioc-heading"><span className={`investigation-ioc-badge investigation-ioc-${ioc.ioc_type}`}>{iocLabels[ioc.ioc_type]}</span><code>{ioc.value}</code></div><p className="investigation-ioc-source">Added via {ioc.source.replace('_', ' ')}</p></div>
    <dl className="investigation-ioc-meta"><div><dt>Confidence</dt><dd>{ioc.confidence === null ? 'Not set' : `${ioc.confidence}%`}</dd></div><div><dt>Created</dt><dd>{formatDate(ioc.created_at)}</dd></div></dl>
  </article>
}

export function InvestigationWorkspace({ id }: { id: string }) {
  const { status: authStatus } = useAuth()
  const [item, setItem] = useState<Investigation | null>(null)
  const [iocs, setIocs] = useState<InvestigationIOC[]>([])
  const [error, setError] = useState('')
  const [iocError, setIocError] = useState('')
  const [loading, setLoading] = useState(true)
  const [iocsLoading, setIocsLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState<{ ioc_type: InvestigationIOC['ioc_type']; value: string }>({ ioc_type: 'ip', value: '' })

  const loadIocs = () => {
    setIocsLoading(true)
    setIocError('')
    return listInvestigationIOCs(id).then(setIocs).catch(() => setIocError('We could not load indicators for this investigation.')).finally(() => setIocsLoading(false))
  }
  const load = () => {
    setLoading(true); setError('')
    Promise.all([getInvestigation(id), loadIocs()]).then(([investigation]) => setItem(investigation)).catch((cause) => setError(cause instanceof ApiError && cause.status === 404 ? 'Investigation not found.' : 'We could not load this investigation.')).finally(() => setLoading(false))
  }
  useEffect(() => { if (authStatus === 'authenticated') load(); else if (authStatus === 'unauthenticated') setLoading(false) }, [authStatus, id])

  const submitIoc = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const value = form.value.trim()
    if (!value) { setIocError('Enter an IOC value before adding it.'); return }
    setCreating(true); setIocError('')
    try {
      await createInvestigationIOC(id, { ioc_type: form.ioc_type, value })
      setForm({ ioc_type: form.ioc_type, value: '' })
      setShowForm(false)
      await loadIocs()
    } catch (cause) {
      setIocError(cause instanceof ApiError ? cause.message : 'We could not add this indicator.')
    } finally { setCreating(false) }
  }

  if (authStatus === 'loading' || loading) return <main className="dashboard-page"><div className="dashboard-container"><div className="investigation-loading"><span /><span /><span /></div></div></main>
  if (authStatus === 'unauthenticated') return <main className="dashboard-page"><div className="dashboard-container"><section className="investigation-gate"><div className="investigation-gate-icon"><LockKeyhole aria-hidden="true" /></div><h1>Sign in to view investigations</h1><p>This workspace is available to authenticated analysts.</p><Link href="/auth" className="investigation-primary-button">Sign In</Link></section></div></main>
  if (error || !item) return <main className="dashboard-page"><div className="dashboard-container"><section className="investigation-empty"><ShieldAlert aria-hidden="true" /><h1>{error || 'Investigation not found.'}</h1><button className="investigation-secondary-button" type="button" onClick={load}><RefreshCw aria-hidden="true" />Retry</button></section></div></main>

  return <main className="dashboard-page"><div className="dashboard-container"><Link href="/investigations" className="investigation-back"><ArrowLeft aria-hidden="true" />Back to Investigations</Link><section className="investigation-detail-header"><div><p className="dashboard-eyebrow"><span className="dashboard-eyebrow-dot" />Investigation #{item.id}</p><div className="investigation-title-row"><h1>{item.title}</h1><span className={`investigation-status investigation-status-${item.status}`}>{statusLabels[item.status]}</span></div><p>{item.description || 'No description was added to this investigation.'}</p></div></section><section className="investigation-detail-grid"><article className="investigation-panel investigation-ioc-panel"><div className="investigation-panel-heading"><div><p className="dashboard-section-kicker">Investigation workspace</p><h2>Indicators of Compromise</h2></div><button className="investigation-primary-button" type="button" onClick={() => { setShowForm(true); setIocError('') }}><Plus aria-hidden="true" />Add IOC</button></div>{showForm && <form className="investigation-ioc-form" onSubmit={submitIoc}><div><label htmlFor="ioc-type">IOC type</label><select id="ioc-type" value={form.ioc_type} onChange={(event) => setForm({ ...form, ioc_type: event.target.value as InvestigationIOC['ioc_type'] })}><option value="ip">IP</option><option value="domain">Domain</option><option value="hash">Hash</option><option value="email">Email</option></select></div><div className="investigation-ioc-value-field"><label htmlFor="ioc-value">IOC value</label><input id="ioc-value" value={form.value} onChange={(event) => setForm({ ...form, value: event.target.value })} placeholder="e.g. 198.51.100.24" autoComplete="off" /></div><div className="investigation-ioc-actions"><button className="investigation-primary-button" type="submit" disabled={creating}>{creating && <LoaderCircle className="animate-spin" aria-hidden="true" />}{creating ? 'Adding…' : 'Add indicator'}</button><button className="investigation-secondary-button" type="button" onClick={() => { setShowForm(false); setIocError('') }} disabled={creating}><X aria-hidden="true" />Cancel</button></div></form>}{iocError && <p className="investigation-form-error" role="alert">{iocError}</p>}{iocsLoading ? <div className="investigation-ioc-skeleton" aria-label="Loading indicators"><span /><span /></div> : iocs.length ? <div className="investigation-ioc-list">{iocs.map((ioc) => <IocCard key={ioc.id} ioc={ioc} />)}</div> : <div className="investigation-ioc-empty"><ShieldAlert aria-hidden="true" /><div><h3>No indicators yet</h3><p>Add indicators manually or extract them from analysis results.</p></div><button className="investigation-secondary-button" type="button" onClick={() => setShowForm(true)}>Add IOC</button></div>}</article><aside className="investigation-panel"><p className="dashboard-section-kicker">Metadata</p><dl className="investigation-metadata"><div><dt>Created</dt><dd>{formatDate(item.created_at)}</dd></div><div><dt>Last updated</dt><dd>{formatDate(item.updated_at)}</dd></div><div><dt>Closed</dt><dd>{item.closed_at ? formatDate(item.closed_at) : 'Not closed'}</dd></div></dl></aside></section></div></main>
}
