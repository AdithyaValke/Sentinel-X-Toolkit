'use client'

import { FormEvent, useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowRight, LockKeyhole, Plus, RefreshCw, ShieldAlert } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { ApiError, createInvestigation, Investigation, listInvestigations } from '@/lib/api'
import { useAuth } from '@/lib/auth'

const statusLabels: Record<Investigation['status'], string> = { open: 'Open', investigating: 'Investigating', resolved: 'Resolved', closed: 'Closed' }
const dateFormat = new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', year: 'numeric' })

function StatusBadge({ status }: { status: Investigation['status'] }) {
  return <span className={`investigation-status investigation-status-${status}`}>{statusLabels[status]}</span>
}

export function InvestigationsPage() {
  const { status: authStatus } = useAuth()
  const [items, setItems] = useState<Investigation[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showForm, setShowForm] = useState(false)
  const router = useRouter()

  useEffect(() => { if (window.location.search.includes('new=1')) setShowForm(true) }, [])
  useEffect(() => {
    if (authStatus !== 'authenticated') return
    setLoading(true); setError('')
    listInvestigations().then(setItems).catch((cause) => {
      if (cause instanceof ApiError && (cause.status === 401 || cause.status === 403)) router.push('/auth')
      else setError('We could not load your investigations. Please try again.')
    }).finally(() => setLoading(false))
  }, [authStatus, router])

  if (authStatus === 'loading') return <main className="dashboard-page"><div className="dashboard-container"><div className="investigation-loading" aria-label="Loading investigations"><span /><span /><span /></div></div></main>
  if (authStatus === 'unauthenticated') return <main className="dashboard-page"><div className="dashboard-container"><section className="investigation-gate"><div className="investigation-gate-icon"><LockKeyhole aria-hidden="true" /></div><p className="dashboard-eyebrow"><span className="dashboard-eyebrow-dot" />Restricted workspace</p><h1>Investigations require an account</h1><p>Create an account or sign in to create and manage persistent investigations.</p><div className="investigation-actions"><Link href="/auth" className="investigation-primary-button">Sign In</Link><Link href="/auth" className="investigation-secondary-button">Create Account</Link></div></section></div></main>

  async function handleCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError('')
    const form = new FormData(event.currentTarget)
    const title = String(form.get('title') || '').trim(); const description = String(form.get('description') || '').trim(); const status = String(form.get('status') || 'open') as Investigation['status']
    if (!title) return setError('Add a title before creating the investigation.')
    if (title.length > 200 || description.length > 8000) return setError('Use a shorter title or description.')
    try { const created = await createInvestigation({ title, description: description || undefined, status }); setItems((current) => [created, ...current]); setShowForm(false); router.push(`/investigations/${created.id}`) }
    catch (cause) { setError(cause instanceof ApiError ? cause.message : 'We could not create the investigation. Please try again.') }
  }

  return <main className="dashboard-page"><div className="dashboard-container"><section className="investigation-header"><div><p className="dashboard-eyebrow"><span className="dashboard-eyebrow-dot" />Persistent security workspace</p><h1>Investigations</h1><p>Create and manage persistent security investigations.</p></div><button className="investigation-primary-button" type="button" onClick={() => setShowForm(true)}><Plus aria-hidden="true" />New Investigation</button></section>
    {showForm && <form className="investigation-form" onSubmit={handleCreate}><div><h2>New Investigation</h2><p>Start a persistent record for an incident or security review.</p></div><label>Title<input name="title" maxLength={200} required autoFocus placeholder="e.g. Suspicious authentication activity" /></label><label>Description<textarea name="description" maxLength={8000} rows={4} placeholder="Add context for your investigation" /></label><label>Status<select name="status" defaultValue="open"><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="closed">Closed</option></select></label><div className="investigation-form-actions"><button type="button" className="investigation-secondary-button" onClick={() => setShowForm(false)}>Cancel</button><button className="investigation-primary-button" type="submit">Create Investigation</button></div></form>}
    {error && <div className="investigation-error" role="alert"><ShieldAlert aria-hidden="true" /><span>{error}</span>{!showForm && <button type="button" onClick={() => { setLoading(true); listInvestigations().then(setItems).catch(() => setError('We could not load your investigations. Please try again.')).finally(() => setLoading(false)) }}><RefreshCw aria-hidden="true" />Retry</button>}</div>}
    {!showForm && !loading && !error && (items.length === 0 ? <section className="investigation-empty"><div className="investigation-empty-icon"><ShieldAlert aria-hidden="true" /></div><h2>No investigations yet</h2><p>Create your first investigation to begin tracking IOCs, findings, evidence, and timeline events.</p><button className="investigation-primary-button" type="button" onClick={() => setShowForm(true)}><Plus aria-hidden="true" />Create Investigation</button></section> : <section className="investigation-list" aria-label="Your investigations">{items.map((item) => <Link className="investigation-card" href={`/investigations/${item.id}`} key={item.id}><div className="investigation-card-main"><div className="investigation-card-title"><h2>{item.title}</h2><StatusBadge status={item.status} /></div>{item.description && <p>{item.description}</p>}</div><div className="investigation-card-meta"><span>Updated {dateFormat.format(new Date(item.updated_at))}</span><ArrowRight aria-hidden="true" /></div></Link>)}</section>)}
  </div></main>
}
