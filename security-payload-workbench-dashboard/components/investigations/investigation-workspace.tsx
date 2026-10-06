'use client'

import { FormEvent, useEffect, useState } from 'react'
import Link from 'next/link'
import { LoaderCircle, LockKeyhole, Plus, RefreshCw, ShieldAlert, X } from 'lucide-react'
import { ApiError, createInvestigationEvidence, createInvestigationFinding, createInvestigationIOC, FINDING_SEVERITIES, FindingSeverity, getInvestigation, Investigation, InvestigationEvidence, InvestigationFinding, InvestigationIOC, InvestigationTimelineEvent, listInvestigationEvidence, listInvestigationFindings, listInvestigationIOCs, listInvestigationTimeline } from '@/lib/api'
import { useAuth } from '@/lib/auth'

const statusLabels: Record<Investigation['status'], string> = { open: 'Open', investigating: 'Investigating', resolved: 'Resolved', closed: 'Closed' }
const iocLabels: Record<InvestigationIOC['ioc_type'], string> = { ip: 'IP', domain: 'Domain', hash: 'Hash', email: 'Email' }
const findingSeverityLabels: Record<FindingSeverity, string> = { info: 'Informational', low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' }
const findingStatusLabels: Record<InvestigationFinding['status'], string> = { open: 'Open', confirmed: 'Confirmed', dismissed: 'Dismissed', resolved: 'Resolved' }
const dateFormat = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' })

function formatDate(value: string | null) {
  if (!value) return 'Not recorded'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Not recorded' : dateFormat.format(date)
}

function textLength(value: string) {
  return Array.from(value).length
}

function IocCard({ ioc }: { ioc: InvestigationIOC }) {
  return <article className="investigation-ioc-card">
    <div className="investigation-ioc-main"><div className="investigation-ioc-heading"><span className={`investigation-ioc-badge investigation-ioc-${ioc.ioc_type}`}>{iocLabels[ioc.ioc_type]}</span><code>{ioc.value}</code></div><p className="investigation-ioc-source">Added via {ioc.source.replace('_', ' ')}</p></div>
    <dl className="investigation-ioc-meta"><div><dt>Confidence</dt><dd>{ioc.confidence === null ? 'Not set' : `${ioc.confidence}%`}</dd></div><div><dt>Created</dt><dd>{formatDate(ioc.created_at)}</dd></div></dl>
  </article>
}

function FindingCard({ finding }: { finding: InvestigationFinding }) {
  return <article className="investigation-finding-card">
    <div className="investigation-finding-heading"><h3>{finding.title}</h3><span className={`investigation-finding-severity investigation-finding-${finding.severity}`}>{findingSeverityLabels[finding.severity]}</span></div>
    <p className="investigation-finding-description">{finding.description || 'No description provided.'}</p>
    <dl className="investigation-finding-meta"><div><dt>Status</dt><dd>{findingStatusLabels[finding.status]}</dd></div>{finding.source && <div><dt>Source</dt><dd>{finding.source}</dd></div>}<div><dt>Created</dt><dd>{formatDate(finding.created_at)}</dd></div><div><dt>Updated</dt><dd>{formatDate(finding.updated_at)}</dd></div></dl>
  </article>
}

function EvidenceCard({ evidence }: { evidence: InvestigationEvidence }) {
  return <article className="investigation-evidence-card">
    <div className="investigation-finding-heading"><div><span className="investigation-evidence-type">{evidence.evidence_type.replaceAll('_', ' ')}</span><h3>{evidence.title}</h3></div><span className="investigation-evidence-date">{formatDate(evidence.created_at)}</span></div>
    <p className="investigation-evidence-content">{evidence.content}</p>
    {evidence.source && <p className="investigation-evidence-source">Source: {evidence.source}</p>}
  </article>
}

function TimelineEvent({ event, isNewest }: { event: InvestigationTimelineEvent; isNewest: boolean }) {
  return <article className={`investigation-timeline-event${isNewest ? ' investigation-timeline-event-newest' : ''}`}>
    <span className="investigation-timeline-marker" aria-hidden="true" />
    <div className="investigation-timeline-event-content"><div className="investigation-timeline-event-heading"><span>{event.event_type.replaceAll('_', ' ')}</span><time dateTime={event.created_at}>{formatDate(event.created_at)}</time></div><p>{event.message}</p></div>
  </article>
}

export function InvestigationWorkspace({ id }: { id: string }) {
  const { status: authStatus } = useAuth()
  const [item, setItem] = useState<Investigation | null>(null)
  const [iocs, setIocs] = useState<InvestigationIOC[]>([])
  const [findings, setFindings] = useState<InvestigationFinding[]>([])
  const [evidence, setEvidence] = useState<InvestigationEvidence[]>([])
  const [timeline, setTimeline] = useState<InvestigationTimelineEvent[]>([])
  const [error, setError] = useState('')
  const [iocError, setIocError] = useState('')
  const [findingError, setFindingError] = useState('')
  const [evidenceError, setEvidenceError] = useState('')
  const [timelineError, setTimelineError] = useState('')
  const [loading, setLoading] = useState(true)
  const [iocsLoading, setIocsLoading] = useState(true)
  const [findingsLoading, setFindingsLoading] = useState(true)
  const [evidenceLoading, setEvidenceLoading] = useState(true)
  const [timelineLoading, setTimelineLoading] = useState(true)
  const [timelineLoadingMore, setTimelineLoadingMore] = useState(false)
  const [timelineLimit, setTimelineLimit] = useState(20)
  const [timelineHasMore, setTimelineHasMore] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [showFindingForm, setShowFindingForm] = useState(false)
  const [showEvidenceForm, setShowEvidenceForm] = useState(false)
  const [creating, setCreating] = useState(false)
  const [findingCreating, setFindingCreating] = useState(false)
  const [evidenceCreating, setEvidenceCreating] = useState(false)
  const [form, setForm] = useState<{ ioc_type: InvestigationIOC['ioc_type']; value: string }>({ ioc_type: 'ip', value: '' })
  const [findingForm, setFindingForm] = useState<{ title: string; description: string; severity: FindingSeverity }>({ title: '', description: '', severity: 'info' })
  const [evidenceForm, setEvidenceForm] = useState({ evidence_type: 'note', title: '', content: '' })

  const loadIocs = () => {
    setIocsLoading(true)
    setIocError('')
    return listInvestigationIOCs(id).then(setIocs).catch(() => setIocError('We could not load indicators for this investigation.')).finally(() => setIocsLoading(false))
  }
  const loadFindings = () => {
    setFindingsLoading(true)
    setFindingError('')
    return listInvestigationFindings(id).then(setFindings).catch((cause: unknown) => setFindingError(cause instanceof ApiError && cause.status === 401 ? 'Your session has expired. Sign in again to view findings.' : cause instanceof Error ? cause.message : 'We could not load findings for this investigation.')).finally(() => setFindingsLoading(false))
  }
  const loadEvidence = () => {
    setEvidenceLoading(true)
    setEvidenceError('')
    return listInvestigationEvidence(id).then(setEvidence).catch((cause: unknown) => setEvidenceError(cause instanceof ApiError && cause.status === 401 ? 'Your session has expired. Sign in again to view evidence.' : cause instanceof Error ? cause.message : 'We could not load evidence for this investigation.')).finally(() => setEvidenceLoading(false))
  }
  const loadTimeline = async (reset = true) => {
    const offset = reset ? 0 : timeline.length
    setTimelineError('')
    if (reset) setTimelineLoading(true)
    else setTimelineLoadingMore(true)
    try {
      const page = await listInvestigationTimeline(id, { limit: timelineLimit, offset })
      setTimeline((current) => reset ? page.items : [...current, ...page.items])
      setTimelineLimit(page.limit)
      setTimelineHasMore(page.items.length === page.limit)
    } catch (cause) {
      setTimelineError(cause instanceof ApiError && cause.status === 401 ? 'Your session has expired. Sign in again to view the timeline.' : cause instanceof Error ? cause.message : 'We could not load the investigation timeline.')
    } finally {
      setTimelineLoading(false)
      setTimelineLoadingMore(false)
    }
  }
  const load = () => {
    setLoading(true); setError('')
    Promise.all([getInvestigation(id), loadIocs(), loadFindings(), loadEvidence(), loadTimeline(true)]).then(([investigation]) => setItem(investigation)).catch((cause) => setError(cause instanceof ApiError && cause.status === 404 ? 'Investigation not found.' : 'We could not load this investigation.')).finally(() => setLoading(false))
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
      await loadTimeline(true)
    } catch (cause) {
      setIocError(cause instanceof ApiError ? cause.message : 'We could not add this indicator.')
    } finally { setCreating(false) }
  }

  const submitFinding = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const title = findingForm.title.trim()
    const description = findingForm.description.trim()
    if (!title) { setFindingError('Enter a title before adding this finding.'); return }
    if (title.length > 200) { setFindingError('Title must be 200 characters or fewer.'); return }
    if (description.length > 8000) { setFindingError('Description must be 8,000 characters or fewer.'); return }
    if (!FINDING_SEVERITIES.includes(findingForm.severity)) { setFindingError('Choose a supported severity.'); return }
    setFindingCreating(true); setFindingError('')
    try {
      await createInvestigationFinding(id, { title, ...(description ? { description } : {}), severity: findingForm.severity })
      setFindingForm({ title: '', description: '', severity: 'info' })
      setShowFindingForm(false)
      await loadFindings()
      await loadTimeline(true)
    } catch (cause) {
      setFindingError(cause instanceof ApiError && cause.status === 401 ? 'Your session has expired. Sign in again to add a finding.' : cause instanceof Error ? cause.message : 'We could not add this finding.')
    } finally { setFindingCreating(false) }
  }

  const submitEvidence = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const evidence_type = evidenceForm.evidence_type.trim()
    const title = evidenceForm.title.trim()
    const content = evidenceForm.content
    if (!evidence_type) { setEvidenceError('Enter an evidence type.'); return }
    if (evidence_type.length > 32 || !/^[a-z][a-z0-9_]*$/.test(evidence_type)) { setEvidenceError('Evidence type must be a lowercase slug of up to 32 characters (letters, numbers, and underscores).'); return }
    if (!title) { setEvidenceError('Enter a title for this evidence.'); return }
    if (textLength(title) > 200) { setEvidenceError('Title must be 200 characters or fewer.'); return }
    if (!content.trim()) { setEvidenceError('Evidence content cannot be empty.'); return }
    if (textLength(content) > 8000) { setEvidenceError('Evidence content must be 8,000 characters or fewer.'); return }
    setEvidenceCreating(true); setEvidenceError('')
    try {
      await createInvestigationEvidence(id, { evidence_type, title, content })
      setEvidenceForm({ evidence_type, title: '', content: '' })
      setShowEvidenceForm(false)
      await loadEvidence()
      await loadTimeline(true)
    } catch (cause) {
      setEvidenceError(cause instanceof ApiError && cause.status === 401 ? 'Your session has expired. Sign in again to add evidence.' : cause instanceof Error ? cause.message : 'We could not add this evidence.')
    } finally { setEvidenceCreating(false) }
  }

  if (authStatus === 'loading' || loading) return <main className="dashboard-page"><div className="dashboard-container"><div className="investigation-loading"><span /><span /><span /></div></div></main>
  if (authStatus === 'unauthenticated') return <main className="dashboard-page"><div className="dashboard-container"><section className="investigation-gate"><div className="investigation-gate-icon"><LockKeyhole aria-hidden="true" /></div><h1>Sign in to view investigations</h1><p>This workspace is available to authenticated analysts.</p><Link href="/auth" className="investigation-primary-button">Sign In</Link></section></div></main>
  if (error || !item) return <main className="dashboard-page"><div className="dashboard-container"><section className="investigation-empty"><ShieldAlert aria-hidden="true" /><h1>{error || 'Investigation not found.'}</h1><button className="investigation-secondary-button" type="button" onClick={load}><RefreshCw aria-hidden="true" />Retry</button></section></div></main>

  return <main className="dashboard-page"><div className="dashboard-container"><section className="investigation-detail-header"><div className="investigation-detail-heading"><p className="dashboard-eyebrow"><span className="dashboard-eyebrow-dot" />Investigation #{item.id}</p><div className="investigation-title-row"><h1>{item.title}</h1><span className={`investigation-status investigation-status-${item.status}`}>{statusLabels[item.status]}</span></div><p>{item.description || 'No description was added to this investigation.'}</p></div><dl className="investigation-header-meta"><div><dt>Created</dt><dd>{formatDate(item.created_at)}</dd></div><div><dt>Updated</dt><dd>{formatDate(item.updated_at)}</dd></div><div><dt>Status</dt><dd>{statusLabels[item.status]}</dd></div></dl></section><section className="investigation-detail-grid">
    <article className="investigation-panel investigation-ioc-panel"><div className="investigation-panel-heading"><div><p className="dashboard-section-kicker">Investigation workspace</p><h2 id="investigation-iocs-heading">Indicators of Compromise</h2></div><button className="investigation-primary-button" type="button" onClick={() => { setShowForm(true); setIocError('') }}><Plus aria-hidden="true" />Add IOC</button></div>{showForm && <form className="investigation-ioc-form" onSubmit={submitIoc}><div><label htmlFor="ioc-type">IOC type</label><select id="ioc-type" value={form.ioc_type} onChange={(event) => setForm({ ...form, ioc_type: event.target.value as InvestigationIOC['ioc_type'] })}><option value="ip">IP</option><option value="domain">Domain</option><option value="hash">Hash</option><option value="email">Email</option></select></div><div className="investigation-ioc-value-field"><label htmlFor="ioc-value">IOC value</label><input id="ioc-value" value={form.value} onChange={(event) => setForm({ ...form, value: event.target.value })} placeholder="e.g. 198.51.100.24" autoComplete="off" /></div><div className="investigation-ioc-actions"><button className="investigation-primary-button" type="submit" disabled={creating}>{creating && <LoaderCircle className="animate-spin" aria-hidden="true" />}{creating ? 'Adding…' : 'Add indicator'}</button><button className="investigation-secondary-button" type="button" onClick={() => { setShowForm(false); setIocError('') }} disabled={creating}><X aria-hidden="true" />Cancel</button></div></form>}{iocError && <p className="investigation-form-error" role="alert">{iocError}</p>}{iocsLoading ? <div className="investigation-ioc-skeleton" aria-label="Loading indicators"><span /><span /></div> : iocs.length ? <div className="investigation-ioc-list investigation-scroll-region" role="region" aria-labelledby="investigation-iocs-heading" tabIndex={0}>{iocs.map((ioc) => <IocCard key={ioc.id} ioc={ioc} />)}</div> : <div className="investigation-ioc-empty"><ShieldAlert aria-hidden="true" /><div><h3>No indicators yet</h3><p>Add indicators manually or extract them from analysis results.</p></div><button className="investigation-secondary-button" type="button" onClick={() => setShowForm(true)}>Add IOC</button></div>}</article>
    <article className="investigation-panel investigation-finding-panel"><div className="investigation-panel-heading"><div><p className="dashboard-section-kicker">Analyst assessments</p><h2 id="investigation-findings-heading">Findings</h2></div><button className="investigation-primary-button" type="button" onClick={() => { setShowFindingForm(true); setFindingError('') }}><Plus aria-hidden="true" />Add Finding</button></div>
      {showFindingForm && <form className="investigation-finding-form" onSubmit={submitFinding} noValidate><div className="investigation-finding-fields"><div><label htmlFor="finding-title">Title</label><input id="finding-title" maxLength={200} value={findingForm.title} onChange={(event) => setFindingForm({ ...findingForm, title: event.target.value })} required /></div><div><label htmlFor="finding-severity">Severity</label><select id="finding-severity" value={findingForm.severity} onChange={(event) => setFindingForm({ ...findingForm, severity: event.target.value as FindingSeverity })}>{FINDING_SEVERITIES.map((severity) => <option key={severity} value={severity}>{findingSeverityLabels[severity]}</option>)}</select></div><div className="investigation-finding-description-field"><label htmlFor="finding-description">Description <span>(optional)</span></label><textarea id="finding-description" rows={4} maxLength={8000} value={findingForm.description} onChange={(event) => setFindingForm({ ...findingForm, description: event.target.value })} /></div></div><p className="investigation-finding-count">{findingForm.description.length}/8,000 characters</p><div className="investigation-ioc-actions"><button className="investigation-primary-button" type="submit" disabled={findingCreating}>{findingCreating && <LoaderCircle className="animate-spin" aria-hidden="true" />}{findingCreating ? 'Adding…' : 'Add finding'}</button><button className="investigation-secondary-button" type="button" onClick={() => { setShowFindingForm(false); setFindingError('') }} disabled={findingCreating}><X aria-hidden="true" />Cancel</button></div></form>}
      {findingError && <div className="investigation-form-error" role="alert"><span>{findingError}</span>{!showFindingForm && <button className="investigation-inline-retry" type="button" onClick={() => void loadFindings()}><RefreshCw aria-hidden="true" />Retry</button>}</div>}
      {findingsLoading ? <div className="investigation-ioc-skeleton" aria-label="Loading findings"><span /><span /></div> : findingError && findings.length === 0 ? null : findings.length ? <div className="investigation-finding-list investigation-scroll-region" role="region" aria-labelledby="investigation-findings-heading" tabIndex={0}>{findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}</div> : <div className="investigation-ioc-empty"><ShieldAlert aria-hidden="true" /><div><h3>No findings yet</h3><p>Record an analyst assessment for this investigation.</p></div><button className="investigation-secondary-button" type="button" onClick={() => setShowFindingForm(true)}>Add Finding</button></div>}
    </article>
    <article className="investigation-panel investigation-evidence-panel"><div className="investigation-panel-heading"><div><p className="dashboard-section-kicker">Investigation records</p><h2 id="investigation-evidence-heading">Evidence</h2></div><button className="investigation-primary-button" type="button" onClick={() => { setShowEvidenceForm(true); setEvidenceError('') }}><Plus aria-hidden="true" />Add Evidence</button></div>
      {showEvidenceForm && <form className="investigation-evidence-form" onSubmit={submitEvidence} noValidate><div className="investigation-evidence-fields"><div><label htmlFor="evidence-type">Evidence type</label><input id="evidence-type" value={evidenceForm.evidence_type} onChange={(event) => setEvidenceForm({ ...evidenceForm, evidence_type: event.target.value })} placeholder="e.g. note, log_snippet" aria-describedby="evidence-type-hint" /><p id="evidence-type-hint">Use a lowercase slug with letters, numbers, and underscores.</p></div><div><label htmlFor="evidence-title">Title</label><input id="evidence-title" value={evidenceForm.title} onChange={(event) => setEvidenceForm({ ...evidenceForm, title: event.target.value })} /></div><div className="investigation-evidence-content-field"><label htmlFor="evidence-content">Textual evidence</label><textarea id="evidence-content" rows={6} value={evidenceForm.content} onChange={(event) => setEvidenceForm({ ...evidenceForm, content: event.target.value })} placeholder="Paste analyst notes, log excerpts, command output, or references as plain text." /><p className="investigation-finding-count">{textLength(evidenceForm.content).toLocaleString()}/8,000 characters</p></div></div><div className="investigation-ioc-actions"><button className="investigation-primary-button" type="submit" disabled={evidenceCreating}>{evidenceCreating && <LoaderCircle className="animate-spin" aria-hidden="true" />}{evidenceCreating ? 'Adding…' : 'Add evidence'}</button><button className="investigation-secondary-button" type="button" onClick={() => { setShowEvidenceForm(false); setEvidenceError('') }} disabled={evidenceCreating}><X aria-hidden="true" />Cancel</button></div></form>}
      {evidenceError && <div className="investigation-form-error" role="alert"><span>{evidenceError}</span>{!showEvidenceForm && <button className="investigation-inline-retry" type="button" onClick={() => void loadEvidence()}><RefreshCw aria-hidden="true" />Retry</button>}</div>}
      {evidenceLoading ? <div className="investigation-ioc-skeleton" aria-label="Loading evidence"><span /><span /></div> : evidenceError && evidence.length === 0 ? null : evidence.length ? <div className="investigation-evidence-list investigation-scroll-region" role="region" aria-labelledby="investigation-evidence-heading" tabIndex={0}>{evidence.map((record) => <EvidenceCard key={record.id} evidence={record} />)}</div> : <div className="investigation-ioc-empty"><ShieldAlert aria-hidden="true" /><div><h3>No evidence yet</h3><p>Add notes or other textual observations to this investigation.</p></div><button className="investigation-secondary-button" type="button" onClick={() => setShowEvidenceForm(true)}>Add Evidence</button></div>}
    </article>
    <article className="investigation-panel investigation-timeline-panel"><div className="investigation-panel-heading"><div><p className="dashboard-section-kicker">Backend activity</p><h2 id="investigation-timeline-heading">Timeline</h2></div><button className="investigation-secondary-button investigation-timeline-refresh" type="button" onClick={() => void loadTimeline(true)} disabled={timelineLoading || timelineLoadingMore}><RefreshCw className={timelineLoading ? 'animate-spin' : ''} aria-hidden="true" />Refresh</button></div><p className="investigation-timeline-order">Newest activity first</p>
      {timelineError && <div className="investigation-form-error" role="alert"><span>{timelineError}</span><button className="investigation-inline-retry" type="button" onClick={() => void loadTimeline(timeline.length === 0)}><RefreshCw aria-hidden="true" />Retry</button></div>}
      {timelineLoading ? <div className="investigation-ioc-skeleton" aria-label="Loading timeline"><span /><span /></div> : timeline.length ? <div><div className="investigation-timeline-list investigation-scroll-region" role="region" aria-labelledby="investigation-timeline-heading" tabIndex={0}>{timeline.map((event, index) => <TimelineEvent key={event.id} event={event} isNewest={index === 0} />)}</div>{timelineHasMore && <button className="investigation-secondary-button investigation-timeline-more" type="button" onClick={() => void loadTimeline(false)} disabled={timelineLoadingMore}>{timelineLoadingMore && <LoaderCircle className="animate-spin" aria-hidden="true" />}{timelineLoadingMore ? 'Loading…' : 'Load older activity'}</button>}</div> : !timelineError && <div className="investigation-ioc-empty"><ShieldAlert aria-hidden="true" /><div><h3>No activity recorded yet</h3><p>Activity will appear here as this investigation and its records are updated.</p></div></div>}
    </article><aside className="investigation-panel"><p className="dashboard-section-kicker">Metadata</p><dl className="investigation-metadata"><div><dt>Created</dt><dd>{formatDate(item.created_at)}</dd></div><div><dt>Last updated</dt><dd>{formatDate(item.updated_at)}</dd></div><div><dt>Closed</dt><dd>{item.closed_at ? formatDate(item.closed_at) : 'Not closed'}</dd></div></dl></aside></section></div></main>
}
