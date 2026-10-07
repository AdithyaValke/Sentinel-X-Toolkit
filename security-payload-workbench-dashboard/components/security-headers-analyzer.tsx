'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { Check, ChevronDown, Clipboard, Download, Eraser, FileJson, LoaderCircle, LockKeyhole, Plus, RefreshCw, Search, ShieldCheck, X } from 'lucide-react'
import { ApiError, listInvestigationsPage, type Investigation } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { clearHeaderFindingSelection, removeSavedHeaderFindings, saveHeaderFindingsToInvestigation, selectVisibleHeaderFindings, toggleHeaderFindingSelection, type HeaderFindingSaveFailure } from '@/lib/security-header-investigation'
import { exportAnalysisCsv, exportAnalysisJson, SECURITY_HEADERS_SAMPLE, securityHeadersAnalyzer, type HeaderFindingSeverity, type HeaderFindingStatus, type SecurityHeadersAnalysis } from '@/lib/security-headers-analyzer'

const statusLabels: Record<HeaderFindingStatus, string> = { present: 'Present', missing: 'Missing', misconfigured: 'Potentially misconfigured', 'not-assessed': 'Not assessed' }
const severityLabels: Record<HeaderFindingSeverity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Informational' }

export function SecurityHeadersAnalyzer() {
  const { status: authStatus, refresh: refreshSession } = useAuth()
  const [input, setInput] = useState('')
  const [analysis, setAnalysis] = useState<SecurityHeadersAnalysis | null>(null)
  const [statusFilter, setStatusFilter] = useState<'all' | HeaderFindingStatus>('all')
  const [severityFilter, setSeverityFilter] = useState<'all' | HeaderFindingSeverity>('all')
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(() => new Set())
  const [saveDialogOpen, setSaveDialogOpen] = useState(false)
  const [investigations, setInvestigations] = useState<Investigation[]>([])
  const [investigationsLoading, setInvestigationsLoading] = useState(false)
  const [investigationsLoadingMore, setInvestigationsLoadingMore] = useState(false)
  const [investigationsError, setInvestigationsError] = useState('')
  const [investigationsLimit, setInvestigationsLimit] = useState(20)
  const [investigationsNextOffset, setInvestigationsNextOffset] = useState(0)
  const [investigationsHaveMore, setInvestigationsHaveMore] = useState(false)
  const [investigationsRetry, setInvestigationsRetry] = useState(0)
  const [destinationId, setDestinationId] = useState('')
  const [isSavingFindings, setIsSavingFindings] = useState(false)
  const [saveReport, setSaveReport] = useState<{ saved: number; total: number; destination: Investigation; failed: HeaderFindingSaveFailure[] } | null>(null)

  const findings = useMemo(() => analysis?.findings.filter((finding) => {
    const haystack = `${finding.header} ${finding.explanation} ${finding.remediation}`.toLowerCase()
    return (statusFilter === 'all' || finding.status === statusFilter) && (severityFilter === 'all' || finding.severity === severityFilter) && haystack.includes(query.toLowerCase().trim())
  }) ?? [], [analysis, query, severityFilter, statusFilter])
  const issueCount = analysis?.findings.filter((finding) => finding.status === 'missing' || finding.status === 'misconfigured').length ?? 0

  useEffect(() => {
    if (!saveDialogOpen || authStatus !== 'authenticated') return
    let active = true
    setInvestigationsLoading(true)
    setInvestigationsError('')
    listInvestigationsPage({ limit: 20, offset: 0 }).then((page) => {
      if (!active) return
      setInvestigations(page.items)
      setInvestigationsLimit(page.limit)
      setInvestigationsNextOffset(page.offset + page.items.length)
      setInvestigationsHaveMore(page.items.length === page.limit)
    }).catch((cause: unknown) => {
      if (active) setInvestigationsError(cause instanceof ApiError && (cause.status === 401 || cause.status === 403)
        ? 'Your session has expired. Refresh your sign-in status to continue.'
        : cause instanceof Error ? cause.message : 'We could not load your investigations.')
    }).finally(() => { if (active) setInvestigationsLoading(false) })
    return () => { active = false }
  }, [authStatus, investigationsRetry, saveDialogOpen])

  function analyze() {
    if (!input.trim()) { setError('Paste a response header block before analyzing.'); setAnalysis(null); return }
    try { setError(''); setAnalysis(securityHeadersAnalyzer.analyze(input)); setExpanded(null); setSelectedFindingIds(new Set()) }
    catch { setError('Response header input must be no more than 64 KiB.'); setAnalysis(null) }
  }
  function clear() { setInput(''); setAnalysis(null); setError(''); setQuery(''); setExpanded(null); setSelectedFindingIds(new Set()) }
  async function copy(text: string, key: string) { try { await navigator.clipboard.writeText(text); setCopied(key); window.setTimeout(() => setCopied(null), 1500) } catch { setError('Clipboard access failed. Select and copy the text manually.') } }
  function download(content: string, filename: string, type: string) { const url = URL.createObjectURL(new Blob([content], { type })); const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url) }
  function summaryText() { if (!analysis) return ''; return `Security Headers Analyzer\nRecognized checks: ${analysis.recognizedHeaders}\nDetected headers: ${analysis.detectedHeaders}\nFindings: ${issueCount}\nCookies reviewed: ${analysis.cookies}\n\n${analysis.findings.map((f) => `${f.header}: ${statusLabels[f.status]} (${severityLabels[f.severity]})`).join('\n')}` }

  async function loadMoreInvestigations() {
    if (investigationsLoadingMore || !investigationsHaveMore) return
    setInvestigationsLoadingMore(true)
    setInvestigationsError('')
    try {
      const page = await listInvestigationsPage({ limit: investigationsLimit, offset: investigationsNextOffset })
      setInvestigations((current) => [...current, ...page.items])
      setInvestigationsLimit(page.limit)
      setInvestigationsNextOffset(page.offset + page.items.length)
      setInvestigationsHaveMore(page.items.length === page.limit)
    } catch (cause) {
      setInvestigationsError(cause instanceof ApiError && (cause.status === 401 || cause.status === 403)
        ? 'Your session has expired. Refresh your sign-in status to continue.'
        : cause instanceof Error ? cause.message : 'We could not load more investigations.')
    } finally { setInvestigationsLoadingMore(false) }
  }

  async function saveSelectedFindings() {
    const destination = investigations.find((item) => String(item.id) === destinationId)
    const selectedFindings = analysis?.findings.filter((finding) => selectedFindingIds.has(finding.id)) ?? []
    if (authStatus !== 'authenticated' || !destination || !selectedFindings.length || isSavingFindings) return
    setIsSavingFindings(true)
    setSaveReport(null)
    try {
      const result = await saveHeaderFindingsToInvestigation(destinationId, selectedFindings)
      setSaveReport({ saved: result.saved.length, total: selectedFindings.length, destination, failed: result.failed })
      setSelectedFindingIds((current) => removeSavedHeaderFindings(current, result.saved))
      if (result.authenticationExpired) await refreshSession()
    } finally { setIsSavingFindings(false) }
  }

  return <section className="mt-4 space-y-6" aria-labelledby="headers-title">
    <header>
      <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-cyan-400"><ShieldCheck className="size-3.5" /> Local security review</div>
      <h2 id="headers-title" className="mt-2 text-2xl font-bold text-white sm:text-3xl">Security Headers Analyzer</h2>
      <p className="mt-2 max-w-3xl text-xs leading-6 text-slate-400 sm:text-sm">Inspect HTTP response headers, identify potential security misconfigurations, and review recommended remediation.</p>
    </header>
    <div className="grid gap-6 lg:grid-cols-[minmax(320px,0.8fr)_minmax(0,1.2fr)]">
      <section className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 sm:p-6" aria-label="Header input">
        <div className="flex items-center justify-between gap-3"><label htmlFor="security-headers-input" className="font-mono text-xs font-bold uppercase tracking-wider text-slate-300">Response headers</label><span className="font-mono text-[10px] text-slate-500">{input.length.toLocaleString()} chars</span></div>
        <textarea id="security-headers-input" value={input} onChange={(event) => setInput(event.target.value)} placeholder={'Content-Security-Policy: default-src \'self\'\nX-Content-Type-Options: nosniff\nSet-Cookie: session=...'} className="mt-3 min-h-[340px] w-full resize-y rounded-xl border border-white/10 bg-[#060810] p-4 font-mono text-xs leading-6 text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/60 focus:ring-1 focus:ring-cyan-400/40" aria-describedby="headers-input-help" />
        <p id="headers-input-help" className="mt-2 text-[11px] leading-5 text-slate-500">Paste one header per line. Status lines, duplicate headers, and repeated Set-Cookie values are supported. Nothing is sent externally.</p>
        <div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={analyze} className="inline-flex min-h-11 flex-1 items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:bg-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400">Analyze Headers</button><button type="button" onClick={clear} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-2.5 text-xs text-slate-300 hover:border-white/20" aria-label="Clear header input"><Eraser className="size-4" /> Clear</button></div>
        <button type="button" onClick={() => { setInput(SECURITY_HEADERS_SAMPLE); setError('') }} className="mt-3 text-xs text-cyan-300 underline-offset-4 hover:underline">Load local demonstration sample</button>
        {error && <p role="alert" className="mt-3 rounded-xl border border-rose-400/20 bg-rose-400/10 p-3 text-xs text-rose-200">{error}</p>}
      </section>
      <section className="min-w-0 rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 sm:p-6" aria-live="polite">
        {!analysis ? <div className="flex min-h-[430px] flex-col items-center justify-center rounded-xl border border-dashed border-white/10 bg-[#060810] p-6 text-center"><FileJson className="size-9 text-slate-600" /><h3 className="mt-3 text-sm font-semibold text-slate-400">No analysis yet</h3><p className="mt-1 max-w-sm text-xs leading-5 text-slate-600">Analyze pasted headers to see calculated observations. Demonstration data is only loaded when you explicitly request it.</p></div> : <>
          <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-400">Analysis summary</p><h3 className="mt-1 text-lg font-semibold text-white">Local header review</h3></div><div className="flex flex-wrap gap-2"><button type="button" onClick={() => copy(summaryText(), 'summary')} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-slate-300">{copied === 'summary' ? <Check className="size-3.5 text-emerald-400" /> : <Clipboard className="size-3.5" />} {copied === 'summary' ? 'Copied' : 'Copy summary'}</button><button type="button" onClick={() => download(exportAnalysisJson(analysis), 'security-headers-report.json', 'application/json')} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-slate-300"><Download className="size-3.5" /> JSON</button><button type="button" onClick={() => download(exportAnalysisCsv(analysis), 'security-headers-report.csv', 'text/csv')} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-slate-300"><Download className="size-3.5" /> CSV</button></div></div>
          <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">{[['Checks', analysis.recognizedHeaders], ['Detected', analysis.detectedHeaders], ['Findings', issueCount], ['Cookies', analysis.cookies]].map(([label, value]) => <div key={label} className="rounded-xl border border-white/10 bg-white/[0.03] p-3"><p className="font-mono text-[10px] uppercase tracking-wider text-slate-500">{label}</p><p className="mt-1 text-xl font-bold text-white">{value}</p></div>)}</div>
          <div className="mt-4 flex flex-col gap-2 xl:flex-row"><label className="relative flex-1"><Search className="absolute left-3 top-2.5 size-4 text-slate-500" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings" className="min-h-10 w-full rounded-lg border border-white/10 bg-white/[0.03] pl-9 pr-3 text-xs text-slate-200 outline-none focus:border-cyan-400/60" /></label><select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as typeof statusFilter)} className="min-h-10 rounded-lg border border-white/10 bg-[#111827] px-3 text-xs text-slate-300"><option value="all">All statuses</option>{Object.entries(statusLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as typeof severityFilter)} className="min-h-10 rounded-lg border border-white/10 bg-[#111827] px-3 text-xs text-slate-300"><option value="all">All severities</option>{Object.entries(severityLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></div>
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-cyan-400/15 bg-cyan-400/[0.04] p-3"><div className="flex flex-wrap items-center gap-x-4 gap-y-2"><label className="flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" aria-label="Select all visible security header findings" disabled={!findings.length || isSavingFindings} checked={findings.length > 0 && findings.every((finding) => selectedFindingIds.has(finding.id))} onChange={(event) => setSelectedFindingIds((current) => selectVisibleHeaderFindings(current, findings.map(({ id }) => id), event.target.checked))} className="size-4 accent-cyan-400" />Select all visible <span className="text-slate-500">({findings.length})</span></label><span className="font-mono text-[10px] text-slate-400">{selectedFindingIds.size} {selectedFindingIds.size === 1 ? 'finding' : 'findings'} selected</span><button type="button" disabled={!selectedFindingIds.size || isSavingFindings} onClick={() => setSelectedFindingIds(clearHeaderFindingSelection())} className="text-xs text-slate-400 hover:text-slate-200 disabled:opacity-40">Clear selection</button></div><button type="button" disabled={!selectedFindingIds.size || isSavingFindings} onClick={() => { setSaveReport(null); setSaveDialogOpen(true) }} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-3 py-1.5 text-xs font-semibold text-cyan-200 hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-40"><Plus className="size-3.5" />Save to Investigation</button></div>
          <div className="mt-4 max-h-[560px] space-y-2 overflow-y-auto pr-1">{findings.length ? findings.map((finding) => <article key={finding.id} className="rounded-xl border border-white/10 bg-white/[0.02]"><div className="flex items-center gap-1"><input type="checkbox" aria-label={`Select ${finding.header} finding`} checked={selectedFindingIds.has(finding.id)} disabled={isSavingFindings} onChange={() => setSelectedFindingIds((current) => toggleHeaderFindingSelection(current, finding.id))} className="ml-3 size-4 shrink-0 accent-cyan-400" /><button type="button" onClick={() => setExpanded(expanded === finding.id ? null : finding.id)} className="flex min-h-16 min-w-0 flex-1 items-center gap-3 px-3 py-3 text-left"><ChevronDown className={`size-4 shrink-0 text-slate-500 transition ${expanded === finding.id ? 'rotate-180' : ''}`} /><span className="min-w-0 flex-1"><strong className="block truncate text-xs font-semibold text-slate-200">{finding.header}</strong><span className="mt-1 block text-[11px] text-slate-500">{statusLabels[finding.status]}</span></span><span className={`rounded-full px-2 py-1 text-[10px] font-semibold ${finding.severity === 'high' || finding.severity === 'critical' ? 'bg-rose-400/10 text-rose-300' : finding.severity === 'medium' ? 'bg-amber-400/10 text-amber-300' : 'bg-slate-400/10 text-slate-300'}`}>{severityLabels[finding.severity]}</span></button></div>{expanded === finding.id && <div className="border-t border-white/10 px-4 py-4 text-xs leading-5 text-slate-400"><p>{finding.explanation}</p><p className="mt-2 text-amber-200/80">Context: {finding.risk}</p>{finding.observedValue && <pre className="mt-3 max-h-28 overflow-auto rounded-lg bg-black/30 p-3 font-mono text-[11px] text-cyan-200">{finding.observedValue}</pre>}<p className="mt-3"><strong className="text-slate-200">Remediation:</strong> {finding.remediation}</p>{finding.example && <code className="mt-3 block overflow-x-auto rounded-lg bg-black/30 p-3 text-[11px] text-emerald-300">{finding.example}</code>}<button type="button" onClick={() => copy(`${finding.header}\n${finding.explanation}\n${finding.remediation}`, finding.id)} className="mt-3 inline-flex items-center gap-1.5 text-xs text-cyan-300">{copied === finding.id ? <Check className="size-3.5" /> : <Clipboard className="size-3.5" />} Copy finding</button></div>}</article>) : <p className="rounded-xl border border-dashed border-white/10 p-6 text-center text-xs text-slate-500">No findings match the selected filters.</p>}</div>
          <p className="mt-4 text-[11px] leading-5 text-slate-500">This is a review of pasted text only. It cannot verify TLS, browser enforcement, live behavior, or whether a policy is appropriate for the full application.</p>
        </>}
      </section>
    </div>
    {saveDialogOpen && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"><section role="dialog" aria-modal="true" aria-labelledby="save-header-findings-title" onKeyDown={(event) => { if (event.key === 'Escape' && !isSavingFindings) setSaveDialogOpen(false) }} className="max-h-[90dvh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-white/10 bg-[#0d121c] p-5 shadow-2xl sm:p-6"><div className="flex items-start justify-between gap-4"><div><p className="font-mono text-[10px] uppercase tracking-[.18em] text-cyan-300">Persistent investigation data</p><h2 id="save-header-findings-title" className="mt-2 text-lg font-semibold text-white">Save to Investigation</h2><p className="mt-1 text-xs text-slate-400">Save {selectedFindingIds.size} selected finding{selectedFindingIds.size === 1 ? '' : 's'}.</p></div><button type="button" onClick={() => setSaveDialogOpen(false)} disabled={isSavingFindings} className="rounded-lg p-2 text-slate-400 hover:bg-white/5 hover:text-white disabled:opacity-40" aria-label="Close dialog" autoFocus><X className="size-4" /></button></div>
      {authStatus === 'loading' && <div className="mt-6 flex items-center gap-2 text-sm text-slate-300"><LoaderCircle className="size-4 animate-spin" />Checking sign-in status…</div>}
      {authStatus === 'unavailable' && <div className="mt-6 rounded-xl border border-amber-400/20 bg-amber-400/[0.05] p-4 text-sm text-amber-100" role="status">Account and investigation services are temporarily unavailable. Analysis remains usable; saving findings will be available when service returns.</div>}
      {authStatus === 'unauthenticated' && <div className="mt-6 rounded-xl border border-amber-400/20 bg-amber-400/[0.05] p-4"><div className="flex items-start gap-3"><LockKeyhole className="mt-0.5 size-4 shrink-0 text-amber-300" /><div><h3 className="text-sm font-semibold text-white">Sign in to save selected findings</h3><p className="mt-1 text-xs leading-5 text-slate-400">The analyzer remains available while signed out. Sign in or create an account, then return and refresh your sign-in status. Your selection stays on this page.</p><div className="mt-4 flex flex-wrap gap-2"><Link href="/auth" target="_blank" rel="noreferrer" className="inline-flex min-h-9 items-center rounded-lg bg-cyan-400 px-3 text-xs font-semibold text-slate-950">Sign in / Create account</Link><button type="button" onClick={() => void refreshSession()} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 text-xs text-slate-200 hover:bg-white/5"><RefreshCw className="size-3" />Refresh sign-in status</button></div></div></div></div>}
      {authStatus === 'authenticated' && <div className="mt-6"><p className="mb-3 text-xs text-slate-400">Choose an investigation you own. The backend validates each finding and records its timeline event.</p>{investigationsError && <div className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-rose-400/20 bg-rose-400/[0.06] p-3 text-xs text-rose-200" role="alert"><span>{investigationsError}</span><button type="button" onClick={() => setInvestigationsRetry((current) => current + 1)} className="inline-flex items-center gap-1.5 text-cyan-200"><RefreshCw className="size-3" />Retry</button></div>}{investigationsLoading ? <div className="flex items-center gap-2 py-8 text-sm text-slate-300"><LoaderCircle className="size-4 animate-spin" />Loading your investigations…</div> : investigations.length ? <><div className="max-h-64 space-y-2 overflow-y-auto pr-1" role="radiogroup" aria-label="Destination investigation">{investigations.map((investigation) => <label key={investigation.id} className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition ${destinationId === String(investigation.id) ? 'border-cyan-400/40 bg-cyan-400/[0.07]' : 'border-white/[0.08] bg-white/[0.02] hover:border-white/20'}`}><input type="radio" name="destination-header-investigation" value={investigation.id} checked={destinationId === String(investigation.id)} onChange={() => { setDestinationId(String(investigation.id)); setSaveReport(null) }} disabled={isSavingFindings} className="mt-1 size-4 accent-cyan-400" /><span className="min-w-0 flex-1"><span className="block break-words text-sm font-medium text-slate-100">{investigation.title}</span><span className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-slate-500"><span>{investigation.status}</span><span>Updated {new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(investigation.updated_at))}</span></span></span></label>)}</div>{investigationsHaveMore && <button type="button" onClick={() => void loadMoreInvestigations()} disabled={investigationsLoadingMore} className="mt-3 inline-flex items-center gap-2 text-xs text-cyan-300 disabled:opacity-50">{investigationsLoadingMore && <LoaderCircle className="size-3 animate-spin" />}{investigationsLoadingMore ? 'Loading more…' : 'Load more investigations'}</button>}{!destinationId && <p className="mt-3 text-xs text-slate-500">Select an investigation to enable saving.</p>}</> : !investigationsError && <div className="rounded-xl border border-dashed border-white/15 p-5"><h3 className="text-sm font-semibold text-white">No investigations yet</h3><p className="mt-1 text-xs leading-5 text-slate-400">Create an investigation, then return here and refresh your list.</p><Link href="/investigations?new=1" target="_blank" rel="noreferrer" className="mt-3 inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-cyan-400/30 px-3 text-xs text-cyan-200"><Plus className="size-3" />Create Investigation</Link><button type="button" onClick={() => setInvestigationsRetry((current) => current + 1)} className="ml-2 mt-3 inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 text-xs text-slate-200 hover:bg-white/5"><RefreshCw className="size-3" />Refresh investigations</button></div>}
        {saveReport && <div className={`mt-4 rounded-xl border p-4 ${saveReport.failed.length ? 'border-amber-400/20 bg-amber-400/[0.05]' : 'border-emerald-400/20 bg-emerald-400/[0.05]'}`} role="status"><p className="text-sm font-medium text-white">{saveReport.saved === saveReport.total ? `${saveReport.saved} finding${saveReport.saved === 1 ? '' : 's'} saved to “${saveReport.destination.title}”.` : saveReport.saved ? `${saveReport.saved} of ${saveReport.total} findings saved to “${saveReport.destination.title}”; ${saveReport.failed.length} failed.` : `None of the ${saveReport.total} findings could be saved to “${saveReport.destination.title}”.`}</p>{saveReport.saved > 0 && <Link href={`/investigations/${saveReport.destination.id}`} className="mt-2 inline-block text-xs text-cyan-200 hover:text-cyan-100">Open investigation</Link>}{saveReport.failed.length > 0 && <ul className="mt-3 space-y-2">{saveReport.failed.map(({ finding, message }) => <li key={finding.id} className="break-words text-xs text-amber-100"><span className="font-mono">{finding.header}</span><span className="block text-amber-200/70">{message}</span></li>)}</ul>}</div>}
        <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.08] pt-4"><button type="button" onClick={() => setSaveDialogOpen(false)} disabled={isSavingFindings} className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-white/10 px-3 text-xs text-slate-200 hover:bg-white/5 disabled:opacity-40">Close</button>{authStatus === 'authenticated' && <button type="button" onClick={() => void saveSelectedFindings()} disabled={!selectedFindingIds.size || !destinationId || isSavingFindings || investigationsLoading} className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-cyan-400 px-4 text-xs font-semibold text-slate-950 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40">{isSavingFindings && <LoaderCircle className="size-3.5 animate-spin" />}{isSavingFindings ? 'Saving findings…' : 'Save selected findings'}</button>}</div>
      </div>}</section></div>}
  </section>
}
