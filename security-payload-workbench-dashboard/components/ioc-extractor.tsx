'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { Check, Clipboard, Download, FileText, LoaderCircle, LockKeyhole, Plus, RefreshCw, Search, ShieldAlert, Trash2, X } from 'lucide-react'
import { ApiError, extractIocs, listInvestigationsPage, type IndicatorCategory, type Investigation } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { canPersistIndicators, saveIndicatorsToInvestigation, selectVisibleIndicators, toggleIndicatorSelection, type IndicatorSaveFailure } from '@/lib/ioc-investigation'
import { LatestRequest } from '@/lib/latest-request'

type FilterCategory = 'all' | IndicatorCategory

type Indicator = {
  id: string
  category: IndicatorCategory
  value: string
  occurrences: number
  context: string
}

const categoryOptions: { id: IndicatorCategory; label: string; detail: string }[] = [
  { id: 'ip', label: 'IP addresses', detail: 'IPv4 and IPv6' },
  { id: 'domain', label: 'Domains and URLs', detail: 'Hostnames and links' },
  { id: 'hash', label: 'File hashes', detail: 'MD5, SHA-1, SHA-256, SHA-512' },
  { id: 'email', label: 'Email addresses', detail: 'Mailbox identifiers' },
]

const labels: Record<IndicatorCategory, string> = { ip: 'IP', domain: 'URL / DOMAIN', hash: 'HASH', email: 'EMAIL' }
const filterLabels: Record<FilterCategory, string> = { all: 'All', ip: 'IP addresses', domain: 'Domains and URLs', hash: 'Hashes', email: 'Emails' }
const investigationStatusLabels: Record<Investigation['status'], string> = { open: 'Open', investigating: 'Investigating', resolved: 'Resolved', closed: 'Closed' }
const investigationDateFormat = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' })

function formatInvestigationDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Not recorded' : investigationDateFormat.format(date)
}

export function IocExtractor({ embeddedInAnalysisLab = false }: { embeddedInAnalysisLab?: boolean }) {
  const { status: authStatus, refresh: refreshSession } = useAuth()
  const [input, setInput] = useState('')
  const [selected, setSelected] = useState<Set<IndicatorCategory>>(() => new Set(categoryOptions.map(({ id }) => id)))
  const [results, setResults] = useState<Indicator[]>([])
  const [filter, setFilter] = useState<FilterCategory>('all')
  const [search, setSearch] = useState('')
  const [isExtracting, setIsExtracting] = useState(false)
  const [message, setMessage] = useState('')
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [selectedIndicatorIds, setSelectedIndicatorIds] = useState<Set<string>>(() => new Set())
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
  const [isSavingIndicators, setIsSavingIndicators] = useState(false)
  const [saveReport, setSaveReport] = useState<{ saved: number; total: number; destination: Investigation; failed: IndicatorSaveFailure[] } | null>(null)
  const latestRequest = useRef(new LatestRequest())

  useEffect(() => () => latestRequest.current.cancel(), [])

  const filteredResults = useMemo(() => results.filter((item) => (
    (filter === 'all' || item.category === filter) &&
    (!search.trim() || `${item.value} ${item.context}`.toLowerCase().includes(search.trim().toLowerCase()))
  )), [filter, results, search])
  const occurrences = results.reduce((sum, item) => sum + item.occurrences, 0)
  const categoryCount = new Set(results.map((item) => item.category)).size
  const selectedIndicators = results.filter((item) => selectedIndicatorIds.has(item.id))

  useEffect(() => {
    if (!saveDialogOpen || authStatus !== 'authenticated') return
    let active = true
    setInvestigations([])
    setInvestigationsLoading(true)
    setInvestigationsError('')
    setInvestigationsNextOffset(0)
    setInvestigationsHaveMore(false)
    listInvestigationsPage({ limit: 20, offset: 0 }).then((page) => {
      if (!active) return
      setInvestigations(page.items)
      setInvestigationsLimit(page.limit)
      setInvestigationsNextOffset(page.offset + page.items.length)
      setInvestigationsHaveMore(page.items.length === page.limit)
    }).catch((cause: unknown) => {
      if (!active) return
      setInvestigationsError(cause instanceof ApiError && (cause.status === 401 || cause.status === 403)
        ? 'Your session has expired. Refresh your sign-in status to continue.'
        : cause instanceof Error ? cause.message : 'We could not load your investigations.')
    }).finally(() => { if (active) setInvestigationsLoading(false) })
    return () => { active = false }
  }, [saveDialogOpen, authStatus, investigationsRetry])

  async function extract() {
    if (!input.trim() || selected.size === 0) return
    const { id, signal } = latestRequest.current.begin()
    setIsExtracting(true)
    setMessage('')
    try {
      const response = await extractIocs(input, Array.from(selected), signal)
      if (!latestRequest.current.isCurrent(id)) return
      setResults(response.results.map((item) => ({ ...item, id: `${item.category}:${item.value.toLowerCase()}` })))
      setSelectedIndicatorIds(new Set())
      setFilter('all')
      setMessage(response.results.length ? 'Potential indicators extracted. Values are not reputation-checked.' : 'No indicators found.')
    } catch (error) {
      if (!latestRequest.current.isCurrent(id)) return
      setMessage(error instanceof Error ? error.message : 'Extraction failed. Please try again.')
    } finally {
      if (latestRequest.current.isCurrent(id)) setIsExtracting(false)
    }
  }

  function openSaveDialog() {
    setSaveReport(null)
    setDestinationId('')
    setInvestigationsError('')
    setInvestigationsRetry((current) => current + 1)
    setSaveDialogOpen(true)
  }

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

  async function saveSelectedIndicators() {
    const destination = investigations.find((item) => String(item.id) === destinationId)
    if (!canPersistIndicators(authStatus === 'authenticated', selectedIndicators.length, isSavingIndicators) || !destination) return
    setIsSavingIndicators(true)
    setSaveReport(null)
    try {
      const result = await saveIndicatorsToInvestigation(destinationId, selectedIndicators)
      setSaveReport({ saved: result.saved.length, total: selectedIndicators.length, destination, failed: result.failed })
      const savedIds = new Set(result.saved.map((item) => item.id))
      setSelectedIndicatorIds((current) => new Set(Array.from(current).filter((id) => !savedIds.has(id))))
      if (result.authenticationExpired) await refreshSession()
    } finally { setIsSavingIndicators(false) }
  }

  function toggleCategory(category: IndicatorCategory) {
    latestRequest.current.cancel()
    setIsExtracting(false)
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(category)) next.delete(category)
      else next.add(category)
      return next
    })
  }

  async function copyValue(value: string, id: string) {
    try {
      await navigator.clipboard.writeText(value)
      setCopiedId(id)
      window.setTimeout(() => setCopiedId(null), 1400)
    } catch {
      setMessage('Clipboard access failed. Select and copy the indicator manually.')
    }
  }

  function copyAll() {
    if (!filteredResults.length) return
    void copyValue(filteredResults.map((item) => item.value).join('\n'), 'all')
  }

  function exportCsv() {
    if (!results.length) return
    const csv = ['Type,Indicator,Occurrences,Context', ...results.map((item) => [labels[item.category], item.value, item.occurrences, item.context].map((field) => `"${String(field).replaceAll('"', '""')}"`).join(','))].join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'sentinelx-indicators.csv'
    anchor.click()
    URL.revokeObjectURL(url)
    setMessage('CSV exported')
  }

  return (
    <main className="min-h-[calc(100dvh-76px)] bg-[#080b12] text-slate-100 selection:bg-cyan-400/30">
      <div className={embeddedInAnalysisLab ? 'w-full pt-4 pb-5 lg:pb-7' : 'mx-auto max-w-[1500px] px-4 py-5 sm:px-6 lg:px-8 lg:py-7'}>
        <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3"><div><p className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-300"><ShieldAlert className="size-4" /> FIND INDICATORS</p><h2 className="mt-1 text-2xl font-bold tracking-tight text-white sm:text-3xl">IoC Extractor</h2></div></div>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">Extract and organize potential indicators of compromise from logs, alerts, and unstructured text.</p>
          </div>
          <span className="rounded-full border border-cyan-400/20 bg-cyan-400/[0.06] px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-cyan-300">Flask API</span>
        </div>

        <div className="grid items-stretch gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.35fr)]">
          <section className="flex min-h-[680px] flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 shadow-xl shadow-black/10 sm:p-6 xl:h-[min(780px,calc(100dvh-10rem))]">
            <div className="flex items-start justify-between gap-4"><div><h3 className="text-base font-semibold text-white">Input Data</h3><p className="mt-1 text-xs leading-5 text-slate-500">Paste logs, alert data, email headers, or incident reports.</p></div><FileText className="size-5 text-slate-600" /></div>
            <div className="relative mt-5 flex min-h-0 flex-1 flex-col"><label htmlFor="ioc-input" className="sr-only">Text to analyze</label><textarea id="ioc-input" value={input} onChange={(event) => { latestRequest.current.cancel(); setIsExtracting(false); setInput(event.target.value) }} placeholder={'Paste security telemetry here...\nExample: connection from 192.0.2.10 to hxxps://cdn.example.net'} className="min-h-[300px] flex-1 resize-none rounded-xl border border-white/10 bg-black/20 p-4 font-mono text-xs leading-6 text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10" /><div className="mt-2 flex items-center justify-between font-mono text-[10px] text-slate-600"><span>{input.length.toLocaleString()} characters</span>{input && <button type="button" onClick={() => { latestRequest.current.cancel(); setIsExtracting(false); setInput(''); setResults([]); setSelectedIndicatorIds(new Set()) }} className="inline-flex items-center gap-1.5 text-slate-500 hover:text-rose-300"><Trash2 className="size-3" /> Clear input</button>}</div></div>
            <div className="mt-6 border-t border-white/[0.08] pt-5"><div className="flex items-center justify-between"><div><h4 className="text-sm font-semibold text-white">Extraction Settings</h4><p className="mt-1 text-xs text-slate-500">Select the indicator types to find.</p></div><button type="button" onClick={() => { latestRequest.current.cancel(); setIsExtracting(false); setSelected(new Set(categoryOptions.map(({ id }) => id))) }} className="font-mono text-[10px] uppercase tracking-wider text-cyan-300 hover:text-cyan-200">Select all</button></div><div className="mt-4 grid gap-2 sm:grid-cols-2">{categoryOptions.map((option) => <label key={option.id} className="flex cursor-pointer items-start gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 hover:border-cyan-400/30"><input type="checkbox" checked={selected.has(option.id)} onChange={() => toggleCategory(option.id)} className="mt-0.5 size-4 accent-cyan-400" /><span><span className="block text-xs font-medium text-slate-200">{option.label}</span><span className="mt-0.5 block text-[10px] text-slate-600">{option.detail}</span></span></label>)}</div></div>
            <button type="button" disabled={!input.trim() || selected.size === 0 || isExtracting} onClick={extract} className="mt-6 inline-flex min-h-12 items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300">{isExtracting ? 'Extracting indicators...' : 'Extract Indicators'}</button>
            <p className="mt-3 text-center font-mono text-[10px] text-slate-600">Text is sent to the configured Flask API for extraction. It is not stored by this tool.</p>
          </section>

          <section className="flex min-h-[680px] min-w-0 flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 shadow-xl shadow-black/10 sm:p-6 xl:h-[min(780px,calc(100dvh-10rem))]">
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/[0.08] pb-5"><div><h3 className="text-base font-semibold text-white">Extracted Indicators</h3><p className="mt-1 font-mono text-[10px] text-slate-500">{results.length} unique · {occurrences} occurrences · {categoryCount} categories</p></div><div className="flex gap-2"><button type="button" disabled={!results.length} onClick={copyAll} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 text-xs text-slate-300 hover:border-cyan-400/40 hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-35"><Clipboard className="size-3.5" /> {copiedId === 'all' ? 'Copied' : 'Copy all'}</button><button type="button" disabled={!results.length} onClick={exportCsv} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 text-xs text-slate-300 hover:border-cyan-400/40 hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-35"><Download className="size-3.5" /> Export CSV</button></div></div>
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] py-4"><div className="flex flex-wrap gap-1">{(Object.keys(filterLabels) as FilterCategory[]).map((id) => <button type="button" key={id} onClick={() => setFilter(id)} className={`rounded-lg px-2.5 py-1.5 text-[11px] transition ${filter === id ? 'bg-cyan-400/10 text-cyan-300' : 'text-slate-500 hover:text-slate-200'}`}>{filterLabels[id]}</button>)}</div><label className="flex h-9 min-w-[190px] items-center gap-2 rounded-lg border border-white/10 px-2.5 text-slate-500 focus-within:border-cyan-400/50"><Search className="size-3.5" /><span className="sr-only">Search results</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter indicators" className="min-w-0 flex-1 bg-transparent text-xs text-slate-200 outline-none placeholder:text-slate-600" /></label></div>
            {results.length > 0 && <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] py-3"><label className="flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" aria-label="Select all visible indicators" disabled={!filteredResults.length || isSavingIndicators} checked={filteredResults.length > 0 && filteredResults.every((item) => selectedIndicatorIds.has(item.id))} onChange={(event) => setSelectedIndicatorIds((current) => selectVisibleIndicators(current, filteredResults.map((item) => item.id), event.target.checked))} className="size-4 accent-cyan-400" />Select all visible <span className="text-slate-500">({filteredResults.length})</span></label><div className="flex items-center gap-3"><span className="font-mono text-[10px] text-slate-500">{selectedIndicatorIds.size} selected</span><button type="button" disabled={!selectedIndicatorIds.size || isSavingIndicators} onClick={() => setSelectedIndicatorIds(new Set())} className="text-xs text-slate-400 hover:text-slate-200 disabled:opacity-40">Clear selection</button></div></div>}
            <div className="min-h-0 flex-1 overflow-auto"><table className="w-full min-w-[680px] border-collapse text-left"><caption className="sr-only">Extracted indicators</caption><thead className="sticky top-0 z-10 bg-[#0d121c]"><tr className="border-b border-white/[0.08] text-[10px] uppercase tracking-wider text-slate-600"><th className="w-10 px-3 py-3 font-medium"><span className="sr-only">Select</span></th><th className="px-3 py-3 font-medium">Type</th><th className="px-3 py-3 font-medium">Indicator</th><th className="px-3 py-3 font-medium">Occurrences</th><th className="px-3 py-3 font-medium">Context</th><th className="px-3 py-3 text-right font-medium">Actions</th></tr></thead><tbody>{filteredResults.map((item) => <tr key={item.id} className="border-b border-white/[0.05] align-top hover:bg-white/[0.02]"><td className="px-3 py-3"><input type="checkbox" aria-label={`Select ${labels[item.category]} indicator ${item.value}`} checked={selectedIndicatorIds.has(item.id)} onChange={() => setSelectedIndicatorIds((current) => toggleIndicatorSelection(current, item.id))} disabled={isSavingIndicators} className="size-4 accent-cyan-400" /></td><td className="px-3 py-3"><span className="rounded bg-cyan-400/10 px-2 py-1 font-mono text-[9px] font-semibold text-cyan-300">{labels[item.category]}</span></td><td className="max-w-[260px] break-all px-3 py-3 font-mono text-xs text-slate-200">{item.value}</td><td className="px-3 py-3 font-mono text-xs text-slate-400">{item.occurrences}</td><td className="max-w-[250px] truncate px-3 py-3 text-xs text-slate-500" title={item.context}>{item.context || '—'}</td><td className="px-3 py-3 text-right"><button type="button" onClick={() => void copyValue(item.value, item.id)} className="inline-flex min-h-8 items-center gap-1 rounded-md px-2 text-[10px] text-slate-500 hover:bg-cyan-400/10 hover:text-cyan-300">{copiedId === item.id ? <Check className="size-3" /> : <Clipboard className="size-3" />}{copiedId === item.id ? 'Copied' : 'Copy'}</button></td></tr>)}</tbody></table>{!filteredResults.length && <div className="flex min-h-[340px] flex-col items-center justify-center px-6 text-center"><span className="flex size-12 items-center justify-center rounded-2xl border border-white/[0.08] bg-white/[0.02] text-slate-600"><ShieldAlert className="size-5" /></span><p className="mt-4 text-sm font-medium text-slate-300">{results.length ? 'No matching indicators' : 'No indicators extracted yet'}</p><p className="mt-2 max-w-sm text-xs leading-5 text-slate-600">{results.length ? 'Try another search term or category filter.' : 'Paste source text on the left and run extraction to review unique indicators.'}</p></div>}</div>
            {results.length > 0 && <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-cyan-400/15 bg-cyan-400/[0.04] p-3"><div><p className="text-xs font-medium text-slate-200">Save selected indicators to a persistent investigation</p><p className="mt-1 text-[10px] text-slate-500">{selectedIndicators.length} selected · nothing is saved until you choose an investigation and confirm.</p></div><button type="button" disabled={!selectedIndicators.length || isSavingIndicators} onClick={openSaveDialog} className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-3 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-40"><Plus className="size-3.5" />Save to Investigation</button></div>}
            <p role="status" aria-live="polite" className="mt-3 min-h-4 text-right font-mono text-[10px] text-cyan-300">{message}</p>
          </section>
        </div>
        {saveDialogOpen && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"><section role="dialog" aria-modal="true" aria-labelledby="save-iocs-title" onKeyDown={(event) => { if (event.key === "Escape" && !isSavingIndicators) setSaveDialogOpen(false) }} className="max-h-[90dvh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-white/10 bg-[#0d121c] p-5 shadow-2xl sm:p-6"><div className="flex items-start justify-between gap-4"><div><p className="font-mono text-[10px] uppercase tracking-[.18em] text-cyan-300">Persistent investigation data</p><h2 id="save-iocs-title" className="mt-2 text-lg font-semibold text-white">Save to Investigation</h2><p className="mt-1 text-xs text-slate-400">Save {selectedIndicators.length} selected indicator{selectedIndicators.length === 1 ? '' : 's'} as IOC records.</p></div><button type="button" onClick={() => setSaveDialogOpen(false)} disabled={isSavingIndicators} className="rounded-lg p-2 text-slate-400 hover:bg-white/5 hover:text-white disabled:opacity-40" aria-label="Close dialog" autoFocus><X className="size-4" /></button></div>
          {authStatus === 'loading' && <div className="mt-6 flex items-center gap-2 text-sm text-slate-300"><LoaderCircle className="size-4 animate-spin" />Checking sign-in status…</div>}
          {authStatus === 'unavailable' && <div className="mt-6 rounded-xl border border-amber-400/20 bg-amber-400/[0.05] p-4 text-sm text-amber-100" role="status">Account and investigation services are temporarily unavailable. Extraction remains usable; saving IoCs will be available when service returns.</div>}
          {authStatus === 'unauthenticated' && <div className="mt-6 rounded-xl border border-amber-400/20 bg-amber-400/[0.05] p-4"><div className="flex items-start gap-3"><LockKeyhole className="mt-0.5 size-4 shrink-0 text-amber-300" /><div><h3 className="text-sm font-semibold text-white">Sign in to save selected IoCs</h3><p className="mt-1 text-xs leading-5 text-slate-400">Extraction remains available while signed out. Open sign in or account creation in another tab, then return here and refresh your sign-in status. Your selected indicators stay on this page.</p><div className="mt-4 flex flex-wrap gap-2"><Link href="/auth" target="_blank" rel="noreferrer" className="inline-flex min-h-9 items-center rounded-lg bg-cyan-400 px-3 text-xs font-semibold text-slate-950">Sign in / Create account</Link><button type="button" onClick={() => void refreshSession()} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 text-xs text-slate-200 hover:bg-white/5"><RefreshCw className="size-3" />Refresh sign-in status</button></div></div></div></div>}
          {authStatus === 'authenticated' && <div className="mt-6"><p className="mb-3 text-xs text-slate-400">Choose one destination investigation. The backend will validate and normalize each IOC.</p>{investigationsError && <div className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-rose-400/20 bg-rose-400/[0.06] p-3 text-xs text-rose-200" role="alert"><span>{investigationsError}</span><button type="button" onClick={() => investigations.length ? void loadMoreInvestigations() : setInvestigationsRetry((current) => current + 1)} className="inline-flex items-center gap-1.5 text-cyan-200"><RefreshCw className="size-3" />Retry</button></div>}{investigationsLoading ? <div className="flex items-center gap-2 py-8 text-sm text-slate-300"><LoaderCircle className="size-4 animate-spin" />Loading your investigations…</div> : investigations.length ? <><div className="max-h-64 space-y-2 overflow-y-auto pr-1" role="radiogroup" aria-label="Destination investigation">{investigations.map((investigation) => <label key={investigation.id} className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition ${destinationId === String(investigation.id) ? 'border-cyan-400/40 bg-cyan-400/[0.07]' : 'border-white/[0.08] bg-white/[0.02] hover:border-white/20'}`}><input type="radio" name="destination-investigation" value={investigation.id} checked={destinationId === String(investigation.id)} onChange={() => { setDestinationId(String(investigation.id)); setSaveReport(null) }} disabled={isSavingIndicators} className="mt-1 size-4 accent-cyan-400" /><span className="min-w-0 flex-1"><span className="block break-words text-sm font-medium text-slate-100">{investigation.title}</span><span className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-slate-500"><span>{investigationStatusLabels[investigation.status]}</span><span>Updated {formatInvestigationDate(investigation.updated_at)}</span></span></span></label>)}</div>{investigationsHaveMore && <button type="button" onClick={() => void loadMoreInvestigations()} disabled={investigationsLoadingMore} className="mt-3 inline-flex items-center gap-2 text-xs text-cyan-300 disabled:opacity-50">{investigationsLoadingMore && <LoaderCircle className="size-3 animate-spin" />}{investigationsLoadingMore ? 'Loading more…' : 'Load more investigations'}</button>}{!destinationId && <p className="mt-3 text-xs text-slate-500">Select an investigation to enable saving.</p>}</> : !investigationsError && <div className="rounded-xl border border-dashed border-white/15 p-5"><h3 className="text-sm font-semibold text-white">No investigations yet</h3><p className="mt-1 text-xs leading-5 text-slate-400">Create an investigation, then return here and refresh your list.</p><button type="button" onClick={() => setInvestigationsRetry((current) => current + 1)} className="mt-3 inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 text-xs text-slate-200 hover:bg-white/5"><RefreshCw className="size-3" />Refresh investigations</button><Link href="/investigations?new=1" target="_blank" rel="noreferrer" className="mt-3 inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-cyan-400/30 px-3 text-xs text-cyan-200"><Plus className="size-3" />Create Investigation</Link></div>}
            {saveReport && <div className={`mt-4 rounded-xl border p-4 ${saveReport.failed.length ? 'border-amber-400/20 bg-amber-400/[0.05]' : 'border-emerald-400/20 bg-emerald-400/[0.05]'}`} role="status"><p className="text-sm font-medium text-white">{saveReport.saved === saveReport.total ? `${saveReport.saved} IoCs saved to “${saveReport.destination.title}”.` : saveReport.saved ? `${saveReport.saved} of ${saveReport.total} IoCs were saved to “${saveReport.destination.title}”. ${saveReport.failed.length} could not be added.` : `None of ${saveReport.total} IoCs could be saved to “${saveReport.destination.title}”.`}</p>{saveReport.saved > 0 && <Link href={`/investigations/${saveReport.destination.id}`} className="mt-2 inline-block text-xs text-cyan-200 hover:text-cyan-100">Open investigation</Link>}{saveReport.failed.length > 0 && <ul className="mt-3 space-y-2">{saveReport.failed.map(({ indicator, message: failureMessage }) => <li key={indicator.id} className="break-words text-xs text-amber-100"><span className="font-mono">{labels[indicator.category]} · {indicator.value}</span><span className="block text-amber-200/70">{failureMessage}</span></li>)}</ul>}</div>}
            <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.08] pt-4"><button type="button" onClick={() => setSaveDialogOpen(false)} disabled={isSavingIndicators} className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-white/10 px-3 text-xs text-slate-200 hover:bg-white/5 disabled:opacity-40">Close</button><button type="button" onClick={() => void saveSelectedIndicators()} disabled={!canPersistIndicators(authStatus === 'authenticated', selectedIndicators.length, isSavingIndicators) || !destinationId || investigationsLoading} className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-cyan-400 px-4 text-xs font-semibold text-slate-950 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40">{isSavingIndicators && <LoaderCircle className="size-3.5 animate-spin" />}{isSavingIndicators ? 'Saving selected IoCs…' : 'Save selected IoCs'}</button></div>
          </div>}
        </section></div>}
      </div>
    </main>
  )
}

export type { Indicator }
