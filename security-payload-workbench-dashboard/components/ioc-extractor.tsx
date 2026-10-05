'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { ArrowLeft, Check, Clipboard, Download, FileText, Search, ShieldAlert, Trash2 } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { extractIocs, type IndicatorCategory } from '@/lib/api'
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

export function IocExtractor() {
  const router = useRouter()
  const [input, setInput] = useState('')
  const [selected, setSelected] = useState<Set<IndicatorCategory>>(() => new Set(categoryOptions.map(({ id }) => id)))
  const [results, setResults] = useState<Indicator[]>([])
  const [filter, setFilter] = useState<FilterCategory>('all')
  const [search, setSearch] = useState('')
  const [isExtracting, setIsExtracting] = useState(false)
  const [message, setMessage] = useState('')
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const latestRequest = useRef(new LatestRequest())

  useEffect(() => () => latestRequest.current.cancel(), [])

  const filteredResults = useMemo(() => results.filter((item) => (
    (filter === 'all' || item.category === filter) &&
    (!search.trim() || `${item.value} ${item.context}`.toLowerCase().includes(search.trim().toLowerCase()))
  )), [filter, results, search])
  const occurrences = results.reduce((sum, item) => sum + item.occurrences, 0)
  const categoryCount = new Set(results.map((item) => item.category)).size

  async function extract() {
    if (!input.trim() || selected.size === 0) return
    const { id, signal } = latestRequest.current.begin()
    setIsExtracting(true)
    setMessage('')
    try {
      const response = await extractIocs(input, Array.from(selected), signal)
      if (!latestRequest.current.isCurrent(id)) return
      setResults(response.results.map((item) => ({ ...item, id: `${item.category}:${item.value.toLowerCase()}` })))
      setFilter('all')
      setMessage(response.results.length ? 'Potential indicators extracted. Values are not reputation-checked.' : 'No indicators found.')
    } catch (error) {
      if (!latestRequest.current.isCurrent(id)) return
      setMessage(error instanceof Error ? error.message : 'Extraction failed. Please try again.')
    } finally {
      if (latestRequest.current.isCurrent(id)) setIsExtracting(false)
    }
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
      <div className="mx-auto max-w-[1500px] px-4 py-5 sm:px-6 lg:px-8 lg:py-7">
        <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <button type="button" onClick={() => router.push('/security-lab')} className="mb-3 inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-300 hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"><ArrowLeft className="size-3.5" /> Analysis Lab</button>
            <div className="flex items-center gap-3"><span className="flex size-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300"><ShieldAlert className="size-5" /></span><div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-300">Analysis Lab / Tool</p><h2 className="mt-1 text-2xl font-bold tracking-tight text-white sm:text-3xl">IoC Extractor</h2></div></div>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">Extract and organize potential indicators of compromise from logs, alerts, and unstructured text.</p>
          </div>
          <span className="rounded-full border border-cyan-400/20 bg-cyan-400/[0.06] px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-cyan-300">Flask API</span>
        </div>

        <div className="grid items-stretch gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.35fr)]">
          <section className="flex min-h-[680px] flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 shadow-xl shadow-black/10 sm:p-6">
            <div className="flex items-start justify-between gap-4"><div><h3 className="text-base font-semibold text-white">Input Data</h3><p className="mt-1 text-xs leading-5 text-slate-500">Paste logs, alert data, email headers, or incident reports.</p></div><FileText className="size-5 text-slate-600" /></div>
            <div className="relative mt-5 flex min-h-0 flex-1 flex-col"><label htmlFor="ioc-input" className="sr-only">Text to analyze</label><textarea id="ioc-input" value={input} onChange={(event) => { latestRequest.current.cancel(); setIsExtracting(false); setInput(event.target.value) }} placeholder={'Paste security telemetry here...\nExample: connection from 192.0.2.10 to hxxps://cdn.example.net'} className="min-h-[300px] flex-1 resize-none rounded-xl border border-white/10 bg-black/20 p-4 font-mono text-xs leading-6 text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10" /><div className="mt-2 flex items-center justify-between font-mono text-[10px] text-slate-600"><span>{input.length.toLocaleString()} characters</span>{input && <button type="button" onClick={() => { latestRequest.current.cancel(); setIsExtracting(false); setInput(''); setResults([]) }} className="inline-flex items-center gap-1.5 text-slate-500 hover:text-rose-300"><Trash2 className="size-3" /> Clear input</button>}</div></div>
            <div className="mt-6 border-t border-white/[0.08] pt-5"><div className="flex items-center justify-between"><div><h4 className="text-sm font-semibold text-white">Extraction Settings</h4><p className="mt-1 text-xs text-slate-500">Select the indicator types to find.</p></div><button type="button" onClick={() => { latestRequest.current.cancel(); setIsExtracting(false); setSelected(new Set(categoryOptions.map(({ id }) => id))) }} className="font-mono text-[10px] uppercase tracking-wider text-cyan-300 hover:text-cyan-200">Select all</button></div><div className="mt-4 grid gap-2 sm:grid-cols-2">{categoryOptions.map((option) => <label key={option.id} className="flex cursor-pointer items-start gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 hover:border-cyan-400/30"><input type="checkbox" checked={selected.has(option.id)} onChange={() => toggleCategory(option.id)} className="mt-0.5 size-4 accent-cyan-400" /><span><span className="block text-xs font-medium text-slate-200">{option.label}</span><span className="mt-0.5 block text-[10px] text-slate-600">{option.detail}</span></span></label>)}</div></div>
            <button type="button" disabled={!input.trim() || selected.size === 0 || isExtracting} onClick={extract} className="mt-6 inline-flex min-h-12 items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300">{isExtracting ? 'Extracting indicators...' : 'Extract Indicators'}</button>
            <p className="mt-3 text-center font-mono text-[10px] text-slate-600">Text is sent to the configured Flask API for extraction. It is not stored by this tool.</p>
          </section>

          <section className="flex min-h-[680px] min-w-0 flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 shadow-xl shadow-black/10 sm:p-6">
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/[0.08] pb-5"><div><h3 className="text-base font-semibold text-white">Extracted Indicators</h3><p className="mt-1 font-mono text-[10px] text-slate-500">{results.length} unique · {occurrences} occurrences · {categoryCount} categories</p></div><div className="flex gap-2"><button type="button" disabled={!results.length} onClick={copyAll} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 text-xs text-slate-300 hover:border-cyan-400/40 hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-35"><Clipboard className="size-3.5" /> {copiedId === 'all' ? 'Copied' : 'Copy all'}</button><button type="button" disabled={!results.length} onClick={exportCsv} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 px-3 text-xs text-slate-300 hover:border-cyan-400/40 hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-35"><Download className="size-3.5" /> Export CSV</button></div></div>
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] py-4"><div className="flex flex-wrap gap-1">{(Object.keys(filterLabels) as FilterCategory[]).map((id) => <button type="button" key={id} onClick={() => setFilter(id)} className={`rounded-lg px-2.5 py-1.5 text-[11px] transition ${filter === id ? 'bg-cyan-400/10 text-cyan-300' : 'text-slate-500 hover:text-slate-200'}`}>{filterLabels[id]}</button>)}</div><label className="flex h-9 min-w-[190px] items-center gap-2 rounded-lg border border-white/10 px-2.5 text-slate-500 focus-within:border-cyan-400/50"><Search className="size-3.5" /><span className="sr-only">Search results</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter indicators" className="min-w-0 flex-1 bg-transparent text-xs text-slate-200 outline-none placeholder:text-slate-600" /></label></div>
            <div className="min-h-0 flex-1 overflow-auto"><table className="w-full min-w-[650px] border-collapse text-left"><caption className="sr-only">Extracted indicators</caption><thead className="sticky top-0 z-10 bg-[#0d121c]"><tr className="border-b border-white/[0.08] text-[10px] uppercase tracking-wider text-slate-600"><th className="px-3 py-3 font-medium">Type</th><th className="px-3 py-3 font-medium">Indicator</th><th className="px-3 py-3 font-medium">Occurrences</th><th className="px-3 py-3 font-medium">Context</th><th className="px-3 py-3 text-right font-medium">Actions</th></tr></thead><tbody>{filteredResults.map((item) => <tr key={item.id} className="border-b border-white/[0.05] align-top hover:bg-white/[0.02]"><td className="px-3 py-3"><span className="rounded bg-cyan-400/10 px-2 py-1 font-mono text-[9px] font-semibold text-cyan-300">{labels[item.category]}</span></td><td className="max-w-[260px] break-all px-3 py-3 font-mono text-xs text-slate-200">{item.value}</td><td className="px-3 py-3 font-mono text-xs text-slate-400">{item.occurrences}</td><td className="max-w-[250px] truncate px-3 py-3 text-xs text-slate-500" title={item.context}>{item.context || '—'}</td><td className="px-3 py-3 text-right"><button type="button" onClick={() => void copyValue(item.value, item.id)} className="inline-flex min-h-8 items-center gap-1 rounded-md px-2 text-[10px] text-slate-500 hover:bg-cyan-400/10 hover:text-cyan-300">{copiedId === item.id ? <Check className="size-3" /> : <Clipboard className="size-3" />}{copiedId === item.id ? 'Copied' : 'Copy'}</button></td></tr>)}</tbody></table>{!filteredResults.length && <div className="flex min-h-[340px] flex-col items-center justify-center px-6 text-center"><span className="flex size-12 items-center justify-center rounded-2xl border border-white/[0.08] bg-white/[0.02] text-slate-600"><ShieldAlert className="size-5" /></span><p className="mt-4 text-sm font-medium text-slate-300">{results.length ? 'No matching indicators' : 'No indicators extracted yet'}</p><p className="mt-2 max-w-sm text-xs leading-5 text-slate-600">{results.length ? 'Try another search term or category filter.' : 'Paste source text on the left and run extraction to review unique indicators.'}</p></div>}</div>
            <p role="status" aria-live="polite" className="mt-3 min-h-4 text-right font-mono text-[10px] text-cyan-300">{message}</p>
          </section>
        </div>
      </div>
    </main>
  )
}

export type { Indicator }
