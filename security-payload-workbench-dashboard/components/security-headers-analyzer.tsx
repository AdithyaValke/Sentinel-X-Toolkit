'use client'

import { useMemo, useState } from 'react'
import { Check, ChevronDown, Clipboard, Download, Eraser, FileJson, Search, ShieldCheck } from 'lucide-react'
import { exportAnalysisCsv, exportAnalysisJson, SECURITY_HEADERS_SAMPLE, securityHeadersAnalyzer, type HeaderFindingSeverity, type HeaderFindingStatus, type SecurityHeadersAnalysis } from '@/lib/security-headers-analyzer'

const statusLabels: Record<HeaderFindingStatus, string> = { present: 'Present', missing: 'Missing', misconfigured: 'Potentially misconfigured', 'not-assessed': 'Not assessed' }
const severityLabels: Record<HeaderFindingSeverity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Informational' }

export function SecurityHeadersAnalyzer() {
  const [input, setInput] = useState('')
  const [analysis, setAnalysis] = useState<SecurityHeadersAnalysis | null>(null)
  const [statusFilter, setStatusFilter] = useState<'all' | HeaderFindingStatus>('all')
  const [severityFilter, setSeverityFilter] = useState<'all' | HeaderFindingSeverity>('all')
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)
  const [error, setError] = useState('')

  const findings = useMemo(() => analysis?.findings.filter((finding) => {
    const haystack = `${finding.header} ${finding.explanation} ${finding.remediation}`.toLowerCase()
    return (statusFilter === 'all' || finding.status === statusFilter) && (severityFilter === 'all' || finding.severity === severityFilter) && haystack.includes(query.toLowerCase().trim())
  }) ?? [], [analysis, query, severityFilter, statusFilter])
  const issueCount = analysis?.findings.filter((finding) => finding.status === 'missing' || finding.status === 'misconfigured').length ?? 0

  function analyze() {
    if (!input.trim()) { setError('Paste a response header block before analyzing.'); setAnalysis(null); return }
    setError(''); setAnalysis(securityHeadersAnalyzer.analyze(input)); setExpanded(null)
  }
  function clear() { setInput(''); setAnalysis(null); setError(''); setQuery(''); setExpanded(null) }
  async function copy(text: string, key: string) { try { await navigator.clipboard.writeText(text); setCopied(key); window.setTimeout(() => setCopied(null), 1500) } catch { setError('Clipboard access failed. Select and copy the text manually.') } }
  function download(content: string, filename: string, type: string) { const url = URL.createObjectURL(new Blob([content], { type })); const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url) }
  function summaryText() { if (!analysis) return ''; return `Security Headers Analyzer\nRecognized checks: ${analysis.recognizedHeaders}\nDetected headers: ${analysis.detectedHeaders}\nFindings: ${issueCount}\nCookies reviewed: ${analysis.cookies}\n\n${analysis.findings.map((f) => `${f.header}: ${statusLabels[f.status]} (${severityLabels[f.severity]})`).join('\n')}` }

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
          <div className="mt-4 max-h-[560px] space-y-2 overflow-y-auto pr-1">{findings.length ? findings.map((finding) => <article key={finding.id} className="rounded-xl border border-white/10 bg-white/[0.02]"><button type="button" onClick={() => setExpanded(expanded === finding.id ? null : finding.id)} className="flex min-h-16 w-full items-center gap-3 px-4 py-3 text-left"><ChevronDown className={`size-4 shrink-0 text-slate-500 transition ${expanded === finding.id ? 'rotate-180' : ''}`} /><span className="min-w-0 flex-1"><strong className="block truncate text-xs font-semibold text-slate-200">{finding.header}</strong><span className="mt-1 block text-[11px] text-slate-500">{statusLabels[finding.status]}</span></span><span className={`rounded-full px-2 py-1 text-[10px] font-semibold ${finding.severity === 'high' || finding.severity === 'critical' ? 'bg-rose-400/10 text-rose-300' : finding.severity === 'medium' ? 'bg-amber-400/10 text-amber-300' : 'bg-slate-400/10 text-slate-300'}`}>{severityLabels[finding.severity]}</span></button>{expanded === finding.id && <div className="border-t border-white/10 px-4 py-4 text-xs leading-5 text-slate-400"><p>{finding.explanation}</p><p className="mt-2 text-amber-200/80">Context: {finding.risk}</p>{finding.observedValue && <pre className="mt-3 max-h-28 overflow-auto rounded-lg bg-black/30 p-3 font-mono text-[11px] text-cyan-200">{finding.observedValue}</pre>}<p className="mt-3"><strong className="text-slate-200">Remediation:</strong> {finding.remediation}</p>{finding.example && <code className="mt-3 block overflow-x-auto rounded-lg bg-black/30 p-3 text-[11px] text-emerald-300">{finding.example}</code>}<button type="button" onClick={() => copy(`${finding.header}\n${finding.explanation}\n${finding.remediation}`, finding.id)} className="mt-3 inline-flex items-center gap-1.5 text-xs text-cyan-300">{copied === finding.id ? <Check className="size-3.5" /> : <Clipboard className="size-3.5" />} Copy finding</button></div>}</article>) : <p className="rounded-xl border border-dashed border-white/10 p-6 text-center text-xs text-slate-500">No findings match the selected filters.</p>}</div>
          <p className="mt-4 text-[11px] leading-5 text-slate-500">This is a review of pasted text only. It cannot verify TLS, browser enforcement, live behavior, or whether a policy is appropriate for the full application.</p>
        </>}
      </section>
    </div>
  </section>
}
