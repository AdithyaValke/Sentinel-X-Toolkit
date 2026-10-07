'use client'

import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Check, Clipboard, Fingerprint, Info, Layers3, Loader2, ScanSearch, ShieldCheck, Sparkles } from 'lucide-react'
import { callBackend, type BackendResponse } from '@/lib/api'
import { LatestRequest } from '@/lib/latest-request'
import { recordActivity } from '@/lib/activity'

const HASH_EXAMPLES = [
  { label: 'MD5 (32 hex)', detail: '32 characters', value: '5d41402abc4b2a76b9719d911017c592' },
  { label: 'SHA-256 (64 hex)', detail: '64 characters', value: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' },
  { label: 'bcrypt ($2a$)', detail: 'Password hash', value: '$2a$12$e8KERg7gm.bQ1qV8q6uP5.9M5M.x2Y7Wv0.qP4P.r8X1V3Z2Y7Wv0' },
  { label: 'Argon2id', detail: 'Password hash', value: '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPuxWCsUzbsRUhq' },
  { label: 'NTLM (32 hex)', detail: '32 characters', value: 'cc325255476a26998656a840e69818ae' },
  { label: 'SHA-1 (40 hex)', detail: '40 characters', value: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d' },
]

export function IdentifyHash() {
  const [input, setInput] = useState('')
  const [analysis, setAnalysis] = useState<BackendResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const latestRequest = useRef(new LatestRequest())
  const debounceTimer = useRef<number | null>(null)

  function updateInput(value: string) {
    if (debounceTimer.current) window.clearTimeout(debounceTimer.current)
    latestRequest.current.cancel(); setInput(value); setAnalysis(null); setError(''); setLoading(false)
  }

  async function identify(value = input) {
    if (debounceTimer.current) window.clearTimeout(debounceTimer.current)
    if (!value.trim()) { setAnalysis(null); setError(''); setLoading(false); return }
    const request = latestRequest.current.begin(); setLoading(true); setError('')
    try {
      const response = await callBackend('identify_hash', value, null, request.signal)
      if (!latestRequest.current.isCurrent(request.id)) return
      if (response.success) { setAnalysis(response); recordActivity('Identify Hash', 'identify', 'success', 'Hash identification completed') }
      else { setAnalysis(null); setError(response.error ?? 'The operation failed.'); recordActivity('Identify Hash', 'identify', 'failure', 'Hash identification failed') }
    } catch (caught) {
      if (!latestRequest.current.isCurrent(request.id)) return
      setAnalysis(null); setError(caught instanceof Error ? caught.message : 'The operation failed.')
      recordActivity('Identify Hash', 'identify', 'failure', 'Hash identification failed')
    } finally { if (latestRequest.current.isCurrent(request.id)) setLoading(false) }
  }

  useEffect(() => {
    if (!input.trim()) { latestRequest.current.cancel(); setAnalysis(null); setError(''); setLoading(false); return }
    debounceTimer.current = window.setTimeout(() => void identify(input), 300)
    return () => { if (debounceTimer.current) window.clearTimeout(debounceTimer.current); latestRequest.current.cancel() }
  }, [input])

  async function copyResult() {
    if (!analysis?.result) return
    try { await navigator.clipboard.writeText(analysis.result); setCopied(true); window.setTimeout(() => setCopied(false), 1600) }
    catch { setError('Clipboard access failed. Select and copy the result manually.') }
  }

  return (
    <main className="identify-hash-page min-h-screen bg-slate-50 text-slate-900 transition-colors dark:bg-[#050b14] dark:text-slate-100">
      <div className="mx-auto flex min-h-screen w-full max-w-[1480px] flex-col px-4 py-6 sm:px-6 lg:px-9 lg:py-7">
        <header className="border-b border-slate-200 pb-5 dark:border-slate-800/80">
          <div className="flex items-center gap-2 font-mono text-[10px] font-bold uppercase tracking-[0.22em] text-cyan-700 dark:text-cyan-400"><Fingerprint className="size-4" /> SECURITY TOOLING</div>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight sm:text-5xl">Inspect a <span className="text-cyan-600 dark:text-cyan-400">hash signature</span></h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600 dark:text-slate-400">Paste one or more hashes to review likely algorithms and evidence. Analyze up to 50 non-empty lines per request.</p>
        </header>

        <section className="grid flex-1 gap-5 py-5 lg:grid-cols-2" aria-label="Hash identification workspace">
          <article className="flex min-h-0 flex-col rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950/45 sm:p-6">
            <div className="flex items-center justify-between"><h2 className="flex items-center gap-3 font-mono text-sm font-bold uppercase tracking-wider"><span className="flex size-9 items-center justify-center rounded-full bg-cyan-500/15 text-xs text-cyan-700 dark:text-cyan-300">01</span> Hash input</h2><span className="rounded-full bg-cyan-500/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-cyan-700 dark:text-cyan-300">Live</span></div>
            <textarea id="identify-input" value={input} onChange={(event) => updateInput(event.target.value)} placeholder="Paste raw hash string..." spellCheck={false} className="mt-4 min-h-40 flex-1 resize-y rounded-xl border border-slate-200 bg-slate-50 p-3 font-mono text-sm leading-6 text-slate-800 outline-none placeholder:text-slate-500 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/15 dark:border-slate-800 dark:bg-[#07111f] dark:text-slate-200 dark:placeholder:text-slate-600" aria-describedby={error ? 'identify-error' : undefined} />
            <div className="mt-2 flex justify-between font-mono text-[10px] text-slate-500"><span>{input.length} characters</span><span>UTF-8</span></div>
            <button type="button" onClick={() => void identify()} disabled={!input.trim() || loading} className="mt-4 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 disabled:cursor-not-allowed disabled:opacity-50">{loading ? <Loader2 className="size-4 animate-spin" /> : <Fingerprint className="size-4" />}{loading ? 'Analyzing format...' : 'Identify Hash'}</button>
            <div className="mt-6"><span className="font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">Load sample hash</span><div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">{HASH_EXAMPLES.map((example) => <button key={example.label} type="button" onClick={() => updateInput(example.value)} className="flex min-h-14 items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-2.5 text-left transition hover:border-cyan-500/60 hover:bg-cyan-500/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:border-slate-800 dark:bg-slate-900/70"><span className="flex size-7 shrink-0 items-center justify-center rounded-full bg-cyan-500/10 text-cyan-600 dark:text-cyan-300"><ShieldCheck className="size-3.5" /></span><span className="min-w-0"><strong className="block truncate text-[11px] font-medium">{example.label}</strong><small className="mt-1 block truncate text-[10px] text-slate-500">{example.detail}</small></span></button>)}</div></div>
            {error && <p id="identify-error" role="alert" className="mt-4 rounded-lg border border-rose-300 bg-rose-50 p-3 text-sm leading-6 text-rose-700 dark:border-rose-400/20 dark:bg-rose-400/10 dark:text-rose-200">{error}</p>}
          </article>

          <article className="flex min-h-0 flex-col rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950/45 sm:p-6"><div className="flex items-center justify-between gap-3"><h2 className="flex items-center gap-3 font-mono text-sm font-bold uppercase tracking-wider"><span className="flex size-9 items-center justify-center rounded-full bg-cyan-500/15 text-xs text-cyan-700 dark:text-cyan-300">02</span> Analysis results</h2><button type="button" onClick={() => void copyResult()} disabled={!analysis?.result} className="inline-flex min-h-10 shrink-0 items-center gap-2 rounded-lg border border-slate-200 px-3 text-xs text-slate-500 transition hover:border-cyan-500/50 hover:text-cyan-700 disabled:cursor-not-allowed disabled:opacity-40 dark:border-slate-800 dark:text-slate-400 dark:hover:text-cyan-300" aria-label="Copy identification result">{copied ? <Check className="size-4" /> : <Clipboard className="size-4" />}{copied ? 'Copied' : 'Copy'}</button></div>
            {analysis ? <div className="mt-5 min-w-0 overflow-y-auto" tabIndex={0} aria-label="Hash identification results"><div className="flex flex-wrap gap-2 border-b border-slate-200 pb-3 text-xs dark:border-slate-800"><span className="rounded bg-cyan-500/10 px-2 py-1 text-cyan-700 dark:text-cyan-200">Length: {analysis.input_length} chars</span><span className="rounded bg-slate-100 px-2 py-1 text-slate-600 dark:bg-white/5 dark:text-slate-300">Format: {analysis.character_format}</span><span className="rounded bg-emerald-500/10 px-2 py-1 text-emerald-700 dark:text-emerald-200">{analysis.candidates?.length ? `${analysis.candidates.length} candidate(s)` : 'Unknown format'}</span></div>{analysis.warning && <div className="mt-4 flex gap-3 rounded-xl border border-amber-300 bg-amber-50 p-3 text-sm leading-6 text-amber-800 dark:border-amber-400/20 dark:bg-amber-400/10 dark:text-amber-100"><AlertTriangle className="mt-1 size-4 shrink-0" /><span>{analysis.warning}</span></div>}<div className="mt-4 flex flex-col gap-3">{analysis.candidates?.map((candidate, index) => <div key={`${candidate.algorithm}-${index}`} className="rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-white/[0.025]"><div className="flex flex-wrap items-center justify-between gap-2"><strong className="text-cyan-700 dark:text-cyan-200">{candidate.algorithm}</strong><span className="rounded bg-slate-200 px-2 py-1 text-[10px] uppercase tracking-wider text-slate-600 dark:bg-white/5 dark:text-slate-400">{candidate.evidence.replace(/_/g, ' ')}</span></div><p className="mt-2 break-words text-sm leading-6 text-slate-600 dark:text-slate-400">{candidate.explanation}</p></div>)}</div>{analysis.recommendation && <div className="mt-4 flex gap-3 rounded-xl border border-cyan-300 bg-cyan-50 p-3 text-sm leading-6 text-cyan-900 dark:border-cyan-400/20 dark:bg-cyan-400/10 dark:text-cyan-100"><Info className="mt-1 size-4 shrink-0" /><span>{analysis.recommendation}</span></div>}</div> : <div className="flex min-h-0 flex-1 flex-col justify-center"><div className="mx-auto max-w-xl text-center"><div className="mx-auto flex size-24 items-center justify-center rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-500"><Fingerprint className="size-12" /></div><h3 className="mt-5 text-2xl font-semibold">Ready to inspect a hash</h3><p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-600 dark:text-slate-400">Paste a hash or choose a sample to view likely algorithms and supporting evidence.</p><div className="mt-8 grid gap-3 sm:grid-cols-3"><div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-left dark:border-slate-800 dark:bg-slate-900/60"><ScanSearch className="size-6 text-cyan-600 dark:text-cyan-300" /><strong className="mt-4 block text-sm">Pattern matching</strong><p className="mt-2 text-xs leading-5 text-slate-500">Analyzes hash structure and common patterns.</p></div><div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-left dark:border-slate-800 dark:bg-slate-900/60"><Layers3 className="size-6 text-cyan-600 dark:text-cyan-300" /><strong className="mt-4 block text-sm">Candidate ranking</strong><p className="mt-2 text-xs leading-5 text-slate-500">Ranks likely algorithms using confidence score.</p></div><div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-left dark:border-slate-800 dark:bg-slate-900/60"><Sparkles className="size-6 text-cyan-600 dark:text-cyan-300" /><strong className="mt-4 block text-sm">Evidence details</strong><p className="mt-2 text-xs leading-5 text-slate-500">Shows format, length, and matching indicators.</p></div></div></div></div>}
          </article>
        </section>

        <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950/45 sm:p-5" aria-labelledby="quick-reference-title"><div className="flex items-center gap-2 font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-cyan-700 dark:text-cyan-300"><Info className="size-4" /><span id="quick-reference-title">Quick reference</span></div><div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4"><div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 dark:border-slate-800 dark:bg-slate-900/60"><strong className="text-sm text-cyan-700 dark:text-cyan-300">32 hex chars</strong><p className="mt-1 text-xs text-slate-500">MD5 / NTLM</p></div><div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 dark:border-slate-800 dark:bg-slate-900/60"><strong className="text-sm text-cyan-700 dark:text-cyan-300">40 hex chars</strong><p className="mt-1 text-xs text-slate-500">SHA-1</p></div><div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 dark:border-slate-800 dark:bg-slate-900/60"><strong className="text-sm text-cyan-700 dark:text-cyan-300">64 hex chars</strong><p className="mt-1 text-xs text-slate-500">SHA-256</p></div><div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 dark:border-slate-800 dark:bg-slate-900/60"><strong className="text-sm text-cyan-700 dark:text-cyan-300">Password hashes</strong><p className="mt-1 text-xs text-slate-500">bcrypt / Argon2id</p></div></div><p className="mt-3 text-[11px] text-slate-500">Format and length are heuristic clues, not definitive identification.</p></section>
      </div>
    </main>
  )
}
