'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { AlertTriangle, ArrowLeft, Check, Clipboard, Fingerprint, Info, Loader2 } from 'lucide-react'
import { callBackend, type BackendResponse } from '@/lib/api'
import { LatestRequest } from '@/lib/latest-request'

const HASH_EXAMPLES = [
  { label: 'MD5 (32 hex)', value: '5d41402abc4b2a76b9719d911017c592' },
  { label: 'SHA-256 (64 hex)', value: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' },
  { label: 'bcrypt ($2a$)', value: '$2a$12$e8KERg7gm.bQ1qV8q6uP5.9M5M.x2Y7Wv0.qP4P.r8X1V3Z2Y7Wv0' },
  { label: 'Argon2id', value: '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPuxWCsUzbsRUhq' },
  { label: 'NTLM (32 hex)', value: 'cc325255476a26998656a840e69818ae' },
  { label: 'SHA-1 (40 hex)', value: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d' },
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
    latestRequest.current.cancel()
    setInput(value)
    setAnalysis(null)
    setError('')
    setLoading(false)
  }

  async function identify(value = input) {
    if (debounceTimer.current) window.clearTimeout(debounceTimer.current)
    if (!value.trim()) {
      setAnalysis(null)
      setError('')
      setLoading(false)
      return
    }
    const request = latestRequest.current.begin()
    setLoading(true)
    setError('')
    try {
      const response = await callBackend('identify_hash', value, null, request.signal)
      if (!latestRequest.current.isCurrent(request.id)) return
      if (response.success) setAnalysis(response)
      else { setAnalysis(null); setError(response.error ?? 'The operation failed.') }
    } catch (caught) {
      if (!latestRequest.current.isCurrent(request.id)) return
      setAnalysis(null)
      setError(caught instanceof Error ? caught.message : 'The operation failed.')
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
    <main className="min-h-screen bg-[#080b12] px-4 py-6 text-slate-100 sm:px-6 lg:px-10 lg:py-10">
      <div className="mx-auto max-w-5xl">
        <Link href="/dashboard" className="inline-flex min-h-11 items-center gap-2 text-sm text-slate-400 transition hover:text-cyan-300"><ArrowLeft className="size-4" />Back to dashboard</Link>
        <header className="mt-8"><div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-violet-300"><Fingerprint className="size-4" />Identify Hash Function</div><h1 className="mt-3 text-3xl font-semibold tracking-tight text-white sm:text-4xl">Inspect a hash signature</h1><p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">Paste a hash string to review likely algorithms and the evidence behind each candidate.</p></header>
        <section className="mt-8 grid gap-5 lg:grid-cols-[0.9fr_1.1fr]" aria-label="Hash identification workspace">
          <article className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 sm:p-6"><label htmlFor="identify-input" className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-500">Hash input</label><textarea id="identify-input" value={input} onChange={(event) => updateInput(event.target.value)} placeholder="Paste raw hash string..." spellCheck={false} className="mt-3 min-h-44 w-full resize-y rounded-xl border border-white/[0.1] bg-[#080b12] p-3 font-mono text-sm leading-6 text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-300/50 focus:ring-2 focus:ring-cyan-300/20" aria-describedby={error ? 'identify-error' : undefined} />
            <div className="mt-2 flex justify-between font-mono text-[10px] text-slate-600"><span>{input.length} characters</span><span>UTF-8</span></div>
            <button type="button" onClick={() => void identify()} disabled={!input.trim() || loading} className="mt-5 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-violet-400 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-violet-300 disabled:cursor-not-allowed disabled:opacity-50"><span>{loading ? <Loader2 className="size-4 animate-spin" /> : <Fingerprint className="size-4" />}</span>{loading ? 'Analyzing format...' : 'Identify Hash'}</button>
            <div className="mt-6"><span className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-600">Load sample hash</span><div className="mt-2 flex flex-wrap gap-2">{HASH_EXAMPLES.map((example) => <button key={example.label} type="button" onClick={() => updateInput(example.value)} className="min-h-11 rounded-lg border border-white/10 px-2.5 py-2 text-left text-xs text-slate-400 transition hover:border-violet-300/40 hover:text-violet-200">{example.label}</button>)}</div></div>
          </article>
          <article className="min-w-0 rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 sm:p-6"><div className="flex items-center justify-between gap-3"><div><p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-600">Analysis output</p><h2 className="mt-2 text-lg font-semibold text-white">Hash candidates</h2></div><button type="button" onClick={() => void copyResult()} disabled={!analysis?.result} className="inline-flex min-h-11 shrink-0 items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs text-slate-400 transition hover:border-cyan-300/40 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-40" aria-label="Copy identification result">{copied ? <Check className="size-4" /> : <Clipboard className="size-4" />}{copied ? 'Copied' : 'Copy'}</button></div>
            {error && <p id="identify-error" role="alert" className="mt-5 rounded-xl border border-rose-400/20 bg-rose-400/10 p-3 text-sm leading-6 text-rose-200">{error}</p>}
            {analysis ? <div className="mt-5 min-w-0" tabIndex={0} aria-label="Hash identification results"><div className="flex flex-wrap gap-2 border-b border-white/[0.08] pb-3 text-xs"><span className="rounded bg-cyan-400/10 px-2 py-1 text-cyan-200">Length: {analysis.input_length} chars</span><span className="rounded bg-white/5 px-2 py-1 text-slate-300">Format: {analysis.character_format}</span><span className="rounded bg-emerald-400/10 px-2 py-1 text-emerald-200">{analysis.candidates?.length ? `${analysis.candidates.length} candidate(s)` : 'Unknown format'}</span></div>{analysis.warning && <div className="mt-4 flex gap-3 rounded-xl border border-amber-400/20 bg-amber-400/10 p-3 text-sm leading-6 text-amber-100"><AlertTriangle className="mt-1 size-4 shrink-0" /><span>{analysis.warning}</span></div>}<div className="mt-4 flex flex-col gap-3">{analysis.candidates?.map((candidate, index) => <div key={`${candidate.algorithm}-${index}`} className="min-w-0 rounded-xl border border-white/[0.08] bg-white/[0.025] p-4"><div className="flex flex-wrap items-center justify-between gap-2"><strong className="text-cyan-200">{candidate.algorithm}</strong><span className="rounded bg-white/5 px-2 py-1 text-[10px] uppercase tracking-wider text-slate-400">{candidate.evidence.replace(/_/g, ' ')}</span></div><p className="mt-2 break-words text-sm leading-6 text-slate-400">{candidate.explanation}</p></div>)}</div>{analysis.recommendation && <div className="mt-4 flex gap-3 rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-3 text-sm leading-6 text-cyan-100"><Info className="mt-1 size-4 shrink-0" /><span>{analysis.recommendation}</span></div>}</div> : <div className="flex min-h-60 flex-col items-center justify-center gap-2 text-center text-slate-500"><Info className="size-6" /><p className="font-semibold text-slate-300">Waiting for a hash</p><p className="max-w-xs text-sm leading-6">Enter a value or choose a sample to see likely algorithms.</p></div>}
          </article>
        </section>
      </div>
    </main>
  )
}
