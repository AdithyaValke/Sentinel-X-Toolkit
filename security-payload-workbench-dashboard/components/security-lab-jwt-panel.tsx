'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle, Check, Clipboard, Clock3, Copy, Info, KeyRound, LoaderCircle,
  LockKeyhole, ShieldAlert, ShieldCheck, TriangleAlert,
} from 'lucide-react'
import { analyzeJwt, createSampleJwt, formatJwtRelativeTime, formatJsonForDisplay, verifyHmac, type JwtAnalysis, type JwtFinding, type JwtSeverity } from '@/lib/jwt-utils.ts'

function ColoredJson({ value }: { value: unknown }) {
  const text = formatJsonForDisplay(value)
  const expression = /("(?:\\.|[^"\\])*"(?=\s*:)|"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\],:])/g
  const parts: React.ReactNode[] = []
  let last = 0
  for (const match of text.matchAll(expression)) {
    const index = match.index ?? 0
    if (index > last) parts.push(text.slice(last, index))
    const token = match[0]
    const following = text.slice(index + token.length).match(/^\s*([\s\S])/)?.[1]
    const color = token.startsWith('"') ? following === ':' ? 'text-cyan-300' : 'text-emerald-300'
      : /^-?\d/.test(token) || token === 'true' || token === 'false' || token === 'null' ? 'text-violet-300' : 'text-slate-500'
    parts.push(<span key={`${index}-${token}`} className={color}>{token}</span>)
    last = index + token.length
  }
  if (last < text.length) parts.push(text.slice(last))
  return <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-all rounded-xl border border-white/[0.07] bg-[#060810] p-4 font-mono text-[11px] leading-5 text-slate-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 sm:text-xs">{parts}</pre>
}

function CopyJsonButton({ value, label, copied, onCopy }: { value: unknown; label: string; copied: string; onCopy: (value: string, label: string) => void }) {
  return <button type="button" onClick={() => onCopy(formatJsonForDisplay(value), label)} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-3 text-xs text-slate-300 transition hover:border-cyan-400/40 hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400" aria-label={`Copy ${label} JSON`}>
    {copied === label ? <Check className="size-3.5 text-emerald-400" /> : <Copy className="size-3.5" />}{copied === label ? 'Copied' : 'Copy'}
  </button>
}

const severityMeta: Record<JwtSeverity, { label: string; icon: typeof ShieldAlert; className: string }> = {
  critical: { label: 'Critical', icon: ShieldAlert, className: 'border-rose-400/20 bg-rose-400/10 text-rose-300' },
  warning: { label: 'Warning', icon: TriangleAlert, className: 'border-amber-400/20 bg-amber-400/10 text-amber-300' },
  info: { label: 'Info', icon: Info, className: 'border-cyan-400/20 bg-cyan-400/10 text-cyan-300' },
}

function FindingGroup({ severity, findings }: { severity: JwtSeverity; findings: JwtFinding[] }) {
  const meta = severityMeta[severity]
  const Icon = meta.icon
  return <section aria-labelledby={`jwt-${severity}-heading`} className="rounded-xl border border-white/[0.07] bg-[#080c14] p-4">
    <div className="mb-3 flex items-center justify-between"><h4 id={`jwt-${severity}-heading`} className="flex items-center gap-2 text-xs font-semibold text-slate-200"><Icon className="size-4" />{meta.label}</h4><span className={`rounded-full border px-2 py-0.5 font-mono text-[10px] ${meta.className}`}>{findings.length}</span></div>
    {findings.length ? <ul className="space-y-3">{findings.map((item, index) => <li key={`${item.title}-${index}`} className="border-t border-white/[0.06] pt-3 first:border-0 first:pt-0"><p className="text-xs font-semibold text-slate-200">{item.title}</p><p className="mt-1 text-xs leading-5 text-slate-400">{item.explanation}</p><p className="mt-1.5 text-[11px] leading-5 text-slate-500"><span className="font-semibold text-slate-400">What to check:</span> {item.whatToCheck}</p></li>)}</ul>
      : <p className="text-xs text-slate-500">No {meta.label.toLowerCase()} findings.</p>}
  </section>
}

function TokenParts({ analysis }: { analysis: JwtAnalysis }) {
  const segments = [
    { label: 'Header', value: analysis.encodedHeader, color: 'text-cyan-300 border-cyan-400/30 bg-cyan-400/[0.06]' },
    { label: 'Payload', value: analysis.encodedPayload, color: 'text-emerald-300 border-emerald-400/30 bg-emerald-400/[0.06]' },
    { label: 'Signature', value: analysis.signature || '(empty)', color: 'text-violet-300 border-violet-400/30 bg-violet-400/[0.06]' },
  ]
  return <div className="mt-4 space-y-2" aria-label="JWT segments">{segments.map(({ label, value, color }) => <div key={label} className={`rounded-lg border p-2.5 ${color}`}><p className="mb-1 font-mono text-[9px] font-semibold uppercase tracking-[0.18em]">{label}</p><p className="break-all font-mono text-[10px] leading-4 sm:text-[11px]">{value}</p></div>)}</div>
}

function ClaimsTable({ analysis, now }: { analysis: JwtAnalysis; now: number }) {
  const claims = ['exp', 'iat', 'nbf'] as const
  const timestampByClaim = new Map(analysis.timestamps.map((item) => [item.claim, item]))
  return <section className="mt-5" aria-labelledby="jwt-claims-heading"><h3 id="jwt-claims-heading" className="mb-2 flex items-center gap-2 text-xs font-semibold text-slate-200"><Clock3 className="size-4 text-cyan-300" />Time claims</h3><div className="overflow-x-auto rounded-xl border border-white/[0.07]"><table className="w-full min-w-[480px] text-left text-[10px] sm:text-xs"><thead className="bg-white/[0.03] font-mono text-[9px] uppercase tracking-wider text-slate-500"><tr><th className="px-3 py-2">Claim</th><th className="px-3 py-2">UTC</th><th className="px-3 py-2">Local</th><th className="px-3 py-2">Relative</th></tr></thead><tbody>{claims.map((claim) => {
    const time = timestampByClaim.get(claim)
    const value = analysis.payload[claim]
    const invalid = value !== undefined && !time
    return <tr key={claim} className="border-t border-white/[0.06]"><th className="px-3 py-2 font-mono font-medium text-cyan-200">{claim}</th><td className="px-3 py-2 text-slate-300">{time?.utc ?? (invalid ? 'Invalid timestamp' : 'Not present')}</td><td className="px-3 py-2 text-slate-300">{time?.local ?? '—'}</td><td className="px-3 py-2 text-slate-400">{time ? formatJwtRelativeTime(claim, time.seconds, now) : '—'}</td></tr>
  })}</tbody></table></div></section>
}

export function SecurityLabJwtPanel() {
  const [token, setToken] = useState('')
  const [secret, setSecret] = useState('')
  const [demoSecretHint, setDemoSecretHint] = useState(false)
  const [now, setNow] = useState(Date.now())
  const [copied, setCopied] = useState('')
  const [verification, setVerification] = useState<{ status: 'valid' | 'invalid' | 'unsupported' | 'unchecked'; explanation: string }>({ status: 'unchecked', explanation: 'Signature has not been checked.' })
  const [verifying, setVerifying] = useState(false)
  const [sampleLoading, setSampleLoading] = useState(false)
  const [actionError, setActionError] = useState('')
  const rightScrollRef = useRef<HTMLDivElement>(null)
  const parseResult = useMemo(() => analyzeJwt(token, now), [token, now])
  const analysis = parseResult.ok ? parseResult.analysis : null

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 30_000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    rightScrollRef.current?.scrollTo({ top: 0 })
  }, [token])

  async function copyText(value: string, key: string) {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(key)
      window.setTimeout(() => setCopied((current) => current === key ? '' : current), 1500)
    } catch {
      setActionError('Clipboard access failed. Select and copy the text manually.')
    }
  }

  function updateToken(value: string) {
    setNow(Date.now()); setToken(value); setVerification({ status: 'unchecked', explanation: 'Signature has not been checked.' }); setActionError('')
  }

  async function loadSample() {
    setSampleLoading(true); setActionError('')
    try {
      const sample = await createSampleJwt()
      updateToken(sample); setSecret('demo-secret'); setDemoSecretHint(true)
    } catch {
      setActionError('A sample token could not be created in this browser.')
    } finally { setSampleLoading(false) }
  }

  async function runVerification() {
    if (!analysis) return
    setVerifying(true)
    const checked = await verifyHmac(token, secret)
    setVerification({ status: checked.status, explanation: checked.explanation })
    setVerifying(false)
  }

  const isHmac = Boolean(analysis && /^HS(256|384|512)$/i.test(analysis.algorithm))
  const visibleVerificationStatus = verification.status === 'unchecked' && analysis && !isHmac ? 'unsupported' : verification.status
  const verificationLabel = visibleVerificationStatus === 'valid' ? 'Valid' : visibleVerificationStatus === 'invalid' ? 'Invalid' : visibleVerificationStatus === 'unsupported' ? 'Not verifiable' : 'Not checked'
  const verificationTone = visibleVerificationStatus === 'valid' ? 'border-emerald-400/25 bg-emerald-400/10 text-emerald-300' : visibleVerificationStatus === 'invalid' ? 'border-rose-400/25 bg-rose-400/10 text-rose-300' : visibleVerificationStatus === 'unsupported' ? 'border-amber-400/25 bg-amber-400/10 text-amber-300' : 'border-white/10 bg-white/[0.03] text-slate-400'
  const visibleVerificationExplanation = visibleVerificationStatus === 'unsupported' && verification.status === 'unchecked' ? 'Verification needs a public key for this algorithm and is not supported here.' : verification.explanation
  const findingsBySeverity = (['critical', 'warning', 'info'] as const).map((severity) => ({ severity, items: analysis?.findings.filter((item) => item.severity === severity) ?? [] }))
  const inputLength = new TextEncoder().encode(token).byteLength

  return <section className="mt-8" aria-labelledby="jwt-panel-heading">
    <header className="mb-5">
      <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-emerald-400"><KeyRound className="size-3.5" /> Token Inspection</div>
      <h2 id="jwt-panel-heading" className="mt-2 text-2xl font-bold text-white sm:text-3xl">JWT Decoder and Analyzer</h2>
      <p className="mt-2 text-sm text-slate-400">Decode token contents and review defensive checks without trusting their claims.</p>
      <p className="mt-3 flex items-center gap-2 rounded-xl border border-emerald-400/20 bg-emerald-400/[0.05] p-3 text-xs leading-5 text-emerald-100"><LockKeyhole className="size-4 shrink-0 text-emerald-300" />Decoded locally in your browser. Tokens and secrets are never sent to a server.</p>
    </header>

    <div className="grid items-stretch gap-5 xl:grid-cols-2">
      <div className="min-h-[24rem] xl:relative">
        <div ref={rightScrollRef} tabIndex={0} role="region" aria-label="Decoded token and analysis" className="space-y-5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 [scrollbar-width:thin] [scrollbar-color:rgb(34_211_238_/_0.42)_transparent] [&::-webkit-scrollbar]:w-[7px] [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-cyan-400/40 [html.light_&]:[scrollbar-color:rgb(8_145_178_/_0.5)_transparent] [html.light_&::-webkit-scrollbar-thumb]:bg-cyan-700/50 xl:absolute xl:inset-0 xl:overflow-y-auto xl:pr-1">
        <section className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-4 sm:p-5" aria-labelledby="jwt-token-heading">
          <div className="mb-3 flex items-start justify-between gap-3"><div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500">Input</p><h3 id="jwt-token-heading" className="mt-1 text-sm font-semibold text-white">Token</h3></div><span className="font-mono text-[10px] text-slate-500">{inputLength.toLocaleString()} characters</span></div>
          <label htmlFor="jwt-token-input" className="sr-only">Paste JWT token</label><textarea id="jwt-token-input" value={token} onChange={(event) => updateToken(event.target.value)} placeholder="Paste a JWT here..." spellCheck={false} className="min-h-36 w-full resize-y rounded-xl border border-white/10 bg-[#060810] p-3 font-mono text-xs leading-5 text-slate-200 placeholder:text-slate-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 sm:min-h-44" />
          {actionError && <p role="alert" className="mt-2 rounded-lg border border-rose-400/20 bg-rose-400/10 p-2.5 text-xs text-rose-200">{actionError}</p>}
          {!parseResult.ok && token.trim() && <p role="alert" className="mt-2 flex items-start gap-2 rounded-lg border border-rose-400/20 bg-rose-400/10 p-3 text-xs text-rose-200"><AlertTriangle className="mt-0.5 size-4 shrink-0" />{parseResult.error}</p>}
          <div className="mt-3 flex flex-wrap items-center gap-2"><button type="button" onClick={() => { updateToken(''); setSecret(''); setDemoSecretHint(false) }} disabled={!token && !secret} className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-white/10 px-3 text-xs text-slate-300 transition hover:border-white/20 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 disabled:opacity-40"><Clipboard className="size-3.5" />Clear</button><button type="button" onClick={() => void loadSample()} disabled={sampleLoading} className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-cyan-400/10 px-3 text-xs font-semibold text-cyan-200 transition hover:bg-cyan-400 hover:text-slate-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 disabled:opacity-50">{sampleLoading && <LoaderCircle className="size-3.5 animate-spin motion-reduce:animate-none" />}{sampleLoading ? 'Loading sample' : 'Load sample'}</button></div>
          {analysis && <TokenParts analysis={analysis} />}
        </section>

        {analysis && <details className="group rounded-2xl border border-white/[0.08] bg-[#0d121c] p-4 sm:p-5">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"><span><span className="block font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500">Optional check</span><span className="mt-1 block text-sm font-semibold text-white">Verify signature</span></span><span className={`rounded-full border px-2.5 py-1 font-mono text-[10px] ${verificationTone}`}>{verificationLabel}</span></summary>
          <div className="mt-4 border-t border-white/[0.07] pt-4"><p className="mb-3 text-xs leading-5 text-slate-400">{isHmac ? 'Check an HMAC signature locally using a shared secret.' : 'Verification needs a public key for this algorithm and is not supported here.'}</p><label htmlFor="jwt-hmac-secret" className="mb-1.5 block text-xs font-medium text-slate-300">Shared secret</label><input id="jwt-hmac-secret" type="password" autoComplete="off" value={secret} onChange={(event) => { setSecret(event.target.value); setVerification({ status: 'unchecked', explanation: 'Signature has not been checked.' }) }} placeholder="Enter the HMAC secret" className="min-h-11 w-full rounded-xl border border-white/10 bg-[#060810] px-3 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400" />
            <p className="mt-2 text-[11px] leading-5 text-slate-500">{demoSecretHint ? <>Sample secret: <code className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-cyan-200">demo-secret</code></> : 'The secret remains only in this panel’s memory.'}</p>
            <div className="mt-3 flex flex-wrap items-center gap-3"><button type="button" onClick={() => void runVerification()} disabled={verifying || !isHmac} className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-emerald-400/10 px-4 text-xs font-semibold text-emerald-200 transition hover:bg-emerald-400 hover:text-slate-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 disabled:cursor-not-allowed disabled:opacity-45">{verifying && <LoaderCircle className="size-3.5 animate-spin motion-reduce:animate-none" />}{verifying ? 'Verifying' : 'Verify signature'}</button><span className={`inline-flex min-h-8 items-center gap-1.5 rounded-full border px-2.5 text-[10px] ${verificationTone}`}>{verification.status === 'valid' ? <ShieldCheck className="size-3.5" /> : verification.status === 'invalid' ? <ShieldAlert className="size-3.5" /> : verification.status === 'unsupported' ? <Info className="size-3.5" /> : <KeyRound className="size-3.5" />}{verificationLabel}</span></div>
            <p role="status" className="mt-2 text-xs leading-5 text-slate-400">{visibleVerificationExplanation}</p>
          </div>
        </details>}
        </div>
      </div>

      <div className="space-y-5">
        {!token.trim() ? <section className="rounded-2xl border border-dashed border-white/15 bg-[#0d121c]/70 p-6 sm:p-8"><div className="flex size-11 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/20"><KeyRound className="size-5" /></div><h3 className="mt-4 text-sm font-semibold text-white">Inspect a JSON Web Token</h3><p className="mt-2 text-xs leading-6 text-slate-400">A JWT has three dot-separated parts: a Base64URL header, a Base64URL payload, and a signature. The first two parts are readable data, not encryption. Load the harmless signed sample to explore the analyzer.</p></section>
          : !analysis ? null : <>
            <section className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-4 sm:p-5" aria-labelledby="jwt-decoded-heading"><div className="mb-4"><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-400">Decoded Locally</p><h3 id="jwt-decoded-heading" className="mt-1 text-sm font-semibold text-white">Decoded</h3></div><div className="space-y-4">
              <section><div className="mb-2 flex items-center justify-between gap-2"><h4 className="text-xs font-semibold text-slate-200">Header</h4><CopyJsonButton value={analysis.header} label="header" copied={copied} onCopy={(value, key) => void copyText(value, key)} /></div><ColoredJson value={analysis.header} /></section>
              <section><div className="mb-2 flex items-center justify-between gap-2"><h4 className="text-xs font-semibold text-slate-200">Payload</h4><CopyJsonButton value={analysis.payload} label="payload" copied={copied} onCopy={(value, key) => void copyText(value, key)} /></div><ColoredJson value={analysis.payload} /></section>
            </div><ClaimsTable analysis={analysis} now={now} /></section>
            <section className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-4 sm:p-5" aria-labelledby="jwt-analysis-heading"><div className="mb-4 flex items-start justify-between gap-3"><div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-emerald-400">Defensive Review</p><h3 id="jwt-analysis-heading" className="mt-1 text-sm font-semibold text-white">Analysis</h3></div><span className="rounded-full border border-white/10 bg-white/[0.03] px-2.5 py-1 font-mono text-[10px] text-slate-400">{analysis.findings.length} findings</span></div>{analysis.findings.length === 0 && <p className="mb-4 rounded-xl border border-emerald-400/20 bg-emerald-400/[0.06] p-3 text-xs leading-5 text-emerald-200">No issues found by these checks. This is not a security guarantee.</p>}<div className="space-y-3">{findingsBySeverity.map(({ severity, items }) => <FindingGroup key={severity} severity={severity} findings={items} />)}</div><p className="mt-3 text-[10px] leading-5 text-slate-500">These rule-based checks are educational signals. Validate issuer, audience, expiry, algorithm, and key policy in the application that accepts the token.</p></section>
          </>}
      </div>
    </div>
    <div aria-live="polite" className="sr-only">{parseResult.ok && token.trim() ? 'Token decoded' : token.trim() && !parseResult.ok ? parseResult.error : ''}</div>
  </section>
}
