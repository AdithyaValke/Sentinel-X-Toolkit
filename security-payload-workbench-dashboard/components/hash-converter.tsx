'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { Check, Clipboard, Eraser, Hash, Loader2, ShieldCheck } from 'lucide-react'
import { callBackend, type HashAlgorithm } from '@/lib/api'
import { LatestRequest } from '@/lib/latest-request'

export function HashConverter() {
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [selectedHash, setSelectedHash] = useState<HashAlgorithm>('SHA-256')
  const [copied, setCopied] = useState(false)
  const latestRequest = useRef(new LatestRequest())

  function updateInput(value: string) {
    latestRequest.current.cancel()
    setInput(value)
    setOutput('')
    setError('')
    setLoading(false)
  }

  function updateAlgorithm(value: HashAlgorithm) {
    latestRequest.current.cancel()
    setSelectedHash(value)
    setOutput('')
    setError('')
    setLoading(false)
  }

  useEffect(() => {
    if (!input) {
      latestRequest.current.cancel()
      setOutput('')
      setError('')
      setLoading(false)
      return
    }

    setLoading(true)
    const handler = window.setTimeout(async () => {
      const request = latestRequest.current.begin()
      setError('')
      try {
        const response = await callBackend('hash', input, selectedHash, request.signal)
        if (!latestRequest.current.isCurrent(request.id)) return
        if (response.success) {
          setOutput(response.result)
        } else {
          setOutput('')
          setError(response.error ?? 'The operation failed.')
        }
      } catch (requestError) {
        if (!latestRequest.current.isCurrent(request.id)) return
        setOutput('')
        setError(requestError instanceof Error ? requestError.message : 'The operation failed.')
      } finally {
        if (latestRequest.current.isCurrent(request.id)) setLoading(false)
      }
    }, 300)

    return () => { window.clearTimeout(handler); latestRequest.current.cancel() }
  }, [input, selectedHash])

  async function copyResult() {
    if (!output) return
    try {
      await navigator.clipboard.writeText(output)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      setError('Clipboard access failed. Select and copy the output manually.')
    }
  }

  function clearAll() {
    latestRequest.current.cancel()
    setInput('')
    setOutput('')
    setError('')
    setCopied(false)
    setLoading(false)
  }

  return (
    <main className="min-h-screen bg-[#080b12] text-slate-100">
      <div className="workbench-shell">
        <header className="workbench-header">
          <div>
            <div className="eyebrow"><ShieldCheck /> Security tooling</div>
            <h1>Hash <span>Converter</span></h1>
            <p>Generate secure hashes from raw text with the algorithm of your choice through the existing Flask API.</p>
          </div>
          <Link href="/dashboard" className="theme-toggle">Back to dashboard</Link>
        </header>

        <section className="workspace" aria-label="Hash converter workspace">
          <article className="buffer-card">
            <div className="buffer-heading"><h2><span>01</span>Input Buffer</h2><small>Live</small></div>
            <textarea id="hash-input" value={input} onChange={(event) => updateInput(event.target.value)} placeholder="Paste text to hash here..." className="buffer-textarea" spellCheck={false} aria-label="Hash input buffer" />
            <div className="buffer-meta"><span>{input.length} characters</span><span>UTF-8</span></div>
          </article>

          <div className="operations" aria-label="Hash converter controls">
            <div className="section-label">Hash algorithm</div>
            <label className="hash-tile operation-button-active" htmlFor="hash-algorithm"><Hash /><select id="hash-algorithm" value={selectedHash} onChange={(event) => updateAlgorithm(event.target.value as HashAlgorithm)} className="hash-select" aria-label="Hash algorithm selection"><option value="MD5">MD5</option><option value="SHA-256">SHA-256</option><option value="SHA-512">SHA-512</option></select></label>
          </div>

          <article className="buffer-card">
            <div className="buffer-heading"><h2><span>02</span>Output Buffer</h2><small>{loading ? 'Processing' : error ? 'Error' : output ? 'Ready' : 'Waiting'}</small></div>
            <textarea id="hash-output" value={output} readOnly placeholder="Your hash will appear here..." className={`buffer-textarea output-textarea ${error ? 'buffer-error' : ''}`} spellCheck={false} aria-label="Hash output buffer" aria-describedby={error ? 'hash-error' : undefined} />
            <div className="buffer-meta"><span id="hash-error" role="alert" className={error ? 'error-text' : ''}>{error || `${output.length} characters`}</span><span>UTF-8</span></div>
          </article>
        </section>

        <footer className="workbench-footer"><span>Developed with modern web security best practices</span><div><button type="button" onClick={clearAll} className="footer-action"><Eraser /> Clear</button><button type="button" onClick={copyResult} className="footer-action" disabled={!output}>{copied ? <Check /> : <Clipboard />} {copied ? 'Copied' : 'Copy result'}</button></div></footer>
      </div>
    </main>
  )
}
