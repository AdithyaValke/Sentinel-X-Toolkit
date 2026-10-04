'use client'

import { useEffect, useRef, useState } from 'react'
import {
  Check,
  Clipboard,
  Eraser,
  Hash,
  Link2,
  LockKeyhole,
  ShieldCheck,
} from 'lucide-react'
import { callBackend } from '@/lib/api'
import { LatestRequest } from '@/lib/latest-request'
import { PAYLOAD_OPERATION_MAP, type PayloadOperation } from '@/lib/payload-operations'

const operations: { id: PayloadOperation; label: string; icon: typeof LockKeyhole }[] = [
  { id: 'base64-encode', label: 'Base64 Encode', icon: LockKeyhole },
  { id: 'base64-decode', label: 'Base64 Decode', icon: LockKeyhole },
  { id: 'url-encode', label: 'URL Encode', icon: Link2 },
  { id: 'url-decode', label: 'URL Decode', icon: Link2 },
  { id: 'hex-encode', label: 'Hex Encode', icon: Hash },
  { id: 'hex-decode', label: 'Hex Decode', icon: Hash },
]

export function PayloadTools() {
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [operation, setOperation] = useState<PayloadOperation>('base64-encode')
  const [copied, setCopied] = useState(false)
  const latestRequest = useRef(new LatestRequest())

  async function executeOperation(textToProcess: string, op: PayloadOperation) {
    if (!textToProcess) {
      setOutput('')
      setError('')
      setLoading(false)
      return
    }

    const request = latestRequest.current.begin()
    setLoading(true)
    setError('')
    try {
      const response = await callBackend(PAYLOAD_OPERATION_MAP[op], textToProcess, null, request.signal)
      if (!latestRequest.current.isCurrent(request.id)) return
      if (response.success) {
        setOutput(response.result)
      } else {
        setOutput('')
        setError(response.error ?? 'The operation failed.')
      }
    } catch (e) {
      if (!latestRequest.current.isCurrent(request.id)) return
      setOutput('')
      setError(e instanceof Error ? e.message : 'The operation failed.')
    } finally {
      if (latestRequest.current.isCurrent(request.id)) setLoading(false)
    }
  }

  useEffect(() => {
    let active = true
    setOutput('')
    setError('')
    if (!input) {
      setLoading(false)
      return
    }

    setLoading(true)
    const handler = setTimeout(async () => {
      if (!active) return
      await executeOperation(input, operation)
    }, 300)

    return () => {
      active = false
      clearTimeout(handler)
      latestRequest.current.cancel()
    }
  }, [input, operation])

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

  useEffect(() => {
    const requestedOperation = new URLSearchParams(window.location.search).get('operation')
    if (operations.some(({ id }) => id === requestedOperation)) {
      setOperation(requestedOperation as PayloadOperation)
    }
  }, [])

  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="workbench-shell">
        <header className="workbench-header">
          <div>
            <div className="eyebrow">
              <ShieldCheck /> Security tooling
            </div>
            <h1>
              Payload <span>Tools</span>
            </h1>
            <p>
              Encode and decode Base64, URL, and Hex data using the existing Flask API.
            </p>
          </div>
          <div className="header-tools">
            <div className="processing-pill">
              <span /> Flask API operations
            </div>
          </div>
        </header>

        <section className="workspace" aria-label="Security operations workspace">
          {/* Input Buffer */}
          <BufferCard title="Input Buffer" icon="01">
            <textarea
              id="input-buffer"
              value={input}
              onChange={(event) => { latestRequest.current.cancel(); setOutput(''); setError(''); setLoading(false); setInput(event.target.value) }}
              placeholder="Paste text or encoded data here..."
              className="buffer-textarea"
              spellCheck={false}
              aria-label="Input buffer"
            />
            <BufferMeta count={input.length} />
          </BufferCard>

          {/* Operations Controls */}
          <div className="operations" aria-label="Operations">
            <div className="section-label">Operations</div>
            <div className="operation-grid">
              {operations.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  type="button"
                  aria-pressed={operation === id}
                  onClick={() => { latestRequest.current.cancel(); setOutput(''); setError(''); setLoading(false); setOperation(id) }}
                  className={`operation-button ${
                    operation === id ? 'operation-button-active' : ''
                  }`}
                >
                  <Icon />
                  <span>{label}</span>
                </button>
              ))}
            </div>

          </div>

          {/* Output Buffer */}
          <BufferCard
            title="Output Buffer"
            icon="02"
            status={loading ? 'Processing' : error ? 'Error' : output ? 'Ready' : 'Waiting'}
          >
            <textarea
              id="output-buffer"
              value={output}
              readOnly
              placeholder="Your result will appear here..."
              className={`buffer-textarea output-textarea ${error ? 'buffer-error' : ''}`}
              spellCheck={false}
              aria-label="Output buffer"
              aria-describedby={error ? 'decode-error' : undefined}
            />

            <div className="buffer-meta">
              <span id="decode-error" role="alert" className={error ? 'error-text' : ''}>
                {error || `${output.length} characters`}
              </span>
              <span>UTF-8</span>
            </div>
          </BufferCard>
        </section>

        {/* Footer */}
        <footer className="workbench-footer">
          <span>Developed with modern web security best practices</span>
          <div>
            <button type="button" onClick={clearAll} className="footer-action">
              <Eraser /> Clear
            </button>
            <button type="button" onClick={copyResult} className="footer-action" disabled={!output}>
              {copied ? <Check /> : <Clipboard />} {copied ? 'Copied' : 'Copy result'}
            </button>
            <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noreferrer">
              OWASP resources ↗
            </a>
          </div>
        </footer>
      </div>
    </main>
  )
}

function BufferCard({
  title,
  icon,
  status = 'Live',
  children,
}: {
  title: string
  icon: string
  status?: string
  children: React.ReactNode
}) {
  return (
    <article className="buffer-card">
      <div className="buffer-heading">
        <h2>
          <span>{icon}</span>
          {title}
        </h2>
        <small>{status}</small>
      </div>
      {children}
    </article>
  )
}

function BufferMeta({ count }: { count: number }) {
  return (
    <div className="buffer-meta">
      <span>{count} characters</span>
      <span>UTF-8</span>
    </div>
  )
}
