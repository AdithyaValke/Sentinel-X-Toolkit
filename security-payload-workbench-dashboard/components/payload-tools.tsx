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
import { useApiStatus } from '@/components/app-shell'
import { recordActivity } from '@/lib/activity'

const operations: { id: PayloadOperation; label: string; description: string; icon: typeof LockKeyhole }[] = [
  { id: 'base64-encode', label: 'Base64 Encode', description: 'Convert to Base64 format', icon: LockKeyhole },
  { id: 'base64-decode', label: 'Base64 Decode', description: 'Decode from Base64 format', icon: LockKeyhole },
  { id: 'url-encode', label: 'URL Encode', description: 'Encode for URL usage', icon: Link2 },
  { id: 'url-decode', label: 'URL Decode', description: 'Decode from URL format', icon: Link2 },
  { id: 'hex-encode', label: 'Hex Encode', description: 'Convert to Hex format', icon: Hash },
  { id: 'hex-decode', label: 'Hex Decode', description: 'Decode from Hex format', icon: Hash },
]

export function PayloadTools() {
  const apiStatus = useApiStatus()
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
        recordActivity('Payload Tools', op.replace('-', ' '), 'success', 'Payload transformation completed')
      } else {
        setOutput('')
        setError(response.error ?? 'The operation failed.')
        recordActivity('Payload Tools', op.replace('-', ' '), 'failure', 'Payload transformation failed')
      }
    } catch (e) {
      if (!latestRequest.current.isCurrent(request.id)) return
      setOutput('')
      setError(e instanceof Error ? e.message : 'The operation failed.')
      recordActivity('Payload Tools', op.replace('-', ' '), 'failure', 'Payload transformation failed')
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
      <div className="workbench-shell payload-tools-shell">
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
            <div className={`api-status-pill api-status-${apiStatus}`} role="status" aria-live="polite">
              <span aria-hidden="true" />
              {apiStatus === 'checking' ? 'Checking API' : apiStatus === 'online' ? 'API Online' : 'API Offline'}
            </div>
          </div>
        </header>

        <div className="payload-workspace-panel">
          <section className="workspace payload-workspace" aria-label="Security operations workspace">
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
              <BufferMeta count={input.length} onClear={clearAll} />
            </BufferCard>

            {/* Operations Controls */}
            <div className="operations" aria-label="Operations">
              <div className="section-label">Operations</div>
              <div className="operation-grid">
                {operations.map(({ id, label, description, icon: Icon }) => (
                  <button
                    key={id}
                    type="button"
                    aria-pressed={operation === id}
                    aria-label={`${label}: ${description}`}
                    onClick={() => { latestRequest.current.cancel(); setOutput(''); setError(''); setLoading(false); setOperation(id) }}
                    className={`operation-button ${
                      operation === id ? 'operation-button-active' : ''
                    }`}
                  >
                    <span className="operation-icon"><Icon aria-hidden="true" /></span>
                    <span className="operation-copy">
                      <strong>{label}</strong>
                      <small>{description}</small>
                    </span>
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

              {error && <p id="decode-error" role="alert" className="buffer-error-message">{error}</p>}
              <BufferMeta count={output.length} />
            </BufferCard>
          </section>

        {/* Footer */}
          <footer className="workbench-footer">
            <span className="payload-security-note">
              <ShieldCheck aria-hidden="true" /> Developed with modern web security best practices
            </span>
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
        <small aria-live="polite">{status}</small>
      </div>
      {children}
    </article>
  )
}

function BufferMeta({ count, onClear }: { count: number; onClear?: () => void }) {
  return (
    <div className="buffer-meta">
      <span>{count} characters</span>
      <span className="buffer-meta-actions">
        {onClear && <button type="button" onClick={onClear} disabled={count === 0} aria-label="Clear input buffer">Clear</button>}
        <span>UTF-8</span>
      </span>
    </div>
  )
}
