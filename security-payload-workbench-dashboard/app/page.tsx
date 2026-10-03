'use client'

import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  Check,
  Clipboard,
  Eraser,
  Fingerprint,
  Hash,
  Info,
  Link2,
  Loader2,
  LockKeyhole,
  Moon,
  ShieldCheck,
  Sun,
} from 'lucide-react'
import { callBackend, type BackendResponse, type HashAlgorithm } from '@/lib/api'

export type Operation =
  | 'base64-encode'
  | 'base64-decode'
  | 'url-encode'
  | 'url-decode'
  | 'hex-encode'
  | 'hex-decode'
  | 'hash'
  | 'identify-hash'

const operations: { id: Operation; label: string; icon: typeof LockKeyhole }[] = [
  { id: 'base64-encode', label: 'Base64 Encode', icon: LockKeyhole },
  { id: 'base64-decode', label: 'Base64 Decode', icon: LockKeyhole },
  { id: 'url-encode', label: 'URL Encode', icon: Link2 },
  { id: 'url-decode', label: 'URL Decode', icon: Link2 },
  { id: 'hex-encode', label: 'Hex Encode', icon: Hash },
  { id: 'hex-decode', label: 'Hex Decode', icon: Hash },
  { id: 'hash', label: 'Hash Converter', icon: Hash },
  { id: 'identify-hash', label: 'Identify Hash', icon: Fingerprint },
]

const HASH_EXAMPLES = [
  { label: 'MD5 (32 hex)', value: '5d41402abc4b2a76b9719d911017c592' },
  { label: 'SHA-256 (64 hex)', value: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' },
  { label: 'bcrypt ($2a$)', value: '$2a$12$e8KERg7gm.bQ1qV8q6uP5.9M5M.x2Y7Wv0.qP4P.r8X1V3Z2Y7Wv0' },
  { label: 'Argon2id', value: '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPuxWCsUzbsRUhq' },
  { label: 'NTLM (32 hex)', value: 'cc325255476a26998656a840e69818ae' },
  { label: 'SHA-1 (40 hex)', value: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d' },
]

export default function Page() {
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [operation, setOperation] = useState<Operation>('base64-encode')
  const [selectedHash, setSelectedHash] = useState<HashAlgorithm>('SHA-256')
  const [analysisData, setAnalysisData] = useState<BackendResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const [darkMode, setDarkMode] = useState(true)

  async function executeOperation(textToProcess: string, op: Operation, hashAlgo: HashAlgorithm | null) {
    if (!textToProcess) {
      setOutput('')
      setError('')
      setAnalysisData(null)
      setLoading(false)
      return
    }

    const opMap: Record<Operation, string> = {
      'base64-encode': 'base64_encode',
      'base64-decode': 'base64_decode',
      'url-encode': 'url_encode',
      'url-decode': 'url_decode',
      'hex-encode': 'hex_encode',
      'hex-decode': 'hex_decode',
      hash: 'hash',
      'identify-hash': 'identify_hash',
    }

    setLoading(true)
    setError('')
    try {
      const response = await callBackend(opMap[op], textToProcess, op === 'hash' ? hashAlgo : null)
      if (response.success) {
        setOutput(response.result)
        if (op === 'identify-hash') {
          setAnalysisData(response)
        } else {
          setAnalysisData(null)
        }
      } else {
        setOutput('')
        setAnalysisData(null)
        setError(response.error ?? 'The operation failed.')
      }
    } catch (e) {
      setOutput('')
      setAnalysisData(null)
      setError(e instanceof Error ? e.message : 'The operation failed.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let active = true
    setOutput('')
    setError('')
    setAnalysisData(null)

    if (!input) {
      setLoading(false)
      return
    }

    setLoading(true)
    const handler = setTimeout(async () => {
      if (!active) return
      await executeOperation(input, operation, selectedHash)
    }, 300)

    return () => {
      active = false
      clearTimeout(handler)
    }
  }, [input, operation, selectedHash])

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
    setInput('')
    setOutput('')
    setError('')
    setAnalysisData(null)
    setCopied(false)
  }

  function loadExample(val: string) {
    setInput(val)
    setOperation('identify-hash')
  }

  useEffect(() => {
    const requestedOperation = new URLSearchParams(window.location.search).get('operation')
    if (requestedOperation && operations.some(({ id }) => id === requestedOperation)) {
      setOperation(requestedOperation as Operation)
    }
  }, [])

  return (
    <main className={darkMode ? 'dark' : 'light'}>
      <div className="workbench-shell">
        <header className="workbench-header">
          <div>
            <div className="eyebrow">
              <ShieldCheck /> Security tooling
            </div>
            <h1>
              Security <span>Workbench</span>
            </h1>
            <p>
              A focused workspace for encoding, decoding, hashing (Hash Converter), identifying hash algorithms, and inspecting payloads
              through the Flask API.
            </p>
          </div>
          <div className="header-tools">
            <div className="processing-pill">
              <span /> Flask API processing
            </div>
            <button
              type="button"
              className="theme-toggle"
              onClick={() => setDarkMode((value) => !value)}
              aria-label={`Switch to ${darkMode ? 'light' : 'dark'} mode`}
            >
              {darkMode ? <Sun /> : <Moon />}
              <span>{darkMode ? 'Light' : 'Dark'}</span>
            </button>
          </div>
        </header>

        <section className="workspace" aria-label="Security operations workspace">
          {/* Input Buffer */}
          <BufferCard title="Input Buffer" icon="01">
            <textarea
              id="input-buffer"
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder={
                operation === 'identify-hash'
                  ? 'Paste raw hash string (e.g., 5d41402abc4b2a76b9719d911017c592 or $2a$12$...)'
                  : 'Paste text or encoded data here...'
              }
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
                  onClick={() => setOperation(id)}
                  className={`operation-button ${
                    operation === id ? 'operation-button-active' : ''
                  }`}
                >
                  <Icon />
                  <span>{label}</span>
                </button>
              ))}
            </div>

            {/* Hash Converter Algorithm Selector - Always accessible */}
            <label className="section-label hash-label" htmlFor="hash-algorithm">
              Hash algorithm (Converter)
            </label>
            <div
              className={`hash-tile transition ${operation === 'hash' ? 'operation-button-active' : ''}`}
              onClick={() => setOperation('hash')}
            >
              <Hash />
              <select
                id="hash-algorithm"
                value={selectedHash}
                onChange={(event) => {
                  setSelectedHash(event.target.value as HashAlgorithm)
                  setOperation('hash')
                }}
                className="hash-select"
                aria-label="Hash algorithm selection"
              >
                <option value="MD5">MD5</option>
                <option value="SHA-256">SHA-256</option>
                <option value="SHA-512">SHA-512</option>
              </select>
            </div>

            {/* Identify Hash Specific Controls */}
            {operation === 'identify-hash' && (
              <div className="mt-4 flex flex-col gap-2.5">
                <button
                  type="button"
                  className="hash-identify-btn"
                  onClick={() => executeOperation(input, 'identify-hash', null)}
                  disabled={!input || loading}
                  aria-label="Analyze and identify hash candidates"
                >
                  {loading ? <Loader2 className="size-4 animate-spin" /> : <Fingerprint className="size-4" />}
                  <span>{loading ? 'Analyzing format...' : 'Identify Hash'}</span>
                </button>

                <div className="mt-2">
                  <span className="section-label block">Load sample hash:</span>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {HASH_EXAMPLES.map((ex) => (
                      <button
                        key={ex.label}
                        type="button"
                        onClick={() => loadExample(ex.value)}
                        className="example-pill"
                        title={`Load example ${ex.label}`}
                      >
                        {ex.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Output Buffer / Hash Identification View */}
          <BufferCard
            title={operation === 'identify-hash' ? 'Hash Candidates' : 'Output Buffer'}
            icon="02"
            status={loading ? 'Processing' : error ? 'Error' : output ? 'Ready' : 'Waiting'}
          >
            {operation === 'identify-hash' && analysisData ? (
              <div className="hash-results-pane" tabIndex={0} aria-label="Hash identification results">
                {/* Meta Header */}
                <div className="flex flex-wrap items-center gap-2 border-b border-slate-700/50 pb-2 text-[11px]">
                  <span className="rounded bg-cyan-500/10 px-2 py-0.5 font-semibold text-cyan-600 dark:text-cyan-300">
                    Length: {analysisData.input_length} chars
                  </span>
                  <span className="rounded bg-slate-500/10 px-2 py-0.5 text-slate-600 dark:text-slate-300">
                    Format: {analysisData.character_format}
                  </span>
                  <span
                    className={`rounded px-2 py-0.5 font-semibold ${
                      analysisData.candidates && analysisData.candidates.length > 0
                        ? analysisData.is_ambiguous
                          ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300'
                          : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                        : 'bg-slate-500/15 text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    {analysisData.candidates && analysisData.candidates.length > 0
                      ? analysisData.is_ambiguous
                        ? 'Ambiguous Candidates'
                        : 'Matching Format'
                      : 'Unknown Format'}
                  </span>
                </div>

                {/* Ambiguity Warning */}
                {analysisData.warning && (
                  <div className="warning-banner" role="alert">
                    <AlertTriangle className="size-4 shrink-0 mt-0.5 text-amber-500" />
                    <div>
                      <strong className="block font-semibold">Heuristic Analysis Notice</strong>
                      <span>{analysisData.warning}</span>
                    </div>
                  </div>
                )}

                {/* Candidate Cards */}
                {analysisData.candidates && analysisData.candidates.length > 0 ? (
                  <div className="flex flex-col gap-2.5">
                    <div className="text-[10px] uppercase tracking-wider text-slate-400">
                      Plausible Candidates ({analysisData.candidates.length}):
                    </div>
                    {analysisData.candidates.map((cand, idx) => (
                      <div key={`${cand.algorithm}-${idx}`} className="candidate-card">
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-cyan-600 dark:text-cyan-300">{cand.algorithm}</span>
                            {cand.hashcat_mode && (
                              <span className="rounded bg-slate-500/20 px-1.5 py-0.5 text-[9px] text-slate-400">
                                Hashcat: -m {cand.hashcat_mode}
                              </span>
                            )}
                          </div>
                          <span className="rounded bg-cyan-500/10 px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-cyan-700 dark:text-cyan-300">
                            {cand.evidence.replace(/_/g, ' ')}
                          </span>
                        </div>
                        <p className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">
                          {cand.explanation}
                        </p>
                      </div>
                    ))}

                    {analysisData.recommendation && (
                      <div className="info-banner">
                        <Info className="size-4 shrink-0 mt-0.5 text-cyan-500" />
                        <div>
                          <strong className="block font-semibold">Recommendation</strong>
                          <span>{analysisData.recommendation}</span>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center gap-2 py-8 text-center text-slate-400">
                    <Info className="size-6 text-slate-500" />
                    <p className="font-semibold text-slate-300">Unknown Hash Format</p>
                    <p className="max-w-xs text-[11px] text-slate-500">
                      Check input length and character set. Ensure standard hex or modular crypt format.
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <textarea
                id="output-buffer"
                value={output}
                readOnly
                placeholder={
                  operation === 'identify-hash'
                    ? 'Enter a hash in the input buffer or choose an example to analyze its plausible algorithms...'
                    : 'Your result will appear here...'
                }
                className={`buffer-textarea output-textarea ${error ? 'buffer-error' : ''}`}
                spellCheck={false}
                aria-label="Output buffer"
                aria-describedby={error ? 'decode-error' : undefined}
              />
            )}

            <div className="buffer-meta">
              <span id="decode-error" role="alert" className={error ? 'error-text' : ''}>
                {error ||
                  (operation === 'identify-hash' && analysisData?.candidates
                    ? `${analysisData.candidates.length} candidate(s) found`
                    : `${output.length} characters`)}
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
