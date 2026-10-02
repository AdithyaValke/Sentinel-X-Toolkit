'use client'

import { useEffect, useState } from 'react'
import { Check, Clipboard, Eraser, Hash, Link2, LockKeyhole, Moon, ShieldCheck, Sun } from 'lucide-react'
import { callBackend } from '@/lib/api'

export type Operation = 'base64-encode' | 'base64-decode' | 'url-encode' | 'url-decode' | 'hex-encode' | 'hex-decode' | 'hash'
export type HashAlgorithm = 'MD5' | 'SHA-256' | 'SHA-512'

const operations: { id: Operation; label: string; icon: typeof LockKeyhole }[] = [
  { id: 'base64-encode', label: 'Base64 Encode', icon: LockKeyhole },
  { id: 'base64-decode', label: 'Base64 Decode', icon: LockKeyhole },
  { id: 'url-encode', label: 'URL Encode', icon: Link2 },
  { id: 'url-decode', label: 'URL Decode', icon: Link2 },
  { id: 'hex-encode', label: 'Hex Encode', icon: Hash },
  { id: 'hex-decode', label: 'Hex Decode', icon: Hash },
]
// The previous custom handleOperation logic has been replaced with the centralized API client.



export default function Page() {
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [error, setError] = useState('')
  const [operation, setOperation] = useState<Operation>('base64-encode')
  const [selectedHash, setSelectedHash] = useState<HashAlgorithm>('SHA-256')
  const [copied, setCopied] = useState(false)
  const [darkMode, setDarkMode] = useState(true)

  useEffect(() => {
    let active = true
    async function run() {
      if (!input) {
        if (active) {
          setOutput('')
          setError('')
        }
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
      }

      const op = opMap[operation]
      const hashAlgo = operation === 'hash' ? selectedHash : null

      try {
        const response = await callBackend(op, input, hashAlgo);
        if (response.success) {
          if (active) setOutput(response.result);
        } else {
          if (active) setError(response.error ?? '');
        }
      } catch (e) {
        if (active) setError(String(e));
      }
    }
    run()
    return () => {
      active = false
    }
  }, [input, operation, selectedHash])
  async function copyResult() { if (!output) return; await navigator.clipboard.writeText(output); setCopied(true); window.setTimeout(() => setCopied(false), 1600) }
  function clearAll() { setInput(''); setOutput(''); setError(''); setCopied(false) }

  return (
    <main className={darkMode ? 'dark' : 'light'}>
      <div className="workbench-shell">
        <header className="workbench-header">
          <div><div className="eyebrow"><ShieldCheck /> Security tooling</div><h1>Security <span>Workbench</span></h1><p>A focused workspace for encoding, decoding, hashing, and inspecting text locally.</p></div>
          <div className="header-tools"><div className="processing-pill"><span /> Local processing</div><button type="button" className="theme-toggle" onClick={() => setDarkMode((value) => !value)} aria-label={`Switch to ${darkMode ? 'light' : 'dark'} mode`}>{darkMode ? <Sun /> : <Moon />}<span>{darkMode ? 'Light' : 'Dark'}</span></button></div>
        </header>
        <section className="workspace" aria-label="Security operations workspace">
          <BufferCard title="Input Buffer" icon="01"><textarea id="input-buffer" value={input} onChange={(event) => setInput(event.target.value)} placeholder="Paste text or encoded data here..." className="buffer-textarea" spellCheck={false} aria-label="Input buffer" /><BufferMeta count={input.length} /></BufferCard>
          <div className="operations" aria-label="Operations"><div className="section-label">Operations</div><div className="operation-grid">{operations.map(({ id, label, icon: Icon }) => <button key={id} type="button" onClick={() => setOperation(id)} className={`operation-button ${operation === id ? 'operation-button-active' : ''}`}><Icon /><span>{label}</span></button>)}</div><label className="section-label hash-label" htmlFor="hash-algorithm">Hash algorithm</label><div className="hash-tile"><Hash /><select id="hash-algorithm" value={selectedHash} onChange={(event) => { setSelectedHash(event.target.value as HashAlgorithm); setOperation('hash') }} className="hash-select"><option>MD5</option><option>SHA-256</option><option>SHA-512</option></select></div></div>
          <BufferCard title="Output Buffer" icon="02"><textarea id="output-buffer" value={output} readOnly placeholder="Your result will appear here..." className={`buffer-textarea output-textarea ${error ? 'buffer-error' : ''}`} spellCheck={false} aria-label="Output buffer" aria-describedby={error ? 'decode-error' : undefined} /><div className="buffer-meta"><span id="decode-error" role="alert" className={error ? 'error-text' : ''}>{error || `${output.length} characters`}</span><span>UTF-8</span></div></BufferCard>
        </section>
        <footer className="workbench-footer"><span>Developed with modern web security best practices</span><div><button type="button" onClick={clearAll} className="footer-action"><Eraser /> Clear</button><button type="button" onClick={copyResult} className="footer-action" disabled={!output}>{copied ? <Check /> : <Clipboard />} {copied ? 'Copied' : 'Copy result'}</button><a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noreferrer">OWASP resources ↗</a></div></footer>
      </div>
    </main>
  )
}

function BufferCard({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) { return <article className="buffer-card"><div className="buffer-heading"><h2><span>{icon}</span>{title}</h2><small>Live</small></div>{children}</article> }
function BufferMeta({ count }: { count: number }) { return <div className="buffer-meta"><span>{count} characters</span><span>UTF-8</span></div> }
