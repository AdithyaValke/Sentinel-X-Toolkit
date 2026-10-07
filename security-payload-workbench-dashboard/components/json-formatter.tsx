'use client'

import { useState } from 'react'
import { Check, Clipboard, Eraser, FileJson, ShieldCheck, WandSparkles } from 'lucide-react'

type Indentation = '2' | '4' | 'tab'

const placeholder = '{\n  "name": "SentinelX",\n  "enabled": true\n}'

export function JsonFormatter() {
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [error, setError] = useState('')
  const [indentation, setIndentation] = useState<Indentation>('2')
  const [copied, setCopied] = useState(false)

  function parseJson() {
    if (!input.trim()) {
      setOutput('')
      setError('Enter JSON to validate and format.')
      setCopied(false)
      return null
    }
    try {
      const value = JSON.parse(input) as unknown
      const indent = indentation === 'tab' ? '\t' : Number(indentation)
      const formatted = JSON.stringify(value, null, indent)
      setOutput(formatted)
      setError('')
      setCopied(false)
      return formatted
    } catch (caught) {
      setOutput('')
      setError(caught instanceof Error ? caught.message : 'The JSON could not be parsed.')
      setCopied(false)
      return null
    }
  }

  function minifyJson() {
    const formatted = parseJson()
    if (formatted === null) return
    try {
      setOutput(JSON.stringify(JSON.parse(input) as unknown))
    } catch {
      // parseJson already reports the native parser error.
    }
  }

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
    setCopied(false)
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="workbench-shell payload-tools-shell">
        <header className="workbench-header">
          <div>
            <div className="eyebrow"><ShieldCheck /> Security tooling</div>
            <h1>JSON <span>Formatter</span></h1>
            <p>Validate, format, and minify JSON locally in your browser. Nothing is sent to the backend.</p>
          </div>
          <div className="header-tools"><span className="api-status-pill api-status-online"><span aria-hidden="true" />Client-side only</span></div>
        </header>

        <div className="payload-workspace-panel">
          <section className="json-formatter-workspace" aria-label="JSON formatter workspace">
            <article className="buffer-card">
              <div className="buffer-heading"><h2><span>01</span>Input JSON</h2><small>{input.length} characters</small></div>
              <textarea value={input} onChange={(event) => { setInput(event.target.value); setOutput(''); setError(''); setCopied(false) }} placeholder={placeholder} className="buffer-textarea json-editor" spellCheck={false} aria-label="JSON input" />
              <div className="buffer-meta"><span>Plain text only</span><button type="button" onClick={clearAll} disabled={!input && !output} aria-label="Clear JSON input">Clear</button></div>
            </article>

            <article className="buffer-card">
              <div className="buffer-heading"><h2><span>02</span>Result</h2><small aria-live="polite">{error ? 'Invalid JSON' : output ? 'Valid JSON' : 'Waiting'}</small></div>
              <pre className={`json-output ${error ? 'buffer-error' : ''}`} aria-label="JSON result" aria-live="polite">{output || 'Formatted output will appear here...'}</pre>
              {error && <p role="alert" className="buffer-error-message">{error}</p>}
              <div className="buffer-meta"><span>{output.length} characters</span><span>Safe text output</span></div>
            </article>
          </section>

          <div className="json-formatter-controls" aria-label="JSON actions">
            <label htmlFor="json-indent">Indentation</label>
            <select id="json-indent" value={indentation} onChange={(event) => setIndentation(event.target.value as Indentation)}>
              <option value="2">2 spaces</option><option value="4">4 spaces</option><option value="tab">Tabs</option>
            </select>
            <button type="button" className="footer-action" onClick={parseJson}><WandSparkles aria-hidden="true" /> Format / Validate</button>
            <button type="button" className="footer-action" onClick={minifyJson}><FileJson aria-hidden="true" /> Minify</button>
            <button type="button" className="footer-action" onClick={copyResult} disabled={!output}>{copied ? <Check aria-hidden="true" /> : <Clipboard aria-hidden="true" />} {copied ? 'Copied' : 'Copy result'}</button>
            <button type="button" className="footer-action" onClick={clearAll} disabled={!input && !output}><Eraser aria-hidden="true" /> Clear</button>
          </div>
        </div>
      </div>
    </main>
  )
}

export function formatJson(input: string, indentation: Indentation = '2') {
  if (!input.trim()) return { output: '', error: 'Enter JSON to validate and format.' }
  try {
    const value = JSON.parse(input) as unknown
    return { output: JSON.stringify(value, null, indentation === 'tab' ? '\t' : Number(indentation)), error: '' }
  } catch (caught) {
    return { output: '', error: caught instanceof Error ? caught.message : 'The JSON could not be parsed.' }
  }
}

export function minifyJson(input: string) {
  try {
    return { output: JSON.stringify(JSON.parse(input) as unknown), error: '' }
  } catch (caught) {
    return { output: '', error: caught instanceof Error ? caught.message : 'The JSON could not be parsed.' }
  }
}

export type { Indentation }
