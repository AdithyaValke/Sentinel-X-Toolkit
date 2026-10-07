'use client'

import { useState } from 'react'
import { Check, Clipboard, Eraser, FileJson, ShieldCheck, WandSparkles } from 'lucide-react'

type Indentation = '2' | '4' | 'tab'

const placeholder = '{\n  "name": "SentinelX",\n  "enabled": true\n}'

function lineCount(value: string) {
  return Math.max(1, value.split('\n').length)
}

function LineNumbers({ value }: { value: string }) {
  return <div className="json-line-numbers" aria-hidden="true">{Array.from({ length: lineCount(value) }, (_, index) => <span key={index}>{index + 1}</span>)}</div>
}

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
    try { setOutput(JSON.stringify(JSON.parse(input) as unknown)) } catch { /* parseJson already reports the native parser error. */ }
  }

  async function copyResult() {
    if (!output) return
    try {
      await navigator.clipboard.writeText(output)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    } catch { setError('Clipboard access failed. Select and copy the output manually.') }
  }

  function clearAll() {
    setInput(''); setOutput(''); setError(''); setCopied(false)
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="workbench-shell payload-tools-shell json-formatter-shell">
        <header className="workbench-header json-formatter-header">
          <div>
            <div className="eyebrow"><ShieldCheck /> SECURITY TOOLING</div>
            <h1>JSON <span>Formatter</span></h1>
            <p>Validate, format, and minify JSON locally in your browser. Nothing is sent to the backend.</p>
          </div>
          <div className="header-tools"><span className="api-status-pill api-status-online"><span aria-hidden="true" />Client-side only</span></div>
        </header>

        <section className="json-formatter-workspace" aria-label="JSON formatter workspace">
          <article className="json-editor-panel">
            <div className="json-panel-header">
              <div className="json-panel-title"><span className="json-panel-icon"><FileJson aria-hidden="true" /></span><h2>Input JSON</h2></div>
              <div className="json-panel-stats"><span className={error ? 'json-status invalid' : input.trim() ? 'json-status valid' : 'json-status'}>{error ? 'INVALID JSON' : input.trim() ? 'VALID JSON' : 'READY'}</span><span>{input.length} chars / {lineCount(input)} lines</span></div>
            </div>
            <div className={`json-code-surface ${error ? 'has-error' : ''}`}>
              <LineNumbers value={input || placeholder} />
              <textarea value={input} onChange={(event) => { setInput(event.target.value); setOutput(''); setError(''); setCopied(false) }} placeholder={placeholder} className="json-code-input" spellCheck={false} aria-label="JSON input" />
            </div>
            <div className="json-panel-footer"><span>EDITOR / UTF-8</span><span>SCROLL TO INSPECT</span></div>
          </article>

          <article className="json-editor-panel">
            <div className="json-panel-header">
              <div className="json-panel-title"><span className="json-panel-icon"><WandSparkles aria-hidden="true" /></span><h2>Formatted Output</h2></div>
              <div className="json-panel-stats"><span>{output.length} chars / {lineCount(output)} lines</span></div>
            </div>
            <div className={`json-code-surface output-surface ${error ? 'has-error' : ''}`}>
              <LineNumbers value={output || 'Formatted output will appear here...'} />
              <pre className="json-code-output" aria-label="JSON result" aria-live="polite">{output || 'Formatted output will appear here...'}</pre>
            </div>
            {error && <p role="alert" className="json-error-message">{error}</p>}
            <div className="json-panel-footer"><span className={error ? 'json-status invalid' : output ? 'json-status valid' : 'json-status'}>{error ? 'INVALID JSON' : output ? 'VALID JSON' : 'AWAITING INPUT'}</span><span>PLAIN TEXT ONLY</span></div>
          </article>
        </section>

        <div className="json-formatter-controls" aria-label="JSON actions">
          <label htmlFor="json-indent">Indentation</label>
          <select id="json-indent" value={indentation} onChange={(event) => setIndentation(event.target.value as Indentation)}><option value="2">2 spaces</option><option value="4">4 spaces</option><option value="tab">Tabs</option></select>
          <button type="button" className="json-primary-action" onClick={parseJson}><WandSparkles aria-hidden="true" /> Format &amp; Validate</button>
          <button type="button" className="json-tool-action" onClick={minifyJson}><FileJson aria-hidden="true" /> Minify</button>
          <button type="button" className="json-tool-action" onClick={copyResult} disabled={!output}>{copied ? <Check aria-hidden="true" /> : <Clipboard aria-hidden="true" />} {copied ? 'Copied' : 'Copy'}</button>
          <button type="button" className="json-tool-action" onClick={clearAll} disabled={!input && !output}><Eraser aria-hidden="true" /> Clear</button>
        </div>
      </div>
    </main>
  )
}

export function formatJson(input: string, indentation: Indentation = '2') {
  if (!input.trim()) return { output: '', error: 'Enter JSON to validate and format.' }
  try { const value = JSON.parse(input) as unknown; return { output: JSON.stringify(value, null, indentation === 'tab' ? '\t' : Number(indentation)), error: '' } } catch (caught) { return { output: '', error: caught instanceof Error ? caught.message : 'The JSON could not be parsed.' } }
}

export function minifyJson(input: string) {
  try { return { output: JSON.stringify(JSON.parse(input) as unknown), error: '' } } catch (caught) { return { output: '', error: caught instanceof Error ? caught.message : 'The JSON could not be parsed.' } }
}

export type { Indentation }
