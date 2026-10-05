'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ArrowDown, ArrowRight, ArrowUp, Bolt, Check, ChevronDown, CircleAlert, Clipboard,
  Code2, Copy, FileText, Filter, Hash, Info, Link2, LoaderCircle, Play, Plus, ShieldCheck,
  Trash2, X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { recordActivity } from '@/lib/activity'
import { callChain, type ChainResponse } from '@/lib/api'
import {
  addChainStep, CHAIN_MAX_STEPS, CHAIN_OPERATIONS, CHAIN_OPERATION_DESCRIPTIONS,
  CHAIN_OPERATION_LABELS, CHAIN_REQUEST_MAX_BYTES, moveChainStep, removeChainStep,
  serializedChainRequestBytes, type ChainStep,
} from '@/lib/payload-operations'

type Preset = { name: string; sample: string; steps: ChainStep[] }
type ChainEntry = ChainStep & { id: number }
const presets: Preset[] = [
  { name: 'Decode Base64 then URL', sample: 'aGVsbG8lMjB3b3JsZA==', steps: [{ operation: 'base64_decode' }, { operation: 'url_decode' }] },
  { name: 'URL encode twice', sample: 'hello world!', steps: [{ operation: 'url_encode' }, { operation: 'url_encode' }] },
  { name: 'Text to Base64 then Hex', sample: 'security payload', steps: [{ operation: 'base64_encode' }, { operation: 'hex_encode' }] },
  { name: 'Hex decode then Base64', sample: '68656c6c6f', steps: [{ operation: 'hex_decode' }, { operation: 'base64_encode' }] },
]

function prefersReducedMotion() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

function StepIcon({ operation, className = 'size-4' }: { operation: string; className?: string }) {
  const Icon = operation.startsWith('base64_') ? Code2 : operation.startsWith('url_') ? Link2 : Hash
  return <Icon className={className} aria-hidden="true" />
}

function getErrorDetails(error: unknown) {
  const requestError = error as Error & { partialSteps?: ChainResponse['steps']; failedStep?: number }
  return {
    message: requestError?.message || 'The chain failed. Try again.',
    partial: requestError?.partialSteps ?? [],
    failedStep: typeof requestError?.failedStep === 'number' ? requestError.failedStep : null,
  }
}

export function ChainBuilder() {
  const [input, setInput] = useState('')
  const [steps, setSteps] = useState<ChainEntry[]>([])
  const [result, setResult] = useState<ChainResponse | null>(null)
  const [partial, setPartial] = useState<ChainResponse['steps']>([])
  const [failedStep, setFailedStep] = useState<number | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState('')
  const [activeStep, setActiveStep] = useState<number | null>(null)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [menuOpen, setMenuOpen] = useState(false)
  const [scrollEdges, setScrollEdges] = useState({ top: false, bottom: false })
  const [announce, setAnnounce] = useState('')
  const sequence = useRef(0)
  const stepListRef = useRef<HTMLDivElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const outputCardRef = useRef<HTMLElement>(null)
  const previousPresetSample = useRef<string | null>(null)
  const inputRef = useRef(input)
  inputRef.current = input

  const requestBytes = useMemo(() => serializedChainRequestBytes(input, steps.map(({ operation }) => ({ operation }))), [input, steps])
  const requestTooLarge = requestBytes > CHAIN_REQUEST_MAX_BYTES
  const requestNearLimit = requestBytes >= CHAIN_REQUEST_MAX_BYTES * 0.85
  const outputSteps = result?.steps ?? partial
  const outputByStepId = useMemo(() => new Map(steps.slice(0, outputSteps.length).map((step, index) => [step.id, outputSteps[index]])), [steps, outputSteps])
  const hasFinalOutput = Boolean(result)
  const runDisabledReason = loading ? 'A chain is already running.' : !steps.length ? 'Add at least one step to run the chain.' : !input ? 'Enter input text to run the chain.' : requestTooLarge ? 'The request exceeds the 10 KiB limit.' : ''
  const stepGroups = useMemo(() => ['Base64', 'URL', 'Hex'].map((group) => ({
    group,
    operations: CHAIN_OPERATIONS.filter((operation) => operation.group === group),
  })), [])

  const resetResults = useCallback(() => {
    setResult(null); setPartial([]); setFailedStep(null); setError(''); setExpanded(new Set()); setAnnounce('')
  }, [])

  const updateStepListEdges = useCallback(() => {
    const element = stepListRef.current
    if (!element) return
    setScrollEdges({ top: element.scrollTop > 2, bottom: element.scrollTop + element.clientHeight < element.scrollHeight - 2 })
  }, [])

  useEffect(() => {
    updateStepListEdges()
  }, [steps.length, updateStepListEdges])

  useEffect(() => {
    if (!menuOpen) return
    const closeOnOutside = (event: PointerEvent) => {
      if (event.target instanceof Node && !menuRef.current?.contains(event.target)) setMenuOpen(false)
    }
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { setMenuOpen(false); event.stopPropagation() }
    }
    document.addEventListener('pointerdown', closeOnOutside)
    document.addEventListener('keydown', closeOnEscape)
    return () => { document.removeEventListener('pointerdown', closeOnOutside); document.removeEventListener('keydown', closeOnEscape) }
  }, [menuOpen])

  useEffect(() => {
    if (failedStep === null) return
    const item = stepListRef.current?.querySelector(`[data-step-index="${failedStep}"]`)
    item?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'nearest' })
  }, [failedStep])

  function scrollStepIntoView(id: number) {
    window.requestAnimationFrame(() => {
      const item = stepListRef.current?.querySelector(`[data-step-id="${id}"]`)
      item?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'nearest' })
    })
  }

  function addOperation(operation: string) {
    const appended = addChainStep(steps, operation)
    if (appended.length === steps.length) return
    const nextId = ++sequence.current
    setSteps([...steps, { operation, id: nextId }])
    setActiveStep(nextId); setMenuOpen(false); resetResults(); scrollStepIntoView(nextId)
  }

  function changeSteps(next: ChainEntry[]) {
    setSteps(next); resetResults()
  }

  function applyPreset(preset: Preset) {
    const canReplaceInput = inputRef.current === '' || inputRef.current === previousPresetSample.current
    if (canReplaceInput) {
      setInput(preset.sample)
      previousPresetSample.current = preset.sample
    }
    const next = preset.steps.map((step) => ({ ...step, id: ++sequence.current }))
    setSteps(next); setActiveStep(next.at(-1)?.id ?? null); resetResults()
  }

  async function run() {
    if (runDisabledReason) return
    setLoading(true); resetResults(); setAnnounce('Running chain.')
    try {
      const response = await callChain(input, steps.map(({ operation }) => ({ operation })))
      setResult(response); setAnnounce(`Chain finished, ${response.steps.length} steps`)
      recordActivity('Chain Builder', 'run chain', 'success', 'Transformation chain completed')
    } catch (reason) {
      const details = getErrorDetails(reason)
      setError(details.message); setPartial(details.partial); setFailedStep(details.failedStep)
      setAnnounce(details.message)
      recordActivity('Chain Builder', 'run chain', 'failure', 'Transformation chain failed')
    } finally {
      setLoading(false)
      window.requestAnimationFrame(() => outputCardRef.current?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'nearest' }))
    }
  }

  async function copy(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(key); window.setTimeout(() => setCopied((current) => current === key ? '' : current), 1500)
    } catch {
      setError('Clipboard access failed. Select and copy the output manually.')
    }
  }

  function clearAll() {
    setInput(''); setSteps([]); setResult(null); setPartial([]); setFailedStep(null); setError(''); setCopied(''); setExpanded(new Set()); setAnnounce('')
    previousPresetSample.current = null
  }

  function useOutputAsInput() {
    if (!result) return
    setInput(result.final); resetResults()
  }

  function handleKeyboard(event: React.KeyboardEvent<HTMLDivElement>) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault()
      if (!runDisabledReason) void run()
    }
  }

  const inputCharacterCount = input.length
  const finalText = result?.final ?? ''
  const outputStatus = loading ? 'Running' : error ? 'Error' : result ? 'Done' : 'Idle'

  return (
    <main className="chain-page min-h-[calc(100vh-76px)] bg-background text-foreground xl:h-[calc(100dvh-76px)] xl:min-h-0" onKeyDown={handleKeyboard}>
      <div className="chain-container mx-auto flex w-full max-w-[1760px] flex-col gap-3 px-4 pb-28 pt-4 sm:px-6 lg:px-8 xl:h-full xl:gap-0 xl:px-6 xl:pb-0 xl:pt-0">
        <header className="flex shrink-0 items-center justify-between gap-5 border-b border-border/70 pb-3 pt-2 xl:pb-2">
          <div className="min-w-0">
            <p className="text-xs leading-5 text-muted-foreground sm:text-sm xl:text-xs xl:leading-4">Chain multiple transformations in sequence. Each step receives the previous step&apos;s output. Build, reorder, and run transformation chains for your payloads.</p>
          </div>
          <div className="hidden shrink-0 items-center gap-2.5 lg:flex" aria-hidden="true">
            {[FileText, Filter, Code2, ShieldCheck].map((Icon, index) => <div key={index} className="flex items-center gap-2.5">
              <div className="grid size-11 place-items-center rounded-xl border border-cyan-400/20 bg-cyan-500/10 text-cyan-600 shadow-[0_0_22px_rgba(34,211,238,0.12)] dark:text-cyan-300"><Icon className="size-5" /></div>
              {index < 3 && <ArrowRight className="size-4 text-cyan-500/60" />}
            </div>)}
          </div>
        </header>

        <div className="grid min-h-0 gap-4 lg:grid-cols-2 xl:flex-1 xl:grid-cols-3 xl:gap-3">
          <section className="chain-card flex min-h-[610px] flex-col overflow-hidden rounded-2xl border border-border bg-card p-4 shadow-sm sm:p-5 xl:min-h-0" aria-labelledby="input-heading">
            <div className="mb-3 flex shrink-0 items-start justify-between gap-3">
              <div><h2 id="input-heading" className="text-base font-semibold">Input</h2><p className="mt-1 text-xs leading-5 text-muted-foreground">Add your text or encoded data to start the chain.</p></div>
              <Button variant="ghost" size="sm" onClick={() => { setInput(''); previousPresetSample.current = null; resetResults() }} disabled={!input} aria-label="Clear input" className="min-h-9 gap-1.5 text-muted-foreground"><X className="size-4" />Clear</Button>
            </div>
            <div className="flex min-h-48 flex-1 flex-col rounded-xl border border-input bg-background/70 focus-within:ring-2 focus-within:ring-cyan-500/30 xl:min-h-[120px]">
              <div className="flex min-h-0 flex-1 items-start gap-2 p-3">
                <FileText className="mt-1 size-4 shrink-0 text-muted-foreground" />
                <textarea aria-label="Input text" value={input} onChange={(event) => { setInput(event.target.value); resetResults() }} placeholder="Paste your input here..." spellCheck={false} className="min-h-36 w-full flex-1 resize-none bg-transparent font-mono text-sm leading-6 outline-none placeholder:text-muted-foreground/70 xl:min-h-0" />
              </div>
              <div className="flex shrink-0 items-center justify-between border-t border-border/60 px-3 py-2 font-mono text-[10px] text-muted-foreground"><span>{inputCharacterCount} characters</span><span>UTF-8</span></div>
            </div>
            {requestNearLimit && <p role="status" className={`mt-2 flex shrink-0 items-center gap-1.5 text-xs ${requestTooLarge ? 'text-destructive' : 'text-amber-600 dark:text-amber-300'}`}><CircleAlert className="size-3.5" />{requestTooLarge ? `Request is ${requestBytes.toLocaleString()} bytes; the limit is ${CHAIN_REQUEST_MAX_BYTES.toLocaleString()} bytes.` : `Request size is approaching the ${CHAIN_REQUEST_MAX_BYTES.toLocaleString()}-byte limit (${requestBytes.toLocaleString()} bytes).`}</p>}
            <div className="mt-4 shrink-0">
              <div className="mb-2 flex items-center gap-2"><Bolt className="size-4 text-amber-500" /><div><h3 className="text-sm font-semibold">Quick presets</h3><p className="text-[11px] text-muted-foreground">Start with common transformation chains.</p></div></div>
              <div className="grid grid-cols-2 gap-2">
                {presets.map((preset) => <button key={preset.name} type="button" onClick={() => applyPreset(preset)} className="group min-h-[76px] rounded-xl border border-border bg-background/70 p-2.5 text-left transition hover:border-cyan-500/50 hover:bg-cyan-500/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500">
                  <span className="flex items-center gap-1.5 text-[11px] font-semibold"><Play className="size-3 text-cyan-600 dark:text-cyan-300" />{preset.name}</span>
                  <span className="mt-1.5 block text-[10px] leading-4 text-muted-foreground">{preset.steps.map((step) => CHAIN_OPERATION_LABELS[step.operation]).join(' → ')}</span>
                </button>)}
              </div>
            </div>
          </section>

          <section className="chain-card flex min-h-[460px] flex-col overflow-hidden rounded-2xl border border-border bg-card p-4 shadow-sm sm:p-5 xl:min-h-0" aria-labelledby="steps-heading">
            <div className="mb-3 flex shrink-0 items-start justify-between gap-3">
              <div className="min-w-0"><h2 id="steps-heading" className="text-base font-semibold">Chain Steps</h2><p className="mt-1 text-xs leading-5 text-muted-foreground">Add, reorder, or remove steps from your transformation chain.</p></div>
              <div className="flex shrink-0 flex-col items-end gap-2"><span className="font-mono text-[10px] text-muted-foreground">{steps.length}/{CHAIN_MAX_STEPS}</span>
                <div className="relative" ref={menuRef}>
                  <Button onClick={() => setMenuOpen((open) => !open)} disabled={steps.length >= CHAIN_MAX_STEPS} aria-expanded={menuOpen} aria-haspopup="menu" title={steps.length >= CHAIN_MAX_STEPS ? 'Maximum 10 steps' : 'Add a transformation'} className="min-h-10 gap-1.5 bg-cyan-600 px-3 text-white shadow-[0_0_20px_rgba(34,211,238,0.2)] hover:bg-cyan-500 focus-visible:ring-cyan-400"><Plus className="size-4" /><span className="hidden sm:inline">Add Step</span><span className="sm:hidden">Add</span><ChevronDown className="size-3.5" /></Button>
                  {menuOpen && <div role="menu" aria-label="Choose transformation" className="absolute right-0 top-[calc(100%+8px)] z-30 max-h-[min(65vh,480px)] w-72 overflow-y-auto rounded-xl border border-border bg-popover p-2 text-popover-foreground shadow-xl ring-1 ring-black/5">
                    {stepGroups.map(({ group, operations }) => <div key={group} className="pb-1 last:pb-0"><p className="px-2 pb-1 pt-2 font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">{group}</p>{operations.map((operation) => <button key={operation.id} type="button" role="menuitem" onClick={() => addOperation(operation.id)} className="flex min-h-12 w-full items-center gap-3 rounded-lg px-2 text-left hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500">
                      <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-cyan-500/10 text-cyan-700 dark:text-cyan-300"><StepIcon operation={operation.id} /></span><span className="min-w-0"><span className="block text-xs font-semibold">{operation.label}</span><span className="block truncate text-[10px] text-muted-foreground">{operation.description}</span></span>
                    </button>)}</div>)}
                  </div>}
                </div>
              </div>
            </div>
            {steps.length >= CHAIN_MAX_STEPS && <p className="mb-2 shrink-0 text-[11px] text-muted-foreground">Maximum 10 steps</p>}
            <div className="relative min-h-[230px] flex-1 xl:min-h-0">
              {scrollEdges.top && <div className="pointer-events-none absolute inset-x-0 top-0 z-10 h-4 bg-gradient-to-b from-card to-transparent" />}
              <div ref={stepListRef} role="region" aria-label="Chain steps" tabIndex={0} onScroll={updateStepListEdges} className={`chain-step-list h-full min-h-0 space-y-2 overflow-y-auto pr-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/50 max-lg:h-auto max-lg:overflow-visible ${steps.length ? 'lg:max-h-[60vh] xl:max-h-none' : ''}`}>
                {!steps.length ? <div className="flex min-h-[220px] flex-col items-center justify-center rounded-xl border border-dashed border-border px-4 py-7 text-center">
                  <span className="mb-3 grid size-11 place-items-center rounded-xl bg-cyan-500/10 text-cyan-700 dark:text-cyan-300"><Code2 className="size-5" /></span><p className="text-sm font-medium">Add a step or pick a preset to start your chain</p><p className="mt-1 text-xs text-muted-foreground">Choose Base64, URL, or Hex transformations.</p><Button variant="outline" className="mt-4 min-h-10 gap-2" onClick={() => setMenuOpen(true)}><Plus className="size-4" />Add Step</Button>
                </div> : <>
                  <ol className="space-y-2">
                    {steps.map((step, index) => {
                      const operation = CHAIN_OPERATIONS.find((item) => item.id === step.operation)
                      const output = outputByStepId.get(step.id)
                      const isFailed = failedStep === index
                      const isSkipped = failedStep !== null && index > failedStep
                      const isOutputExpanded = expanded.has(step.id)
                      return <li key={step.id} data-step-id={step.id} data-step-index={index} onClick={() => setActiveStep(step.id)} className={`rounded-xl border bg-background/65 p-3 transition-colors ${isFailed ? 'border-destructive/60' : activeStep === step.id ? 'border-cyan-500/60 shadow-[0_0_18px_rgba(34,211,238,0.08)]' : 'border-border'} ${isSkipped ? 'opacity-55' : ''}`}>
                        <div className="flex items-center gap-2.5">
                          <span className="grid size-7 shrink-0 place-items-center rounded-full bg-muted font-mono text-[11px] font-semibold text-muted-foreground">{index + 1}</span>
                          <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-cyan-500/10 text-cyan-700 dark:text-cyan-300"><StepIcon operation={step.operation} /></span>
                          <span className="min-w-0 flex-1"><span className="block truncate text-xs font-semibold">{operation?.label ?? step.operation}</span><span className="block truncate text-[10px] text-muted-foreground">{operation?.description ?? CHAIN_OPERATION_DESCRIPTIONS[step.operation]}</span></span>
                          {isSkipped && <span className="text-[10px] font-medium text-muted-foreground">Skipped</span>}
                          <button type="button" aria-label={`Move step ${index + 1} up`} title="Move up" disabled={index === 0} onClick={(event) => { event.stopPropagation(); setActiveStep(step.id); changeSteps(moveChainStep(steps, index, -1) as ChainEntry[]) }} className="grid size-9 shrink-0 place-items-center rounded-lg text-muted-foreground hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 disabled:opacity-35"><ArrowUp className="size-4" /></button>
                          <button type="button" aria-label={`Move step ${index + 1} down`} title="Move down" disabled={index === steps.length - 1} onClick={(event) => { event.stopPropagation(); setActiveStep(step.id); changeSteps(moveChainStep(steps, index, 1) as ChainEntry[]) }} className="grid size-9 shrink-0 place-items-center rounded-lg text-muted-foreground hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 disabled:opacity-35"><ArrowDown className="size-4" /></button>
                          <button type="button" aria-label={`Remove step ${index + 1}`} title="Remove step" onClick={(event) => { event.stopPropagation(); setActiveStep(null); changeSteps(removeChainStep(steps, index) as ChainEntry[]) }} className="grid size-9 shrink-0 place-items-center rounded-lg text-muted-foreground hover:bg-destructive/10 hover:text-destructive focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-destructive"><Trash2 className="size-4" /></button>
                        </div>
                        {isFailed && error && <p role="alert" className="mt-2 flex items-start gap-1.5 text-[11px] text-destructive"><CircleAlert className="mt-0.5 size-3.5 shrink-0" />{error}</p>}
                        {output && <div className="chain-output-enter mt-2 border-t border-border/70 pt-2"><div className="mb-1.5 flex items-center justify-between gap-2"><span className="font-mono text-[10px] text-muted-foreground">Output · {output.output.length.toLocaleString()} characters</span><div className="flex items-center gap-1"><button type="button" onClick={() => void copy(output.output, `step-${step.id}`)} className="flex min-h-9 items-center gap-1 rounded-md px-2 text-[10px] text-muted-foreground hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500">{copied === `step-${step.id}` ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}{copied === `step-${step.id}` ? 'Copied' : 'Copy'}</button>{output.output.length > 160 && <button type="button" onClick={() => setExpanded((current) => { const next = new Set(current); if (next.has(step.id)) next.delete(step.id); else next.add(step.id); return next })} className="min-h-9 rounded-md px-2 text-[10px] text-cyan-700 hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:text-cyan-300">{isOutputExpanded ? 'Collapse' : 'Expand'}</button>}</div></div><pre className={`whitespace-pre-wrap break-all rounded-lg bg-muted/60 p-2 font-mono text-[10px] leading-4 ${isOutputExpanded ? 'max-h-72 overflow-auto' : 'max-h-14 overflow-hidden'}`}>{output.output}</pre></div>}
                      </li>
                    })}
                  </ol>
                  {steps.length < CHAIN_MAX_STEPS && <button type="button" onClick={() => setMenuOpen(true)} className="flex min-h-11 w-full items-center justify-center gap-2 rounded-xl border border-dashed border-border text-xs text-muted-foreground transition hover:border-cyan-500/50 hover:text-cyan-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:hover:text-cyan-300"><Plus className="size-4" />Add step</button>}
                </>}
              </div>
              {scrollEdges.bottom && <div className="pointer-events-none absolute inset-x-0 bottom-0 z-10 h-4 bg-gradient-to-t from-card to-transparent" />}
            </div>
          </section>

          <section ref={outputCardRef as React.RefObject<HTMLElement>} className="chain-card flex min-h-[460px] flex-col overflow-hidden rounded-2xl border border-border bg-card p-4 shadow-sm sm:p-5 lg:col-span-2 xl:col-span-1 xl:min-h-0" aria-labelledby="output-heading">
            <div className="mb-3 flex shrink-0 items-start justify-between gap-3"><div><h2 id="output-heading" className="text-base font-semibold">Output</h2><p className="mt-1 text-xs leading-5 text-muted-foreground">Final result after all transformations.</p></div><span className={`inline-flex min-h-7 items-center gap-1.5 rounded-full border px-2.5 font-mono text-[10px] ${outputStatus === 'Done' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' : outputStatus === 'Error' ? 'border-destructive/30 bg-destructive/10 text-destructive' : outputStatus === 'Running' ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300' : 'border-border text-muted-foreground'}`}>{loading && <LoaderCircle className="size-3 animate-spin motion-reduce:animate-none" />}{error && <CircleAlert className="size-3" />}{result && <Check className="size-3" />}{outputStatus}</span></div>
            <div className="flex min-h-48 flex-1 flex-col rounded-xl border border-input bg-background/70 xl:min-h-[120px]">
              <div className="flex min-h-0 flex-1 items-start gap-2 overflow-hidden p-3"><FileText className="mt-1 size-4 shrink-0 text-muted-foreground" /><pre aria-label="Final output" className="min-h-36 w-full flex-1 overflow-auto whitespace-pre-wrap break-all font-mono text-sm leading-6 text-foreground xl:min-h-0">{result ? finalText : <span className="text-muted-foreground/70">Your result will appear here...</span>}</pre></div>
              <div className="flex shrink-0 items-center justify-between border-t border-border/60 px-3 py-2 font-mono text-[10px] text-muted-foreground"><span>{finalText.length.toLocaleString()} characters</span><span>UTF-8</span></div>
            </div>
            {error && failedStep !== null && <p className="mt-2 shrink-0 text-xs text-destructive">Step {failedStep + 1} failed. Later steps were skipped.</p>}
            <div className="mt-2 flex shrink-0 justify-end"><Button variant="outline" size="sm" disabled={!result} onClick={useOutputAsInput} className="min-h-9">Use as input</Button></div>
            {!steps.length && <p className="mt-2 flex shrink-0 items-center gap-1.5 text-[10px] text-muted-foreground"><Info className="size-3.5" />Add steps to transform your input.</p>}
          </section>
        </div>

        <footer className="sticky bottom-0 z-20 -mx-4 flex shrink-0 items-center justify-between gap-3 border-t border-border bg-background/95 px-4 py-3 pb-[calc(0.75rem+env(safe-area-inset-bottom))] backdrop-blur sm:-mx-6 sm:px-6 lg:-mx-8 lg:px-8 xl:static xl:mx-0 xl:bg-transparent xl:px-0 xl:py-1">
          <p className="hidden min-w-0 items-center gap-2 text-xs text-muted-foreground md:flex"><Info className="size-4 shrink-0 text-cyan-600 dark:text-cyan-300" /><span>Supports Base64, URL, and Hex transformations. Up to 10 steps.</span></p>
          <div className="ml-auto flex shrink-0 items-center gap-1.5 sm:gap-2">
            <Button variant="ghost" size="sm" onClick={clearAll} className="min-h-10 px-2 sm:px-3"><Trash2 className="size-4" /><span className="hidden sm:inline">Clear All</span><span className="sm:hidden">Clear</span></Button>
            <span title={hasFinalOutput ? 'Copy the final result' : 'Run a chain to create a result'}><Button variant="outline" size="sm" disabled={!result} onClick={() => result && void copy(result.final, 'final')} className="min-h-10 px-2 sm:px-3"><Clipboard className="size-4" /><span className="hidden sm:inline">{copied === 'final' ? 'Copied' : 'Copy Result'}</span><span className="sm:hidden">Copy</span></Button></span>
            <span title={runDisabledReason || 'Run this chain'}><Button aria-label={runDisabledReason ? `Run Chain. ${runDisabledReason}` : 'Run Chain'} onClick={() => void run()} disabled={Boolean(runDisabledReason)} className="min-h-10 gap-1.5 bg-cyan-600 px-3 text-white shadow-[0_0_22px_rgba(34,211,238,0.2)] hover:bg-cyan-500 focus-visible:ring-cyan-400 sm:px-4">{loading ? <LoaderCircle className="size-4 animate-spin motion-reduce:animate-none" /> : <Play className="size-4" fill="currentColor" />}<span className="hidden sm:inline">{loading ? 'Running…' : 'Run Chain'}</span><span className="sm:hidden">{loading ? 'Run…' : 'Run'}</span></Button></span>
          </div>
        </footer>
        <div aria-live="polite" className="sr-only">{announce}</div>
      </div>
    </main>
  )
}
