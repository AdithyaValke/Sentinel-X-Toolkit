'use client'

import { Suspense, useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Check,
  Clipboard,
  Cpu,
  Eraser,
  FlaskConical,
  Info,
  KeyRound,
  Lock,
  ScanSearch,
  Monitor,
  RefreshCw,
  Shield,
  ShieldCheck,
  Terminal,
  Zap,
} from 'lucide-react'
import { formatHttpUrl, validateIP } from '@/lib/security-lab-utils'
import { IOC_EXTRACTOR_CATALOG_ENTRY, JWT_DECODER_CATALOG_ENTRY, PAYLOAD_GENERATOR_CATALOG_ENTRY, SECURITY_HEADERS_CATALOG_ENTRY, parseSecurityLabTab, type SecurityLabTabId } from '@/lib/security-lab-catalog.ts'
import { IocExtractor } from '@/components/ioc-extractor'
import { SecurityHeadersAnalyzer } from '@/components/security-headers-analyzer'
import { SecurityLabJwtPanel } from '@/components/security-lab-jwt-panel'
import { cancelActivityDebounce, recordActivity, recordActivityDebounced } from '@/lib/activity'

// ─── Payload Generator ───────────────────────────────────────────────────────

type Platform = 'Linux' | 'Windows' | 'macOS'
type Category =
  | 'connectivity-test'
  | 'port-check'
  | 'listener-reference'
  | 'socat-relay'
  | 'curl-beacon'

interface PayloadCategory {
  id: Category
  label: string
  description: string
  platforms: Platform[]
}

const PAYLOAD_CATEGORIES: PayloadCategory[] = [
  {
    id: 'connectivity-test',
    label: 'Connectivity Test',
    description: 'Benign TCP reachability probe — verifies that a host:port is accepting connections.',
    platforms: ['Linux', 'Windows', 'macOS'],
  },
  {
    id: 'port-check',
    label: 'Port-Open Check',
    description: 'One-liner that reports whether a specific port is open on the target IP.',
    platforms: ['Linux', 'Windows', 'macOS'],
  },
  {
    id: 'listener-reference',
    label: 'Listener Setup Reference',
    description:
      'Non-executable reference illustrating the netcat/socat listener command structure studied in defensive training.',
    platforms: ['Linux', 'macOS'],
  },
  {
    id: 'socat-relay',
    label: 'Socat Relay Reference',
    description:
      'Reference template for socat TCP relay syntax — used in defensive lab configurations and firewalled network analysis.',
    platforms: ['Linux', 'macOS'],
  },
  {
    id: 'curl-beacon',
    label: 'HTTP Beacon Probe',
    description:
      'Simple HTTP GET probe to check HTTP reachability on the configured IP and port.',
    platforms: ['Linux', 'Windows', 'macOS'],
  },
]

function generatePayload(
  ip: string,
  port: string,
  platform: Platform,
  category: Category,
): string {
  const portNum = parseInt(port, 10)

  switch (category) {
    case 'connectivity-test': {
      if (platform === 'Windows') {
        return [
          `# [REFERENCE ONLY — NOT FOR UNAUTHORIZED USE]`,
          `# Windows PowerShell TCP connectivity test to ${ip}:${portNum}`,
          `#`,
          `# Purpose: Verify that TCP port ${portNum} is reachable at ${ip}`,
          `# This probes only — it does not execute any remote code.`,
          ``,
          `$target = "${ip}"`,
          `$port   = ${portNum}`,
          ``,
          `$client = New-Object System.Net.Sockets.TcpClient`,
          `$connect = $null`,
          `try {`,
          `    $connect = $client.BeginConnect($target, $port, $null, $null)`,
          `    if (-not $connect.AsyncWaitHandle.WaitOne(5000, $false)) { throw [TimeoutException]::new('Connection timed out after 5 seconds.') }`,
          `    $client.EndConnect($connect)`,
          `    Write-Host "[$( Get-Date -f 'HH:mm:ss' )] TCP $target:${portNum} — REACHABLE" -ForegroundColor Green`,
          `} catch [TimeoutException] {`,
          `    Write-Host "[$( Get-Date -f 'HH:mm:ss' )] TCP $target:${portNum} — TIMED OUT after 5 seconds" -ForegroundColor Red`,
          `} catch {`,
          `    Write-Host "[$( Get-Date -f 'HH:mm:ss' )] TCP $target:${portNum} — UNREACHABLE: $_" -ForegroundColor Red`,
          `} finally {`,
          `    if ($connect) { $connect.AsyncWaitHandle.Close() }`,
          `    $client.Dispose()`,
          `}`,
        ].join('\n')
      }
      // Linux / macOS (Python socket timeout works on both platforms)
      return [
        `# [REFERENCE ONLY — NOT FOR UNAUTHORIZED USE]`,
        `# Python 3 TCP connectivity test to ${ip}:${portNum}`,
        `#`,
        `# Purpose: Verify that TCP port ${portNum} is reachable at ${ip}`,
        `# Uses a 5-second socket timeout and distinguishes timeout from connection failure.`,
        `# This probes only — it does not execute any remote code.`,
        ``,
        `python3 - "${ip}" ${portNum} <<'PY'`,
        `import socket, sys`,
        `host, port = sys.argv[1], int(sys.argv[2])`,
        `try:`,
        `    with socket.create_connection((host, port), timeout=5):`,
        `        print(f"TCP {host}:{port} — REACHABLE")`,
        `except TimeoutError:`,
        `    print(f"TCP {host}:{port} — TIMED OUT after 5 seconds")`,
        `except OSError as error:`,
        `    print(f"TCP {host}:{port} — UNREACHABLE: {error}")`,
        `PY`,
      ].join('\n')
    }

    case 'port-check': {
      if (platform === 'Windows') {
        return [
          `# [REFERENCE ONLY — NOT FOR UNAUTHORIZED USE]`,
          `# Windows: Test-NetConnection port check for ${ip}:${portNum}`,
          `#`,
          `# Requires PowerShell 4.0+`,
          ``,
          `Test-NetConnection -ComputerName "${ip}" -Port ${portNum} | Select-Object -Property ComputerName, RemotePort, TcpTestSucceeded`,
        ].join('\n')
      }
      if (platform === 'macOS') {
        return [
          `# [REFERENCE ONLY — NOT FOR UNAUTHORIZED USE]`,
          `# macOS: nc-based port-open check for ${ip}:${portNum}`,
          `#`,
          `# nc -z: zero-I/O mode (port scan), -w 5: 5-second timeout`,
          ``,
          `nc -z -w 5 "${ip}" ${portNum} 2>&1 && \\`,
          `    echo "Port ${portNum} on ${ip} is OPEN" || \\`,
          `    echo "Port ${portNum} on ${ip} is CLOSED or FILTERED"`,
        ].join('\n')
      }
      // Linux
      return [
        `# [REFERENCE ONLY — NOT FOR UNAUTHORIZED USE]`,
        `# Linux: nc / nmap port-open check for ${ip}:${portNum}`,
        `#`,
        `# Option A — netcat (nc)`,
        `nc -z -v -w 5 "${ip}" ${portNum} 2>&1`,
        ``,
        `# Option B — nmap single-port scan (requires nmap)`,
        `# nmap -sV -p ${portNum} --open "${ip}"`,
      ].join('\n')
    }

    case 'listener-reference': {
      // Linux / macOS only
      return [
        `# [REFERENCE ONLY — NON-EXECUTABLE EDUCATIONAL TEMPLATE]`,
        `# Listener setup reference — ${platform}`,
        `#`,
        `# The following illustrates the command structure studied in defensive network-security`,
        `# training. It is provided as a static architectural reference, NOT a ready-to-run payload.`,
        `# Replace <LISTENER_IP> and <PORT> placeholders before any authorised lab use.`,
        `#`,
        `# ── Option A: netcat (classic listener) ──────────────────────────────────`,
        `# nc -lvnp <PORT>`,
        `#   -l  listen mode`,
        `#   -v  verbose output`,
        `#   -n  skip DNS resolution`,
        `#   -p  port to bind`,
        `#`,
        `# ── Option B: socat (TLS-capable listener) ────────────────────────────────`,
        `# socat TCP-LISTEN:<PORT>,reuseaddr,fork STDOUT`,
        `#`,
        `# ── Lab configuration reference values ───────────────────────────────────`,
        `# Configured IP  : ${ip}`,
        `# Configured Port: ${portNum}`,
        `#`,
        `# The IP and port above are configuration values for your authorised lab environment.`,
        `# This file was generated locally; no network connection was made.`,
      ].join('\n')
    }

    case 'socat-relay': {
      // Linux / macOS only
      return [
        `# [REFERENCE ONLY — NON-EXECUTABLE EDUCATIONAL TEMPLATE]`,
        `# socat TCP relay reference — ${platform}`,
        `#`,
        `# Purpose: Illustrate socat relay syntax for defensive network-lab configurations.`,
        `# Used for port-forwarding analysis, honeypot forwarding, and firewalled-network studies.`,
        `#`,
        `# ── TCP relay (forward incoming on <LOCAL_PORT> to ${ip}:${portNum}) ──────`,
        `# socat TCP-LISTEN:<LOCAL_PORT>,fork TCP:${ip}:${portNum}`,
        `#`,
        `# ── TLS relay (TLS in → plain TCP out) ────────────────────────────────────`,
        `# socat OPENSSL-LISTEN:<LOCAL_PORT>,cert=server.pem,cafile=ca.pem,verify=1,fork \\`,
        `#       TCP:${ip}:${portNum}`,
        `#`,
        `# ── Lab configuration reference values ───────────────────────────────────`,
        `# Relay destination: ${ip}:${portNum}`,
        `#`,
        `# This file was generated locally; no network connection was made.`,
      ].join('\n')
    }

    case 'curl-beacon': {
      if (platform === 'Windows') {
        return [
          `# [REFERENCE ONLY — NOT FOR UNAUTHORIZED USE]`,
          `# Windows PowerShell HTTP GET reachability probe for ${formatHttpUrl(ip, portNum)}`,
          `#`,
          `# Sends a GET request and reports HTTP status; the response body is discarded.`,
          ``,
          `$url = "${formatHttpUrl(ip, portNum)}"`,
          `try {`,
          `    $resp = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 10 -UseBasicParsing`,
          `    Write-Host "HTTP $($resp.StatusCode) — $url reachable" -ForegroundColor Green`,
          `} catch {`,
          `    Write-Host "FAILED — $url unreachable: $_" -ForegroundColor Red`,
          `}`,
        ].join('\n')
      }
      // Linux / macOS
      const url = formatHttpUrl(ip, portNum)
      return [
        `# [REFERENCE ONLY — NOT FOR UNAUTHORIZED USE]`,
        `# curl HTTP GET reachability probe for ${url}`,
        `#`,
        `# -s  silent  -o /dev/null  discard body  -w  write status code`,
        `# No data is posted; this is a GET reachability check only.`,
        ``,
        `curl -s -X GET -o /dev/null -w "HTTP %{http_code} — ${ip}:${portNum}\\n" \\`,
        `     --max-time 10 \\`,
        `     "${url}"`,
      ].join('\n')
    }

    default:
      return ''
  }
}

// ─── Validation ──────────────────────────────────────────────────────────────

function validatePort(port: string): { valid: boolean; message?: string } {
  if (!port.trim()) return { valid: false, message: 'Port is required.' }
  const n = Number(port)
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    return { valid: false, message: 'Port must be an integer between 1 and 65535.' }
  }
  return { valid: true }
}

// ─── IoC Sample Data ─────────────────────────────────────────────────────────

const SAMPLE_IOCS = [
  { label: 'Malicious URL', value: 'https://malicious-c2-server.example.com/payloads/dropper.exe' },
  { label: 'C2 IPv4 Address', value: '198.51.100.45:8443' },
  { label: 'Phishing Domain', value: 'login.bank-security-verify.example.org' },
  { label: 'Threat Email', value: 'attacker@threat-campaign.example.net' },
  {
    label: 'Multi-IoC List',
    value:
      'http://phishing-site.example.com/login\n192.0.2.146\nfinance-update@malware-domain.org\nhttps://evil-cdn.example.net/stager.ps1',
  },
]

// ─── Component ───────────────────────────────────────────────────────────────

type SecurityLabTab = SecurityLabTabId

function SecurityLabSearchTabSync({ onTabChange }: { onTabChange: (tab: SecurityLabTab) => void }) {
  const searchParams = useSearchParams()
  const tab = parseSecurityLabTab(searchParams.get('tab'))

  useEffect(() => {
    onTabChange(tab)
  }, [onTabChange, tab])

  return null
}

export function SecurityLab() {
  const router = useRouter()
  const [activeTab, setActiveTab] = useState<SecurityLabTab>('overview')

  function selectTab(tab: SecurityLabTab) {
    setActiveTab(tab)
    router.replace(`/security-lab?tab=${tab}`, { scroll: false })
  }

  // ── IoC Defanger state ──────────────────────────────────────────────────
  const [iocInput, setIocInput] = useState('')
  const [iocOutput, setIocOutput] = useState('')
  const [iocMode, setIocMode] = useState<'defang' | 'refang'>('defang')
  const [iocType, setIocType] = useState<string>('Empty')
  const [iocError, setIocError] = useState('')
  const [copiedIoc, setCopiedIoc] = useState(false)

  // ── Payload Generator state ─────────────────────────────────────────────
  const [pgIP, setPgIP] = useState('')
  const [pgPort, setPgPort] = useState('')
  const [pgPlatform, setPgPlatform] = useState<Platform>('Linux')
  const [pgCategory, setPgCategory] = useState<Category>('connectivity-test')
  const [pgOutput, setPgOutput] = useState('')
  const [pgError, setPgError] = useState('')
  const [pgCopied, setPgCopied] = useState(false)
  const [pgIPError, setPgIPError] = useState('')
  const [pgPortError, setPgPortError] = useState('')

  // ── IoC helpers ─────────────────────────────────────────────────────────
  function detectIoCType(text: string): string {
    const trimmed = text.trim()
    if (!trimmed) return 'Empty'
    const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0)
    if (lines.length > 1) return `Batch (${lines.length} indicators)`
    if (/^https?:\/\//i.test(trimmed) || /^hxxps?:\/\//i.test(trimmed)) return 'URL'
    if (
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?$/.test(
        trimmed,
      )
    )
      return 'IPv4 Address'
    if (/^[^\s@]+(?:@|\[at\])[^\s@]+$/i.test(trimmed)) return 'Email Address'
    if (
      /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.)+[a-zA-Z]{2,}(?::\d+)?$/i.test(
        trimmed,
      )
    )
      return 'Domain / FQDN'
    return 'Text / Mixed'
  }

  function handleProcessIoc(text: string, mode: 'defang' | 'refang') {
    if (!text.trim()) {
      cancelActivityDebounce('ioc-defender')
      setIocOutput('')
      setIocError('')
      setIocType('Empty')
      return
    }
    setIocError('')
    setIocType(detectIoCType(text))
    try {
      if (mode === 'defang') {
        let r = text.replace(/http:\/\//gi, 'hxxp://')
        r = r.replace(/https:\/\//gi, 'hxxps://')
        r = r.replace(/ftp:\/\//gi, 'fxp://')
        r = r.replace(/\[\.\]/g, '___DOT___')
        r = r.replace(/\./g, '[.]')
        r = r.replace(/___DOT___/g, '[.]')
        r = r.replace(/\[at\]/gi, '___AT___')
        r = r.replace(/@/g, '[at]')
        r = r.replace(/___AT___/g, '[at]')
        setIocOutput(r)
        recordActivityDebounced('ioc-defender', 'IoC Defender', mode, 'success', 'Indicator transformation completed')
      } else {
        let r = text.replace(/hxxps:\/\//gi, 'https://')
        r = r.replace(/hxxp:\/\//gi, 'http://')
        r = r.replace(/fxp:\/\//gi, 'ftp://')
        r = r.replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
        r = r.replace(/\[at\]|\(@\)|\{@\}|\[AT\]/gi, '@')
        r = r.replace(/\[:\/\/\]/g, '://')
        setIocOutput(r)
        recordActivityDebounced('ioc-defender', 'IoC Defender', mode, 'success', 'Indicator transformation completed')
      }
    } catch {
      setIocError('An error occurred while sanitizing the indicators.')
      recordActivityDebounced('ioc-defender', 'IoC Defender', mode, 'failure', 'Indicator transformation failed')
    }
  }

  function handleIocInputChange(value: string) {
    setIocInput(value)
    handleProcessIoc(value, iocMode)
  }

  function switchIocMode(newMode: 'defang' | 'refang') {
    setIocMode(newMode)
    handleProcessIoc(iocInput, newMode)
  }

  async function copyIocResult() {
    if (!iocOutput) return
    try {
      await navigator.clipboard.writeText(iocOutput)
      setCopiedIoc(true)
      window.setTimeout(() => setCopiedIoc(false), 1600)
    } catch {
      setIocError('Clipboard access failed. Select and copy output manually.')
    }
  }

  function clearIoc() {
    setIocInput('')
    setIocOutput('')
    setIocError('')
    setIocType('Empty')
    setCopiedIoc(false)
  }

  // ── Payload Generator helpers ───────────────────────────────────────────
  function handleGenerate() {
    const ipResult = validateIP(pgIP)
    const portResult = validatePort(pgPort)
    setPgIPError(ipResult.message ?? '')
    setPgPortError(portResult.message ?? '')
    if (!ipResult.valid || !portResult.valid) {
      setPgOutput('')
      setPgError('')
      recordActivity(pgCategory === 'listener-reference' || pgCategory === 'socat-relay' ? 'Reference Generator' : 'Payload Generator', pgCategory.replace('-', ' '), 'failure', 'Reference generation failed')
      return
    }
    setPgError('')
    const result = generatePayload(pgIP.trim(), pgPort.trim(), pgPlatform, pgCategory)
    setPgOutput(result)
    setPgCopied(false)
    recordActivity(pgCategory === 'listener-reference' || pgCategory === 'socat-relay' ? 'Reference Generator' : 'Payload Generator', pgCategory.replace('-', ' '), 'success', 'Reference generated')
  }

  async function copyPgOutput() {
    if (!pgOutput) return
    try {
      await navigator.clipboard.writeText(pgOutput)
      setPgCopied(true)
      window.setTimeout(() => setPgCopied(false), 1600)
    } catch {
      setPgError('Clipboard access failed. Select and copy the output manually.')
    }
  }

  function clearPg() {
    setPgIP('')
    setPgPort('')
    setPgPlatform('Linux')
    setPgCategory('connectivity-test')
    setPgOutput('')
    setPgError('')
    setPgIPError('')
    setPgPortError('')
    setPgCopied(false)
  }

  // Filtered categories for the selected platform
  const availableCategories = PAYLOAD_CATEGORIES.filter((c) =>
    c.platforms.includes(pgPlatform),
  )
  const activeCategoryMeta =
    PAYLOAD_CATEGORIES.find((c) => c.id === pgCategory) ?? PAYLOAD_CATEGORIES[0]

  return (
    <main className="min-h-screen bg-[#080b12] text-slate-100 selection:bg-cyan-400/30">
      <Suspense fallback={null}>
        <SecurityLabSearchTabSync onTabChange={setActiveTab} />
      </Suspense>
      <div className="mx-auto max-w-7xl px-4 pt-3 pb-6 sm:px-6 sm:pt-3 sm:pb-7 lg:px-8 lg:pt-4 lg:pb-8">
        {/* ── Hero ──────────────────────────────────────────────────────────── */}
        {activeTab === 'overview' ? <section className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-[#101928] via-[#0d1422] to-[#0a0e17] p-6 sm:p-8 lg:p-10">
          <div className="pointer-events-none absolute -right-24 -top-32 size-80 rounded-full bg-emerald-400/[0.07] blur-3xl" />
          <span title="Isolated lab: no live commands or network connections" aria-label="Isolated lab: no live commands or network connections" className="absolute right-6 top-6 z-10 inline-flex items-center gap-1.5 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-emerald-300 sm:right-8 sm:top-8">
            <span className="size-1.5 animate-pulse rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(74,222,128,0.8)]" />
            Isolated Lab
          </span>
          <div className="relative max-w-3xl">
            <div className="mb-4 inline-flex items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 font-mono text-xs font-semibold text-emerald-300">
              <FlaskConical className="size-3.5" />
              Educational &amp; Security Analysis
            </div>
            <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl lg:text-5xl">
              Analysis <span className="text-emerald-400">Lab</span>
            </h1>
            <p className="mt-4 text-sm leading-6 text-slate-300 sm:text-base sm:leading-7">
              An interactive defensive analysis environment for indicator sanitization (IoC
              defanging), JWT decoding, reference payload generation, and security tooling — without executing
              live commands or initiating network connections.
            </p>
            <div className="mt-6 flex flex-wrap gap-2 text-xs">
              <span className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-slate-300">
                <ShieldCheck className="size-3.5 text-emerald-400" /> Safe Sandbox (Zero Remote
                Calls)
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-slate-300">
                <Lock className="size-3.5 text-cyan-400" /> Client-Side Generation Only
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-slate-300">
                <Terminal className="size-3.5 text-violet-400" /> Defense &amp; Detection Focus
              </span>
            </div>
          </div>
        </section> : <h1 className="sr-only">Analysis Lab</h1>}

        {/* ── Tab Navigation ────────────────────────────────────────────────── */}
        <nav
          aria-label="Analysis Lab navigation tabs"
          className={`${activeTab === 'overview' ? 'mt-4' : 'mt-0'} flex flex-wrap gap-2 border-b border-white/[0.08] pb-3`}
        >
          {(
            [
              { id: 'overview', label: 'Overview & Catalog' },
              { id: 'defanger', label: 'IoC Defanger & Sanitizer' },
              { id: 'payload-generator', label: PAYLOAD_GENERATOR_CATALOG_ENTRY.title },
              { id: 'jwt-decoder', label: JWT_DECODER_CATALOG_ENTRY.title },
              { id: 'ioc-extractor', label: IOC_EXTRACTOR_CATALOG_ENTRY.title },
              { id: 'security-headers', label: SECURITY_HEADERS_CATALOG_ENTRY.title },
            ] as const
          ).map(({ id, label }) => (
            <button
              key={id}
              type="button"
              onClick={() => selectTab(id)}
              aria-current={activeTab === id ? 'page' : undefined}
              className={`min-h-11 rounded-xl px-4 py-2.5 text-xs font-semibold transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 sm:text-sm ${
                activeTab === id
                  ? 'bg-emerald-400 text-slate-950 shadow-md shadow-emerald-400/20'
                  : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200'
              }`}
            >
              {label}
            </button>
          ))}
          {activeTab !== 'overview' && (
            <span title="Isolated lab: no live commands or network connections" aria-label="Isolated lab: no live commands or network connections" className="ml-auto inline-flex items-center gap-1.5 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-emerald-300">
              <span className="size-1.5 animate-pulse rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(74,222,128,0.8)]" />
              Isolated Lab
            </span>
          )}
        </nav>

        {/* ════════════════════════════════════════════════════════════════════
            TAB 1: OVERVIEW & CATALOG
        ════════════════════════════════════════════════════════════════════ */}
        {activeTab === 'overview' && (
          <div className="mt-6 space-y-6">
            <div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-emerald-400">
                    Lab Suite
                  </p>
                  <h2 className="mt-1 text-xl font-bold text-white sm:text-2xl">
                    Security Analysis Tools
                  </h2>
                </div>
              </div>

              <div className="mt-4 grid items-stretch gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {/* Card: IoC Defanger */}
                <article className="flex flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-6 transition duration-200 hover:border-emerald-400/40 hover:bg-[#101724]">
                  <div className="flex items-start justify-between">
                    <span className="flex size-10 items-center justify-center rounded-xl bg-emerald-400/10 text-emerald-300 ring-1 ring-emerald-400/20">
                      <Shield className="size-5" />
                    </span>
                    <span className="rounded bg-emerald-400/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-emerald-300">
                      Active Utility
                    </span>
                  </div>
                  <h3 className="mt-4 text-base font-semibold text-white">
                    IoC Defanger &amp; Sanitizer
                  </h3>
                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    Defang and neutralize malicious URLs, IP addresses, domains, and email
                    addresses for secure logging and reporting.
                  </p>
                  <button
                    type="button"
                    onClick={() => selectTab('defanger')}
                    className="mt-auto inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-emerald-400/10 px-4 py-2 text-xs font-semibold text-emerald-300 transition hover:bg-emerald-400 hover:text-slate-950"
                  >
                    Open Defanger <ArrowRight className="size-3.5" />
                  </button>
                </article>

                {/* Card: Payload Generator */}
                <article className="flex flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-6 transition duration-200 hover:border-cyan-400/40 hover:bg-[#101724]">
                  <div className="flex items-start justify-between gap-3">
                    <span className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/20">
                      <Zap className="size-5" />
                    </span>
                    <span className="rounded bg-cyan-400/10 px-2 py-0.5 text-right font-mono text-[10px] font-semibold uppercase tracking-wider text-cyan-300">
                      Reference Generator
                    </span>
                  </div>
                  <h3 className="mt-4 text-base font-semibold text-white">
                    {PAYLOAD_GENERATOR_CATALOG_ENTRY.title}
                  </h3>
                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    {PAYLOAD_GENERATOR_CATALOG_ENTRY.description} Everything is generated locally;
                    nothing is executed or sent over the network.
                  </p>
                  <Link
                    href={PAYLOAD_GENERATOR_CATALOG_ENTRY.href}
                    className="mt-auto inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-cyan-400/10 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-400 hover:text-slate-950"
                  >
                    Open Payload Generator <ArrowUpRight className="size-3.5" />
                  </Link>
                </article>

                {/* Card: IoC Extractor */}
                <article className="flex flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-6 transition duration-200 hover:border-cyan-400/40 hover:bg-[#101724]">
                  <div className="flex items-start justify-between gap-3">
                    <span className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/20"><ScanSearch className="size-5" /></span>
                    <span className="rounded bg-cyan-400/10 px-2 py-0.5 text-right font-mono text-[10px] font-semibold uppercase tracking-wider text-cyan-300">Local Analyzer</span>
                  </div>
                  <h3 className="mt-4 text-base font-semibold text-white">{IOC_EXTRACTOR_CATALOG_ENTRY.title}</h3>
                  <p className="mt-2 text-xs leading-5 text-slate-400">{IOC_EXTRACTOR_CATALOG_ENTRY.description} Results are deduplicated locally with occurrence counts.</p>
                  <Link href={IOC_EXTRACTOR_CATALOG_ENTRY.href} className="mt-auto inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-cyan-400/10 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-400 hover:text-slate-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400">
                    Open IoC Extractor <ArrowUpRight className="size-3.5" />
                  </Link>
                </article>

                {/* Card: JWT Decoder */}
                <article className="flex flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-6 transition duration-200 hover:border-emerald-400/40 hover:bg-[#101724]">
                  <div className="flex items-start justify-between gap-3">
                    <span className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-emerald-400/10 text-emerald-300 ring-1 ring-emerald-400/20"><KeyRound className="size-5" /></span>
                    <span className="rounded bg-emerald-400/10 px-2 py-0.5 text-right font-mono text-[10px] font-semibold uppercase tracking-wider text-emerald-300">Local Analyzer</span>
                  </div>
                  <h3 className="mt-4 text-base font-semibold text-white">{JWT_DECODER_CATALOG_ENTRY.title}</h3>
                  <p className="mt-2 text-xs leading-5 text-slate-400">{JWT_DECODER_CATALOG_ENTRY.description} Token data stays in this browser tab.</p>
                  <Link href={JWT_DECODER_CATALOG_ENTRY.href} className="mt-auto inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-emerald-400/10 px-4 py-2 text-xs font-semibold text-emerald-300 transition hover:bg-emerald-400 hover:text-slate-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400">
                    Open JWT Decoder <ArrowUpRight className="size-3.5" />
                  </Link>
                </article>

                {/* Card: Security Headers Analyzer */}
                <article className="flex flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-6 transition duration-200 hover:border-cyan-400/40 hover:bg-[#101724]">
                  <div className="flex items-start justify-between gap-3">
                    <span className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/20"><ShieldCheck className="size-5" /></span>
                    <span className="rounded bg-cyan-400/10 px-2 py-0.5 text-right font-mono text-[10px] font-semibold uppercase tracking-wider text-cyan-300">Local Analyzer</span>
                  </div>
                  <h3 className="mt-4 text-base font-semibold text-white">{SECURITY_HEADERS_CATALOG_ENTRY.title}</h3>
                  <p className="mt-2 text-xs leading-5 text-slate-400">{SECURITY_HEADERS_CATALOG_ENTRY.description}</p>
                  <Link href={SECURITY_HEADERS_CATALOG_ENTRY.href} className="mt-auto inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-cyan-400/10 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-400 hover:text-slate-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400">
                    Open Security Headers Analyzer <ArrowUpRight className="size-3.5" />
                  </Link>
                </article>

              </div>
            </div>

            {/* Safety Governance Notice */}
            <section className="rounded-2xl border border-emerald-400/20 bg-emerald-400/[0.04] p-5 sm:p-6">
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-1 size-5 shrink-0 text-emerald-400" />
                <div className="text-xs leading-6 text-slate-300 sm:text-sm">
                  <strong className="block text-emerald-200">
                    Security Architecture &amp; Safety Protocol
                  </strong>
                  SentinelX Analysis Lab provides security utilities for analysis, learning,
                  and data sanitization. It does not initiate external network requests,
                  execute code on remote endpoints, scan IP ranges, or provide functional exploit
                  payloads. All operations run locally in your browser.
                </div>
              </div>
            </section>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════════
            TAB 2: IOC DEFANGER & SANITIZER
        ════════════════��═══════════════════════════════════════════════════ */}
        {activeTab === 'defanger' && (
          <div className="mt-4 space-y-6">
            <header>
              <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-emerald-400">
                <Shield className="size-3.5" />
                Security Utility
              </div>
              <h2 className="mt-2 text-2xl font-bold text-white sm:text-3xl">
                IoC Defanger &amp; Sanitizer
              </h2>
              <p className="mt-2 max-w-3xl text-xs leading-6 text-slate-400 sm:text-sm">
                Neutralize suspicious URLs, IP addresses, domains, and email addresses by replacing
                dots and protocol schemes (e.g.{' '}
                <code className="rounded bg-white/5 px-1 py-0.5 text-cyan-300">https://</code> →{' '}
                <code className="rounded bg-white/5 px-1 py-0.5 text-emerald-300">hxxps://</code>
                ,{' '}
                <code className="rounded bg-white/5 px-1 py-0.5 text-cyan-300">.</code> →{' '}
                <code className="rounded bg-white/5 px-1 py-0.5 text-emerald-300">[.]</code>) so
                they can be safely documented without accidental execution or pre-fetching.
              </p>
            </header>

            {/* Mode selector + samples */}
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-white/[0.08] bg-[#0d121c] p-4">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs uppercase tracking-wider text-slate-400">
                  Operation:
                </span>
                <div className="inline-flex rounded-xl bg-black/40 p-1 ring-1 ring-white/10">
                  <button
                    type="button"
                    onClick={() => switchIocMode('defang')}
                    className={`min-h-9 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                      iocMode === 'defang'
                        ? 'bg-emerald-400 text-slate-950 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Defang (Neutralize)
                  </button>
                  <button
                    type="button"
                    onClick={() => switchIocMode('refang')}
                    className={`min-h-9 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                      iocMode === 'refang'
                        ? 'bg-cyan-400 text-slate-950 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Refang (Restore)
                  </button>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-mono text-[10px] uppercase text-slate-500">Samples:</span>
                {SAMPLE_IOCS.map((s) => (
                  <button
                    key={s.label}
                    type="button"
                    onClick={() => handleIocInputChange(s.value)}
                    className="min-h-8 rounded-lg border border-white/10 bg-white/[0.02] px-2.5 py-1 text-xs text-slate-400 transition hover:border-emerald-400/40 hover:text-emerald-300"
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Input / Output */}
            <div className="grid gap-6 lg:grid-cols-2">
              <article className="flex flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 sm:p-6">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="ioc-input"
                    className="font-mono text-xs font-bold uppercase tracking-wider text-slate-400"
                  >
                    Input Indicator(s)
                  </label>
                  <span className="rounded bg-white/5 px-2 py-0.5 font-mono text-[10px] text-slate-400">
                    Detected:{' '}
                    <strong className="text-cyan-300">{iocType}</strong>
                  </span>
                </div>
                <textarea
                  id="ioc-input"
                  value={iocInput}
                  onChange={(e) => handleIocInputChange(e.target.value)}
                  placeholder="Paste URL, IP address, domain, or multi-line list..."
                  rows={8}
                  spellCheck={false}
                  className="mt-3 w-full flex-1 resize-y rounded-xl border border-white/10 bg-[#080b12] p-3 font-mono text-xs leading-6 text-slate-200 outline-none placeholder:text-slate-600 focus:border-emerald-400 focus:ring-1 focus:ring-emerald-400"
                  aria-label="Input indicators to defang or refang"
                />
                <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
                  <span>{iocInput.length} characters</span>
                  <span>UTF-8 Client-Side</span>
                </div>
              </article>

              <article className="flex flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 sm:p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold uppercase tracking-wider text-slate-400">
                      Sanitized Output
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase ${
                        iocMode === 'defang'
                          ? 'bg-emerald-400/10 text-emerald-300'
                          : 'bg-cyan-400/10 text-cyan-300'
                      }`}
                    >
                      {iocMode === 'defang' ? 'Defanged' : 'Refanged'}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={copyIocResult}
                    disabled={!iocOutput}
                    className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-slate-300 transition hover:border-emerald-400/40 hover:text-emerald-200 disabled:cursor-not-allowed disabled:opacity-40"
                    aria-label="Copy sanitized output"
                  >
                    {copiedIoc ? (
                      <Check className="size-3.5 text-emerald-400" />
                    ) : (
                      <Clipboard className="size-3.5" />
                    )}
                    <span>{copiedIoc ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <textarea
                  id="ioc-output"
                  value={iocOutput}
                  readOnly
                  placeholder="Sanitized indicators will appear here..."
                  rows={8}
                  spellCheck={false}
                  className="mt-3 w-full flex-1 resize-y rounded-xl border border-white/10 bg-[#080b12] p-3 font-mono text-xs leading-6 text-emerald-300 outline-none placeholder:text-slate-600"
                  aria-label="Sanitized indicator output"
                />
                <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
                  <span>{iocOutput.length} characters</span>
                  <button
                    type="button"
                    onClick={clearIoc}
                    className="inline-flex items-center gap-1 text-slate-400 transition hover:text-rose-400"
                  >
                    <Eraser className="size-3" /> Clear
                  </button>
                </div>
              </article>
            </div>

            {iocError && (
              <div
                role="alert"
                className="rounded-xl border border-rose-500/20 bg-rose-500/10 p-3 text-xs text-rose-200"
              >
                {iocError}
              </div>
            )}
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════════
            TAB 3: PAYLOAD GENERATOR
        ════════════════════════════════════════════════════════════════════ */}
        {activeTab === 'payload-generator' && (
          <div className="mt-4 space-y-6">
            {/* Header */}
            <header>
              <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-cyan-400">
                <Zap className="size-3.5" />
                Reference Generator
              </div>
              <h2 className="mt-2 text-2xl font-bold text-white sm:text-3xl">Payload Generator</h2>
              <p className="mt-2 max-w-3xl text-xs leading-6 text-slate-400 sm:text-sm">
                Configure a listener IP and port, select a target platform and category, then
                generate a locally-rendered reference template. No code is executed, no network
                connection is made, and no shell is invoked at any point.
              </p>
            </header>

            {/* Reference-only disclaimer banner */}
            <div
              role="note"
              className="flex items-start gap-3 rounded-2xl border border-amber-400/25 bg-amber-400/[0.05] p-4 sm:p-5"
            >
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-400" />
              <p className="text-xs leading-6 text-amber-200 sm:text-sm">
                <strong className="text-amber-300">Reference &amp; educational use only.</strong>{' '}
                Output is a static text template rendered in your browser. It is not executed,
                transmitted, or stored. Use only in authorised environments where you have explicit
                permission to perform connectivity testing.
              </p>
            </div>

            <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
              {/* ── Left: Controls ──────────────────────────────────────────── */}
              <section
                aria-label="Generator configuration"
                className="space-y-5 rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 sm:p-6"
              >
                <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500">
                  Configuration
                </p>

                {/* IP Address */}
                <div>
                  <label
                    htmlFor="pg-ip"
                    className="block text-xs font-semibold text-slate-300"
                  >
                    Listener IP Address
                    <span className="ml-1 font-normal text-slate-500">(IPv4 or IPv6)</span>
                  </label>
                  <input
                    id="pg-ip"
                    type="text"
                    value={pgIP}
                    onChange={(e) => {
                      setPgIP(e.target.value)
                      setPgIPError('')
                    }}
                    placeholder="e.g. 10.0.0.1  or  ::1"
                    spellCheck={false}
                    autoComplete="off"
                    className={`mt-2 w-full rounded-xl border bg-[#080b12] px-3.5 py-3 font-mono text-sm text-slate-200 outline-none placeholder:text-slate-600 transition focus:ring-1 ${
                      pgIPError
                        ? 'border-rose-500/60 focus:border-rose-400 focus:ring-rose-400/30'
                        : 'border-white/10 focus:border-cyan-400 focus:ring-cyan-400/20'
                    }`}
                    aria-describedby={pgIPError ? 'pg-ip-error' : undefined}
                  />
                  {pgIPError && (
                    <p id="pg-ip-error" role="alert" className="mt-1.5 text-xs text-rose-400">
                      {pgIPError}
                    </p>
                  )}
                </div>

                {/* Port */}
                <div>
                  <label htmlFor="pg-port" className="block text-xs font-semibold text-slate-300">
                    Port
                    <span className="ml-1 font-normal text-slate-500">(1 – 65535)</span>
                  </label>
                  <input
                    id="pg-port"
                    type="text"
                    inputMode="numeric"
                    value={pgPort}
                    onChange={(e) => {
                      setPgPort(e.target.value)
                      setPgPortError('')
                    }}
                    placeholder="e.g. 4444"
                    spellCheck={false}
                    autoComplete="off"
                    className={`mt-2 w-full rounded-xl border bg-[#080b12] px-3.5 py-3 font-mono text-sm text-slate-200 outline-none placeholder:text-slate-600 transition focus:ring-1 ${
                      pgPortError
                        ? 'border-rose-500/60 focus:border-rose-400 focus:ring-rose-400/30'
                        : 'border-white/10 focus:border-cyan-400 focus:ring-cyan-400/20'
                    }`}
                    aria-describedby={pgPortError ? 'pg-port-error' : undefined}
                  />
                  {pgPortError && (
                    <p id="pg-port-error" role="alert" className="mt-1.5 text-xs text-rose-400">
                      {pgPortError}
                    </p>
                  )}
                </div>

                {/* Platform */}
                <div>
                  <label
                    htmlFor="pg-platform"
                    className="block text-xs font-semibold text-slate-300"
                  >
                    Target Platform
                  </label>
                  <div className="mt-2 grid grid-cols-3 gap-2">
                    {(['Linux', 'Windows', 'macOS'] as Platform[]).map((p) => (
                      <button
                        key={p}
                        type="button"
                        onClick={() => {
                          setPgPlatform(p)
                          // Reset category if it's not valid for this platform
                          const valid = PAYLOAD_CATEGORIES.filter((c) =>
                            c.platforms.includes(p),
                          )
                          if (!valid.find((c) => c.id === pgCategory)) {
                            setPgCategory(valid[0].id)
                          }
                          setPgOutput('')
                        }}
                        className={`min-h-11 rounded-xl border px-3 py-2 text-xs font-semibold transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 ${
                          pgPlatform === p
                            ? 'border-cyan-400/60 bg-cyan-400/10 text-cyan-200'
                            : 'border-white/10 bg-white/[0.02] text-slate-400 hover:border-white/20 hover:text-slate-200'
                        }`}
                        aria-pressed={pgPlatform === p}
                      >
                        {p === 'Linux' && '🐧 '}
                        {p === 'Windows' && '⊞ '}
                        {p === 'macOS' && '🍎 '}
                        {p}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Category */}
                <div>
                  <label
                    htmlFor="pg-category"
                    className="block text-xs font-semibold text-slate-300"
                  >
                    Payload Category
                  </label>
                  <div className="mt-2 flex flex-col gap-2">
                    {availableCategories.map((cat) => (
                      <button
                        key={cat.id}
                        type="button"
                        onClick={() => {
                          setPgCategory(cat.id)
                          setPgOutput('')
                        }}
                        className={`flex min-h-14 w-full flex-col items-start rounded-xl border px-4 py-3 text-left transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 ${
                          pgCategory === cat.id
                            ? 'border-cyan-400/50 bg-cyan-400/[0.08] text-cyan-100'
                            : 'border-white/10 bg-white/[0.02] text-slate-400 hover:border-white/20 hover:text-slate-200'
                        }`}
                        aria-pressed={pgCategory === cat.id}
                      >
                        <span className="text-xs font-semibold">{cat.label}</span>
                        <span
                          className={`mt-0.5 text-[11px] leading-4 ${pgCategory === cat.id ? 'text-cyan-300/80' : 'text-slate-500'}`}
                        >
                          {cat.description}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex gap-3 pt-1">
                  <button
                    type="button"
                    onClick={handleGenerate}
                    className="inline-flex min-h-11 flex-1 items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-bold text-slate-950 shadow-md shadow-cyan-400/20 transition hover:bg-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
                  >
                    <Zap className="size-4" />
                    Generate Reference
                  </button>
                  <button
                    type="button"
                    onClick={clearPg}
                    className="inline-flex min-h-11 items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-2.5 text-xs font-medium text-slate-400 transition hover:border-white/20 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
                    aria-label="Clear all inputs and output"
                  >
                    <Eraser className="size-4" />
                    Clear
                  </button>
                </div>
              </section>

              {/* ── Right: Output ────────────────────────────────────────────── */}
              <section
                aria-label="Generator output"
                className="flex flex-col rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 sm:p-6"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500">
                      Output
                    </p>
                    <h3 className="mt-0.5 text-sm font-semibold text-white">
                      Generated Reference Template
                    </h3>
                  </div>
                  <div className="flex items-center gap-2">
                    {/* Reference-only badge */}
                    <span className="hidden rounded-full border border-amber-400/20 bg-amber-400/10 px-2.5 py-0.5 font-mono text-[10px] font-semibold text-amber-300 sm:inline-flex">
                      Reference Only
                    </span>
                    {pgOutput && (
                      <button
                        type="button"
                        onClick={copyPgOutput}
                        className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-slate-300 transition hover:border-cyan-400/40 hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
                        aria-label="Copy generated output to clipboard"
                      >
                        {pgCopied ? (
                          <Check className="size-3.5 text-emerald-400" />
                        ) : (
                          <Clipboard className="size-3.5" />
                        )}
                        <span>{pgCopied ? 'Copied' : 'Copy'}</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Output area */}
                {pgOutput ? (
                  <pre
                    tabIndex={0}
                    className="mt-4 min-h-[300px] flex-1 overflow-auto rounded-xl border border-white/[0.08] bg-[#060810] p-4 font-mono text-xs leading-6 text-cyan-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400 sm:text-[13px]"
                    aria-label="Generated reference output"
                  >
                    {pgOutput}
                  </pre>
                ) : (
                  <div className="mt-4 flex min-h-[300px] flex-1 flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-white/10 bg-[#060810] text-center">
                    <Cpu className="size-8 text-slate-600" />
                    <div>
                      <p className="text-sm font-semibold text-slate-400">
                        {!pgIP && !pgPort
                          ? 'Enter IP and port to continue'
                          : 'Press Generate Reference'}
                      </p>
                      <p className="mt-1 max-w-xs text-xs text-slate-600">
                        Configure a listener IP, port, platform, and category above, then click
                        Generate Reference.
                      </p>
                    </div>
                  </div>
                )}

                {pgError && (
                  <div
                    role="alert"
                    className="mt-3 rounded-xl border border-rose-500/20 bg-rose-500/10 p-3 text-xs text-rose-200"
                  >
                    {pgError}
                  </div>
                )}

                {/* Footer info */}
                {pgOutput && (
                  <div className="mt-3 flex items-start gap-2 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
                    <Info className="mt-0.5 size-3.5 shrink-0 text-slate-500" />
                    <p className="text-[11px] leading-5 text-slate-500">
                      This output was generated locally in your browser. No network connection was
                      made and no code was executed. The text above is a reference template for
                      authorised lab or training use only.
                    </p>
                  </div>
                )}
              </section>
            </div>
          </div>
        )}

        {activeTab === 'jwt-decoder' && <SecurityLabJwtPanel />}

        {activeTab === 'ioc-extractor' && <IocExtractor />}

        {activeTab === 'security-headers' && <SecurityHeadersAnalyzer />}

        {/* ── Page footer ───────────────────────────────────────────────────── */}
        <footer className="mt-12 flex flex-col items-center justify-between gap-4 border-t border-white/[0.08] pt-6 text-xs text-slate-500 sm:flex-row">
          <span>
            SentinelX Analysis Lab
          </span>
          <div className="flex items-center gap-4">
            <Link href="/dashboard" className="transition hover:text-cyan-300">
              Dashboard
            </Link>
            <Link href="/hash-tools" className="transition hover:text-cyan-300">
              Hash Converter
            </Link>
            <Link href="/identify-hash" className="transition hover:text-cyan-300">
              Identify Hash
            </Link>
            <Link href="/payload-tools" className="transition hover:text-cyan-300">
              Payload Tools
            </Link>
          </div>
        </footer>
      </div>
    </main>
  )
}
