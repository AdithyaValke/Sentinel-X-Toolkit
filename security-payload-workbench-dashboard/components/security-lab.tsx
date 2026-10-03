'use client'

import { useState } from 'react'
import Link from 'next/link'
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronRight,
  Clipboard,
  Code2,
  Cpu,
  Eraser,
  FileCode,
  Fingerprint,
  FlaskConical,
  Hash,
  Info,
  Layers,
  Lock,
  Monitor,
  Radio,
  RefreshCw,
  Shield,
  ShieldCheck,
  Terminal,
  TerminalSquare,
  Wifi,
  Zap,
} from 'lucide-react'

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
      'Simple HTTP GET/HEAD probe to check HTTP/HTTPS reachability on the configured IP and port.',
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
          `try {`,
          `    $client.Connect($target, $port)`,
          `    Write-Host "[$( Get-Date -f 'HH:mm:ss' )] TCP $target:${portNum} — REACHABLE" -ForegroundColor Green`,
          `} catch {`,
          `    Write-Host "[$( Get-Date -f 'HH:mm:ss' )] TCP $target:${portNum} — UNREACHABLE: $_" -ForegroundColor Red`,
          `} finally {`,
          `    $client.Dispose()`,
          `}`,
        ].join('\n')
      }
      // Linux / macOS (bash)
      return [
        `# [REFERENCE ONLY — NOT FOR UNAUTHORIZED USE]`,
        `# Bash TCP connectivity test to ${ip}:${portNum}`,
        `#`,
        `# Purpose: Verify that TCP port ${portNum} is reachable at ${ip}`,
        `# Uses /dev/tcp (bash built-in) — no external binary required.`,
        `# This probes only — it does not execute any remote code.`,
        ``,
        `TARGET="${ip}"`,
        `PORT=${portNum}`,
        `TIMEOUT=5`,
        ``,
        `if (echo >/dev/tcp/"$TARGET"/"$PORT") 2>/dev/null; then`,
        `    echo "$(date +%H:%M:%S) TCP $TARGET:$PORT — REACHABLE"`,
        `else`,
        `    echo "$(date +%H:%M:%S) TCP $TARGET:$PORT — UNREACHABLE (timeout: ${portNum}s)"`,
        `fi`,
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
        `# socat OPENSSL-LISTEN:<LOCAL_PORT>,cert=server.pem,verify=0,fork \\`,
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
          `# Windows PowerShell HTTP reachability probe for http://${ip}:${portNum}/`,
          `#`,
          `# Sends a HEAD request and reports HTTP status — no data is posted.`,
          ``,
          `$url = "http://${ip}:${portNum}/"`,
          `try {`,
          `    $resp = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 10 -UseBasicParsing`,
          `    Write-Host "HTTP $($resp.StatusCode) — $url reachable" -ForegroundColor Green`,
          `} catch {`,
          `    Write-Host "FAILED — $url unreachable: $_" -ForegroundColor Red`,
          `}`,
        ].join('\n')
      }
      // Linux / macOS
      return [
        `# [REFERENCE ONLY — NOT FOR UNAUTHORIZED USE]`,
        `# curl HTTP reachability probe for http://${ip}:${portNum}/`,
        `#`,
        `# -s  silent  -o /dev/null  discard body  -w  write status code`,
        `# No data is posted; this is a GET/HEAD reachability check only.`,
        ``,
        `curl -s -o /dev/null -w "HTTP %{http_code} — ${ip}:${portNum}\\n" \\`,
        `     --max-time 10 \\`,
        `     "http://${ip}:${portNum}/"`,
      ].join('\n')
    }

    default:
      return ''
  }
}

// ─── Validation ──────────────────────────────────────────────────────────────

function validateIPv4(ip: string): boolean {
  return /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(ip)
}

function validateIPv6(ip: string): boolean {
  // Covers full, compressed, and loopback IPv6 — including common bracketed forms stripped beforehand
  return /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^(?:[0-9a-fA-F]{1,4}:)*:[0-9a-fA-F]{1,4}$|^::$/.test(
    ip,
  )
}

function validatePort(port: string): { valid: boolean; message?: string } {
  if (!port.trim()) return { valid: false, message: 'Port is required.' }
  const n = Number(port)
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    return { valid: false, message: 'Port must be an integer between 1 and 65535.' }
  }
  return { valid: true }
}

function validateIP(ip: string): { valid: boolean; message?: string } {
  const trimmed = ip.trim()
  if (!trimmed) return { valid: false, message: 'IP address is required.' }
  if (validateIPv4(trimmed) || validateIPv6(trimmed)) return { valid: true }
  return {
    valid: false,
    message:
      'Enter a valid IPv4 (e.g. 10.0.0.1) or IPv6 (e.g. ::1) address. Hostnames are not accepted.',
  }
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

export function SecurityLab() {
  const [activeTab, setActiveTab] = useState<
    'overview' | 'defanger' | 'payload-generator' | 'planned'
  >('overview')

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
      } else {
        let r = text.replace(/hxxps:\/\//gi, 'https://')
        r = r.replace(/hxxp:\/\//gi, 'http://')
        r = r.replace(/fxp:\/\//gi, 'ftp://')
        r = r.replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
        r = r.replace(/\[at\]|\(@\)|\{@\}|\[AT\]/gi, '@')
        r = r.replace(/\[:\/\/\]/g, '://')
        setIocOutput(r)
      }
    } catch {
      setIocError('An error occurred while sanitizing the indicators.')
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
      return
    }
    setPgError('')
    const result = generatePayload(pgIP.trim(), pgPort.trim(), pgPlatform, pgCategory)
    setPgOutput(result)
    setPgCopied(false)
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
      {/* ── Sticky header ─────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-30 border-b border-white/[0.07] bg-[#0b0f18]/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3.5 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <Link
              href="/dashboard"
              className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-2 text-xs font-medium text-slate-300 transition hover:border-cyan-300/40 hover:bg-white/[0.06] hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
              aria-label="Back to dashboard"
            >
              <ArrowLeft className="size-4" />
              <span>Back to Dashboard</span>
            </Link>
            <div className="hidden h-5 w-px bg-white/10 sm:block" />
            <span className="hidden font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500 sm:block">
              Workspace / Security Lab
            </span>
          </div>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-emerald-300">
            <span className="size-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(74,222,128,0.8)]" />
            Isolated Lab
          </span>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 sm:py-8 lg:px-8 lg:py-10">
        {/* ── Hero ──────────────────────────────────────────────────────────── */}
        <section className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-[#101928] via-[#0d1422] to-[#0a0e17] p-6 sm:p-8 lg:p-10">
          <div className="pointer-events-none absolute -right-24 -top-32 size-80 rounded-full bg-emerald-400/[0.07] blur-3xl" />
          <div className="relative max-w-3xl">
            <div className="mb-4 inline-flex items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 font-mono text-xs font-semibold text-emerald-300">
              <FlaskConical className="size-3.5" />
              Educational &amp; Security Analysis
            </div>
            <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl lg:text-5xl">
              Security <span className="text-emerald-400">Lab</span>
            </h1>
            <p className="mt-4 text-sm leading-6 text-slate-300 sm:text-base sm:leading-7">
              An interactive defensive analysis environment for indicator sanitization (IoC
              defanging), reference payload generation, and security tooling — without executing
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
        </section>

        {/* ── Tab Navigation ────────────────────────────────────────────────── */}
        <nav
          aria-label="Security Lab navigation tabs"
          className="mt-8 flex flex-wrap gap-2 border-b border-white/[0.08] pb-4"
        >
          {(
            [
              { id: 'overview', label: 'Overview & Catalog' },
              { id: 'defanger', label: 'IoC Defanger & Sanitizer' },
              { id: 'payload-generator', label: 'Payload Generator' },
              { id: 'planned', label: 'Planned Modules' },
            ] as const
          ).map(({ id, label }) => (
            <button
              key={id}
              type="button"
              onClick={() => setActiveTab(id)}
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
        </nav>

        {/* ════════════════════════════════════════════════════════════════════
            TAB 1: OVERVIEW & CATALOG
        ════════════════════════════════════════════════════════════════════ */}
        {activeTab === 'overview' && (
          <div className="mt-8 space-y-10">
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

              <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {/* Card: IoC Defanger */}
                <article className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-6 transition duration-200 hover:border-emerald-400/40 hover:bg-[#101724]">
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
                    onClick={() => setActiveTab('defanger')}
                    className="mt-6 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-emerald-400/10 px-4 py-2 text-xs font-semibold text-emerald-300 transition hover:bg-emerald-400 hover:text-slate-950"
                  >
                    Open Defanger <ArrowRight className="size-3.5" />
                  </button>
                </article>

                {/* Card: Payload Generator */}
                <article className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-6 transition duration-200 hover:border-cyan-400/40 hover:bg-[#101724]">
                  <div className="flex items-start justify-between">
                    <span className="flex size-10 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/20">
                      <Zap className="size-5" />
                    </span>
                    <span className="rounded bg-cyan-400/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-cyan-300">
                      Reference Generator
                    </span>
                  </div>
                  <h3 className="mt-4 text-base font-semibold text-white">Payload Generator</h3>
                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    Generate connectivity-test and reference templates for a configured IP and
                    port. Client-side only — no network calls are made.
                  </p>
                  <button
                    type="button"
                    onClick={() => setActiveTab('payload-generator')}
                    className="mt-6 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-cyan-400/10 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-400 hover:text-slate-950"
                  >
                    Open Generator <ArrowRight className="size-3.5" />
                  </button>
                </article>

                {/* Card: Identify Hash Function */}
                <article className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-6 transition duration-200 hover:border-violet-400/40 hover:bg-[#101724]">
                  <div className="flex items-start justify-between">
                    <span className="flex size-10 items-center justify-center rounded-xl bg-violet-400/10 text-violet-300 ring-1 ring-violet-400/20">
                      <Fingerprint className="size-5" />
                    </span>
                    <span className="rounded bg-violet-400/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-violet-300">
                      Analyzer
                    </span>
                  </div>
                  <h3 className="mt-4 text-base font-semibold text-white">
                    Identify Hash Function
                  </h3>
                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    Inspect unknown cryptographic hashes, match formats (MD5, SHA-256, bcrypt),
                    and review algorithmic confidence.
                  </p>
                  <Link
                    href="/identify-hash"
                    className="mt-6 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-violet-400/10 px-4 py-2 text-xs font-semibold text-violet-300 transition hover:bg-violet-400 hover:text-slate-950"
                  >
                    Launch Analyzer <ArrowUpRight className="size-3.5" />
                  </Link>
                </article>

                {/* Card: Hash Converter */}
                <article className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-6 transition duration-200 hover:border-cyan-400/40 hover:bg-[#101724]">
                  <div className="flex items-start justify-between">
                    <span className="flex size-10 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/20">
                      <Hash className="size-5" />
                    </span>
                    <span className="rounded bg-cyan-400/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-cyan-300">
                      Converter
                    </span>
                  </div>
                  <h3 className="mt-4 text-base font-semibold text-white">Hash Converter</h3>
                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    Generate MD5, SHA-256, and SHA-512 cryptographic digests from raw input
                    through the backend service.
                  </p>
                  <Link
                    href="/hash-tools"
                    className="mt-6 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-cyan-400/10 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-400 hover:text-slate-950"
                  >
                    Open Converter <ArrowUpRight className="size-3.5" />
                  </Link>
                </article>

                {/* Card: Payload Encoding Workbench */}
                <article className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-6 transition duration-200 hover:border-amber-400/40 hover:bg-[#101724]">
                  <div className="flex items-start justify-between">
                    <span className="flex size-10 items-center justify-center rounded-xl bg-amber-400/10 text-amber-300 ring-1 ring-amber-400/20">
                      <TerminalSquare className="size-5" />
                    </span>
                    <span className="rounded bg-amber-400/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-amber-300">
                      Workbench
                    </span>
                  </div>
                  <h3 className="mt-4 text-base font-semibold text-white">
                    Payload Encoding Workbench
                  </h3>
                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    Encode and decode Base64, URL percent-encoding, and Hexadecimal representations
                    with live validation.
                  </p>
                  <Link
                    href="/?operation=base64-encode"
                    className="mt-6 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-amber-400/10 px-4 py-2 text-xs font-semibold text-amber-300 transition hover:bg-amber-400 hover:text-slate-950"
                  >
                    Open Workbench <ArrowUpRight className="size-3.5" />
                  </Link>
                </article>

                {/* Card: Planned Modules */}
                <article className="rounded-2xl border border-dashed border-white/20 bg-white/[0.015] p-6">
                  <div className="flex items-start justify-between">
                    <span className="flex size-10 items-center justify-center rounded-xl bg-slate-800 text-slate-400">
                      <Layers className="size-5" />
                    </span>
                    <span className="rounded bg-white/5 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-slate-400">
                      Roadmap
                    </span>
                  </div>
                  <h3 className="mt-4 text-base font-semibold text-slate-300">
                    Upcoming Security Modules
                  </h3>
                  <p className="mt-2 text-xs leading-5 text-slate-500">
                    PCAP frame analysis and YARA rule syntax verification are planned for
                    subsequent releases.
                  </p>
                  <button
                    type="button"
                    onClick={() => setActiveTab('planned')}
                    className="mt-6 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl border border-white/10 px-4 py-2 text-xs font-medium text-slate-400 transition hover:border-white/20 hover:text-slate-200"
                  >
                    View Roadmap <ChevronRight className="size-3.5" />
                  </button>
                </article>
              </div>
            </div>

            {/* Safety Governance Notice */}
            <section className="rounded-2xl border border-emerald-400/20 bg-emerald-400/[0.04] p-5 sm:p-6">
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-1 size-5 shrink-0 text-emerald-400" />
                <div className="text-xs leading-6 text-slate-300 sm:text-sm">
                  <strong className="block text-emerald-200">
                    Defensive Architecture &amp; Safety Protocol
                  </strong>
                  Payload Workbench Security Lab is built strictly for defensive cybersecurity
                  education and data sanitization. It does not initiate external network requests,
                  execute code on remote endpoints, scan IP ranges, or provide functional exploit
                  payloads. All operations run locally in your browser.
                </div>
              </div>
            </section>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════════
            TAB 2: IOC DEFANGER & SANITIZER
        ════════════════════════════════════════════════════════════════════ */}
        {activeTab === 'defanger' && (
          <div className="mt-8 space-y-6">
            <header>
              <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-emerald-400">
                <Shield className="size-3.5" />
                Defensive Utility
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
          <div className="mt-8 space-y-6">
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

        {/* ════════════════════════════════════════════════════════════════════
            TAB 4: PLANNED MODULES
        ════════════════════════════════════════════════════════════════════ */}
        {activeTab === 'planned' && (
          <div className="mt-8 space-y-6">
            <header>
              <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-slate-500">
                <Layers className="size-3.5" />
                Security Roadmap
              </div>
              <h2 className="mt-2 text-2xl font-bold text-white sm:text-3xl">
                Upcoming Security Modules
              </h2>
              <p className="mt-2 max-w-3xl text-xs leading-6 text-slate-400 sm:text-sm">
                These modules are under active design for future phases of Payload Workbench. They
                are clearly marked as unreleased and non-functional in keeping with our strict
                truthful-state policy.
              </p>
            </header>

            <div className="grid gap-6 sm:grid-cols-2">
              {/* Planned: PCAP Inspector */}
              <article className="rounded-2xl border border-dashed border-white/20 bg-[#0d121c]/60 p-6 sm:p-8">
                <div className="flex items-start justify-between">
                  <div className="flex size-12 items-center justify-center rounded-xl bg-slate-800 text-cyan-300">
                    <Radio className="size-6" />
                  </div>
                  <span className="rounded-full border border-amber-400/20 bg-amber-400/10 px-3 py-1 font-mono text-[10px] font-semibold text-amber-300">
                    Phase 2 Planned
                  </span>
                </div>
                <h3 className="mt-5 text-lg font-bold text-white">
                  Offline PCAP &amp; Frame Inspector
                </h3>
                <p className="mt-2 text-xs leading-6 text-slate-400">
                  Dissect client-side packet captures, inspect TLS handshake ClientHello
                  extensions, and review Ethernet/IP headers offline without sending telemetry to
                  external services.
                </p>
                <div className="mt-6 rounded-xl border border-white/5 bg-black/40 p-6 text-center">
                  <Wifi className="mx-auto size-8 text-slate-600" />
                  <p className="mt-2 text-xs font-semibold text-slate-300">
                    Module Not Implemented Yet
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Scheduled for Phase 2. Core packet decoding engine is in development.
                  </p>
                  <button
                    type="button"
                    disabled
                    className="mt-4 inline-flex min-h-10 cursor-not-allowed items-center justify-center rounded-xl border border-white/10 px-4 py-2 text-xs text-slate-500"
                  >
                    Feature in Development
                  </button>
                </div>
              </article>

              {/* Planned: YARA Validator */}
              <article className="rounded-2xl border border-dashed border-white/20 bg-[#0d121c]/60 p-6 sm:p-8">
                <div className="flex items-start justify-between">
                  <div className="flex size-12 items-center justify-center rounded-xl bg-slate-800 text-violet-300">
                    <FileCode className="size-6" />
                  </div>
                  <span className="rounded-full border border-amber-400/20 bg-amber-400/10 px-3 py-1 font-mono text-[10px] font-semibold text-amber-300">
                    Phase 2 Planned
                  </span>
                </div>
                <h3 className="mt-5 text-lg font-bold text-white">
                  YARA Rule Syntax Validator
                </h3>
                <p className="mt-2 text-xs leading-6 text-slate-400">
                  Verify YARA signature formatting, string definitions, and conditional clauses
                  against standard syntax specifications to accelerate incident-response rule
                  authoring.
                </p>
                <div className="mt-6 rounded-xl border border-white/5 bg-black/40 p-6 text-center">
                  <Code2 className="mx-auto size-8 text-slate-600" />
                  <p className="mt-2 text-xs font-semibold text-slate-300">
                    Module Not Implemented Yet
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Scheduled for Phase 2. WebAssembly-based YARA AST parser is being evaluated.
                  </p>
                  <button
                    type="button"
                    disabled
                    className="mt-4 inline-flex min-h-10 cursor-not-allowed items-center justify-center rounded-xl border border-white/10 px-4 py-2 text-xs text-slate-500"
                  >
                    Feature in Development
                  </button>
                </div>
              </article>
            </div>
          </div>
        )}

        {/* ── Page footer ───────────────────────────────────────────────────── */}
        <footer className="mt-12 flex flex-col items-center justify-between gap-4 border-t border-white/[0.08] pt-6 text-xs text-slate-500 sm:flex-row">
          <span>
            Payload Workbench Security Lab &bull; Defensive Analysis &bull; MIT License
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
            <Link href="/?operation=base64-encode" className="transition hover:text-cyan-300">
              Workbench
            </Link>
          </div>
        </footer>
      </div>
    </main>
  )
}
