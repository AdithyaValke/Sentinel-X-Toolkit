'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import Image from 'next/image'
import { usePathname } from 'next/navigation'
import {
  Activity,
  ArrowUpRight,
  ChevronRight,
  Command,
  Fingerprint,
  FlaskConical,
  Hash,
  LayoutDashboard,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  ShieldCheck,
  TerminalSquare,
  X,
} from 'lucide-react'
import { checkBackendHealth } from '@/lib/api'
import { LatestRequest } from '@/lib/latest-request'

const navigation = [
  { label: 'Dashboard', icon: LayoutDashboard, href: '/dashboard' },
  { label: 'Payload Tools', icon: TerminalSquare, href: '/payload-tools' },
  { label: 'Hash Tools', icon: Hash, href: '/hash-tools' },
  { label: 'Identify Hash', icon: Fingerprint, href: '/identify-hash' },
  { label: 'Security Lab', icon: FlaskConical, href: '/security-lab' },
]

const tools = [
  {
    title: 'Hash Converter',
    description: 'Generate secure hashes from raw text with the algorithm of your choice.',
    icon: Hash,
    accent: 'text-cyan-300 bg-cyan-400/10 ring-cyan-300/20',
    href: '/hash-tools',
    tag: 'Converter',
  },
  {
    title: 'Identify Hash Function',
    description: 'Inspect a hash string and review likely algorithms with supporting evidence.',
    icon: Fingerprint,
    accent: 'text-violet-300 bg-violet-400/10 ring-violet-300/20',
    href: '/identify-hash',
    tag: 'Analyzer',
  },
  {
    title: 'Payload Tools',
    description: 'Encode and decode Base64, URL, and Hex data in one focused workspace.',
    icon: TerminalSquare,
    accent: 'text-amber-300 bg-amber-400/10 ring-amber-300/20',
    href: '/payload-tools',
    tag: 'Workbench',
  },
  {
    title: 'Security Lab',
    description: 'Explore practical security utilities and validate suspicious input safely.',
    icon: FlaskConical,
    accent: 'text-emerald-300 bg-emerald-400/10 ring-emerald-300/20',
    href: '/security-lab',
    tag: 'Explore',
  },
]

const activity = [
  { title: 'SHA-256 hash generated', detail: 'Hash Converter', time: '12 min ago', tone: 'bg-cyan-400' },
  { title: 'Hash candidates identified', detail: 'Identify Hash Function', time: 'Yesterday', tone: 'bg-violet-400' },
  { title: 'Base64 payload decoded', detail: 'Payload Tools', time: '2 days ago', tone: 'bg-amber-400' },
]

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link href="/dashboard" className="flex items-center gap-3" aria-label="Payload Workbench dashboard">
      <Image src="/icon.svg" alt="" width={36} height={36} className="size-9 shrink-0 rounded-xl" priority />
      {!compact && (
        <span className="leading-none">
          <span className="block font-mono text-sm font-bold tracking-tight text-slate-100">Payload</span>
          <span className="block font-mono text-[10px] font-medium uppercase tracking-[0.2em] text-cyan-300">Workbench</span>
        </span>
      )}
    </Link>
  )
}

export function DashboardShell() {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [apiStatus, setApiStatus] = useState<'checking' | 'online' | 'offline'>('checking')
  const latestHealth = useRef(new LatestRequest())
  const pathname = usePathname()

  useEffect(() => {
    const request = latestHealth.current.begin()
    checkBackendHealth(request.signal).then((online) => {
      if (latestHealth.current.isCurrent(request.id)) setApiStatus(online ? 'online' : 'offline')
    })
    return () => {
      latestHealth.current.cancel()
    }
  }, [])

  const apiStatusLabel = apiStatus === 'online' ? 'API online' : apiStatus === 'offline' ? 'API offline' : 'Checking API'

  return (
    <main className="min-h-screen bg-[#080b12] text-slate-100 selection:bg-cyan-400/30">
      <div className="flex min-h-screen">
        {mobileOpen && <button aria-label="Close navigation" className="fixed inset-0 z-30 bg-slate-950/70 backdrop-blur-sm lg:hidden" onClick={() => setMobileOpen(false)} />}
        <aside className={`fixed inset-y-0 left-0 z-40 flex w-72 flex-col border-r border-white/[0.07] bg-[#0b0f18] px-4 py-5 transition-transform duration-200 lg:relative lg:z-0 lg:translate-x-0 ${collapsed ? 'lg:w-[84px]' : 'lg:w-72'} ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}`}>
          <div className={`flex items-center ${collapsed ? 'justify-center' : 'justify-between'} px-2`}>
            <Brand compact={collapsed} />
            {!collapsed && <button className="hidden min-h-11 min-w-11 items-center justify-center rounded-lg p-2 text-slate-500 transition hover:bg-white/5 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 lg:flex" onClick={() => setCollapsed(true)} aria-label="Collapse sidebar"><PanelLeftClose className="size-4" /></button>}
            <button className="flex min-h-11 min-w-11 items-center justify-center rounded-lg p-2 text-slate-500 transition hover:bg-white/5 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Close sidebar"><X className="size-4" /></button>
          </div>
          {collapsed && <button className="mx-auto mt-6 hidden min-h-11 min-w-11 items-center justify-center rounded-lg p-2 text-slate-500 transition hover:bg-white/5 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 lg:flex" onClick={() => setCollapsed(false)} aria-label="Expand sidebar"><PanelLeftOpen className="size-4" /></button>}
          <nav className="mt-10 flex flex-1 flex-col gap-1" aria-label="Main navigation">
            {!collapsed && <p className="mb-3 px-3 font-mono text-[10px] uppercase tracking-[0.2em] text-slate-600">Workspace</p>}
            {navigation.map(({ label, icon: Icon, href }) => {
              const active = pathname === href || (href !== '/dashboard' && pathname.startsWith(`${href}/`))
              return <Link key={label} href={href} onClick={() => setMobileOpen(false)} title={collapsed ? label : undefined} aria-current={active ? 'page' : undefined} className={`group flex min-h-11 items-center gap-3 rounded-xl px-3 py-3 text-sm transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 ${active ? 'bg-cyan-400/[0.11] text-cyan-200 shadow-[inset_2px_0_0_#22d3ee]' : 'text-slate-500 hover:bg-white/[0.04] hover:text-slate-200'} ${collapsed ? 'justify-center' : ''}`}>
                <Icon className={`size-[18px] shrink-0 ${active ? 'text-cyan-300' : 'text-slate-600 group-hover:text-slate-300'}`} />
                {!collapsed && <span>{label}</span>}
              </Link>
            })}
          </nav>
          <div className="border-t border-white/[0.07] pt-4">
            {!collapsed && <div className="mt-5 rounded-xl border border-white/[0.07] bg-white/[0.025] p-3"><div className="flex items-center gap-2"><span className={`size-2 rounded-full ${apiStatus === 'online' ? 'bg-emerald-400' : apiStatus === 'offline' ? 'bg-rose-400' : 'bg-amber-400'}`} /><span className={`font-mono text-[10px] uppercase tracking-wider ${apiStatus === 'online' ? 'text-emerald-300' : apiStatus === 'offline' ? 'text-rose-300' : 'text-amber-300'}`}>{apiStatusLabel}</span></div><p className="mt-2 text-xs leading-5 text-slate-600">Health check: Flask /health endpoint.</p></div>}
          </div>
        </aside>

        <section className="min-w-0 flex-1">
          <header className="flex h-[76px] items-center justify-between border-b border-white/[0.07] px-5 sm:px-8 lg:px-10">
            <div className="flex items-center gap-3"><button className="flex min-h-11 min-w-11 items-center justify-center rounded-lg p-2 text-slate-400 hover:bg-white/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu className="size-5" /></button><div><p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-600">Workspace / Overview</p><h1 className="mt-1 text-sm font-semibold text-slate-200 sm:text-base">Dashboard</h1></div></div>
            <div className="hidden items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.025] px-3 py-2 sm:flex"><Search className="size-4 text-slate-600" /><span className="w-36 text-xs text-slate-600">Search tools...</span><kbd className="flex items-center gap-0.5 rounded border border-white/10 px-1.5 py-0.5 font-mono text-[9px] text-slate-600"><Command className="size-2.5" />K</kbd></div>
          </header>

          <div className="mx-auto max-w-[1440px] px-5 py-8 sm:px-8 sm:py-10 lg:px-10 lg:py-12">
            <section className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-[#101a29] via-[#0d1420] to-[#0b101a] p-6 sm:p-8 lg:p-10"><div className="absolute -right-24 -top-32 size-80 rounded-full bg-cyan-400/[0.07] blur-3xl" /><div className="relative max-w-2xl"><div className="mb-5 flex items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-[0.22em] text-cyan-300"><span className="size-1.5 rounded-full bg-cyan-300" />Secure environment</div><h2 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Your Security Workspace</h2><p className="mt-4 max-w-xl text-sm leading-6 text-slate-400 sm:text-base">A focused command center for inspecting payloads, converting hashes, and validating security signals without leaving your workflow.</p><div className="mt-7 flex flex-wrap gap-3"><Link href="/payload-tools" className="inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300">Open Payload Tools <ArrowUpRight className="size-4" /></Link><span className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-4 py-2.5 font-mono text-xs text-slate-400"><span className={`size-1.5 rounded-full ${apiStatus === 'online' ? 'bg-emerald-400' : apiStatus === 'offline' ? 'bg-rose-400' : 'bg-amber-400'}`} />{apiStatusLabel}</span></div></div></section>

            <div className="mt-10 flex items-end justify-between"><div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-300">Quick access</p><h2 className="mt-2 text-xl font-semibold text-white">Choose a tool to get started</h2></div><Link href="/payload-tools" className="hidden items-center gap-1 text-xs text-slate-500 transition hover:text-cyan-300 sm:flex">View Payload Tools <ChevronRight className="size-4" /></Link></div>
            <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{tools.map(({ title, description, icon: Icon, accent, href, tag }) => <Link key={title} href={href} className="group rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 transition duration-200 hover:-translate-y-1 hover:border-cyan-300/30 hover:bg-[#101a27] hover:shadow-[0_14px_40px_rgba(0,0,0,0.25)]"><div className="flex items-start justify-between"><span className={`flex size-10 items-center justify-center rounded-xl ring-1 ${accent}`}><Icon className="size-5" /></span><ArrowUpRight className="size-4 text-slate-700 transition group-hover:text-cyan-300" /></div><p className="mt-5 font-mono text-[10px] uppercase tracking-[0.16em] text-slate-600">{tag}</p><h3 className="mt-2 font-semibold text-slate-100">{title}</h3><p className="mt-2 min-h-12 text-sm leading-5 text-slate-500">{description}</p><div className="mt-5 flex items-center gap-2 text-xs font-medium text-cyan-300 opacity-0 transition group-hover:opacity-100">Launch tool <ChevronRight className="size-3" /></div></Link>)}</div>

            <section className="mt-10 grid gap-5 lg:grid-cols-[1.2fr_0.8fr]"><div className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 sm:p-6"><div className="flex items-center justify-between"><div><p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-600">Sample data</p><h2 className="mt-2 text-lg font-semibold text-white">Recent activity</h2></div><Activity className="size-5 text-slate-600" /></div><div className="mt-5 flex flex-col">{activity.map((item, index) => <div key={item.title} className="flex items-center gap-3 border-t border-white/[0.06] py-4 first:border-0 first:pt-0 last:pb-0"><span className={`size-2 shrink-0 rounded-full ${item.tone}`} /><div className="min-w-0 flex-1"><p className="truncate text-sm text-slate-300">{item.title}</p><p className="mt-1 text-xs text-slate-600">{item.detail}</p></div><time className="shrink-0 font-mono text-[10px] text-slate-600">{item.time}</time></div>)}</div></div><div className="rounded-2xl border border-white/[0.08] bg-[#0d121c] p-5 sm:p-6"><p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-600">Workspace status</p><h2 className="mt-2 text-lg font-semibold text-white">Ready when you are</h2><p className="mt-3 text-sm leading-6 text-slate-500">Your tools run through the existing Flask API. Activity shown here is sample data until persistence is added.</p><div className="mt-6 flex items-center gap-3 rounded-xl border border-emerald-400/15 bg-emerald-400/[0.06] p-3"><span className="flex size-8 items-center justify-center rounded-lg bg-emerald-400/10 text-emerald-300"><ShieldCheck className="size-4" /></span><div><p className="text-xs font-medium text-emerald-200">Protected workspace</p><p className="mt-0.5 font-mono text-[10px] text-emerald-300/60">No session required</p></div></div></div></section>
          </div>
        </section>
      </div>
    </main>
  )
}


