'use client'

import Link from 'next/link'
import { Activity, ArrowUpRight, ChevronRight, FileJson, FlaskConical, FolderKanban, GitBranch, ShieldCheck, TerminalSquare, Hash, Fingerprint } from 'lucide-react'
import { useApiStatus } from '@/components/app-shell'
import { useSyncExternalStore } from 'react'
import { getActivityServerSnapshot, getActivitySnapshot, localActivityStore } from '@/lib/activity'

const commonTools = [
  { title: 'Payload Tools', description: 'Encode and decode Base64, URL, and Hex data.', icon: TerminalSquare, accent: 'dashboard-icon-amber', href: '/payload-tools' },
  { title: 'Hash Tools', description: 'Generate MD5, SHA-1, SHA-2, SHA-3, and SHAKE digests.', icon: Hash, accent: 'dashboard-icon-cyan', href: '/hash-tools' },
  { title: 'JSON Formatter', description: 'Validate, format, and minify JSON locally in your browser.', icon: FileJson, accent: 'dashboard-icon-emerald', href: '/json-formatter' },
  { title: 'Identify Hash', description: 'Review likely algorithms for a hash string.', icon: Fingerprint, accent: 'dashboard-icon-violet', href: '/identify-hash' },
]

export function DashboardShell() {
  const apiStatus = useApiStatus()
  const activity = useSyncExternalStore(localActivityStore.subscribe, getActivitySnapshot, getActivityServerSnapshot)
  const apiStatusLabel = apiStatus === 'online' ? 'API online' : apiStatus === 'offline' ? 'API offline' : 'Checking API'

  return (
    <main className="dashboard-page">
      <div className="dashboard-container">
        <section className="dashboard-hero" aria-labelledby="workspace-heading">
          <div className="dashboard-hero-grid" aria-hidden="true" /><div className="dashboard-hero-glow" aria-hidden="true" />
          <div className="dashboard-hero-content"><div className="dashboard-eyebrow"><span className="dashboard-eyebrow-dot" />Secure environment</div><h1 id="workspace-heading" className="dashboard-hero-title">Your Security Workspace</h1><p className="dashboard-hero-copy">A focused command center for inspecting payloads, converting hashes, and building repeatable security workflows.</p><div className="dashboard-hero-actions"><span className="dashboard-status-pill"><span className={`dashboard-status-dot ${apiStatus === 'online' ? 'dashboard-status-online' : apiStatus === 'offline' ? 'dashboard-status-offline' : 'dashboard-status-checking'}`} />{apiStatusLabel}</span></div></div>
          <div className="dashboard-hero-mark" aria-hidden="true"><ShieldCheck /><span>LOCAL<br />WORKSPACE</span></div>
        </section>

        <section aria-labelledby="common-access-heading">
          <div className="dashboard-section-heading"><div><p className="dashboard-section-kicker">Everyday utilities</p><h2 id="common-access-heading">Common Tools</h2></div><Link href="/common-tools" className="dashboard-section-link">View all Common Tools <ChevronRight aria-hidden="true" /></Link></div>
          <p className="mt-2 max-w-2xl text-sm text-slate-500">Everyday utilities for encoding, hashing, identification, and conversion.</p>
          <div className="dashboard-tool-grid dashboard-tool-grid-three">{commonTools.map(({ title, description, icon: Icon, accent, href }) => <Link key={title} href={href} className="dashboard-tool-card"><div className="dashboard-tool-card-top"><span className={`dashboard-tool-icon ${accent}`}><Icon aria-hidden="true" /></span><ArrowUpRight className="dashboard-tool-arrow" aria-hidden="true" /></div><p className="dashboard-tool-tag">Common utility</p><h3>{title}</h3><p className="dashboard-tool-description">{description}</p><span className="dashboard-tool-cta mt-auto">Launch tool <ChevronRight aria-hidden="true" /></span></Link>)}</div>
        </section>

        <div className="mt-10 grid gap-4 lg:grid-cols-3">
          <Link href="/chain-builder" className="dashboard-panel group"><div className="flex items-start justify-between"><span className="dashboard-tool-icon dashboard-icon-cyan"><GitBranch aria-hidden="true" /></span><ArrowUpRight className="dashboard-tool-arrow" aria-hidden="true" /></div><p className="dashboard-section-kicker mt-5">Workflows</p><h2>Chain Builder</h2><p className="dashboard-status-copy">Build repeatable workflows by chaining SentinelX tools together.</p><span className="dashboard-tool-cta">Open Chain Builder <ChevronRight aria-hidden="true" /></span></Link>
          <Link href="/security-lab" className="dashboard-panel group"><div className="flex items-start justify-between"><span className="dashboard-tool-icon dashboard-icon-emerald"><FlaskConical aria-hidden="true" /></span><ArrowUpRight className="dashboard-tool-arrow" aria-hidden="true" /></div><p className="dashboard-section-kicker mt-5">Advanced analysis</p><h2>Analysis Lab</h2><p className="dashboard-status-copy">Explore advanced security analysis tools and validate suspicious input safely.</p><span className="dashboard-tool-cta">Open Analysis Lab <ChevronRight aria-hidden="true" /></span></Link>
          <Link href="/investigations" className="dashboard-panel group"><div className="flex items-start justify-between"><span className="dashboard-tool-icon dashboard-icon-violet"><FolderKanban aria-hidden="true" /></span><ArrowUpRight className="dashboard-tool-arrow" aria-hidden="true" /></div><p className="dashboard-section-kicker mt-5">Case management</p><h2>Investigations</h2><p className="dashboard-status-copy">Persistent security cases, IOCs, findings, evidence, and timeline.</p><span className="dashboard-tool-cta">Open Investigations <ChevronRight aria-hidden="true" /></span></Link>
        </div>

        <section className="dashboard-lower-grid" aria-label="Workspace overview"><div className="dashboard-panel"><div className="dashboard-panel-heading"><div><p className="dashboard-section-kicker">This browser</p><h2>Recent activity</h2></div><div className="flex items-center gap-3"><button type="button" className="dashboard-section-link" disabled={!activity.length} onClick={() => { if (window.confirm('Clear recent activity from this browser?')) localActivityStore.clear() }}>Clear activity</button><Activity aria-hidden="true" /></div></div><div className="dashboard-activity-list" aria-live="polite">{activity.length ? activity.map((item) => <div key={item.id} className="dashboard-activity-row"><span className={`dashboard-activity-dot ${item.outcome === 'success' ? 'dashboard-dot-cyan' : 'dashboard-dot-amber'}`} /><div className="dashboard-activity-copy min-w-0"><p>{item.description}</p><span>{item.tool} · {item.operation} · {item.outcome}</span></div><time dateTime={item.timestamp}>{new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(item.timestamp))}</time></div>) : <p className="py-5 text-sm text-muted-foreground">Completed tool operations will appear here.</p>}</div></div><div className="dashboard-panel"><p className="dashboard-section-kicker">Workspace status</p><h2>Ready when you are</h2><p className="dashboard-status-copy">Activity is stored in this browser only.</p><div className="dashboard-protected"><span><ShieldCheck aria-hidden="true" /></span><div><p>Protected workspace</p><small>No session required</small></div></div></div></section>
      </div>
    </main>
  )
}
