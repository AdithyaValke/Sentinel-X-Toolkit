'use client'

import Link from 'next/link'
import { Activity, ArrowUpRight, ChevronRight, Fingerprint, FlaskConical, Hash, ShieldCheck, TerminalSquare } from 'lucide-react'
import { useApiStatus } from '@/components/app-shell'

const tools = [
  { title: 'Hash Converter', description: 'Generate secure hashes from raw text with the algorithm of your choice.', icon: Hash, accent: 'dashboard-icon-cyan', href: '/hash-tools', tag: 'Converter' },
  { title: 'Identify Hash Function', description: 'Inspect a hash string and review likely algorithms with supporting evidence.', icon: Fingerprint, accent: 'dashboard-icon-violet', href: '/identify-hash', tag: 'Analyzer' },
  { title: 'Payload Tools', description: 'Encode and decode Base64, URL, and Hex data in one focused workspace.', icon: TerminalSquare, accent: 'dashboard-icon-amber', href: '/payload-tools', tag: 'Workbench' },
  { title: 'Security Lab', description: 'Explore practical security utilities and validate suspicious input safely.', icon: FlaskConical, accent: 'dashboard-icon-emerald', href: '/security-lab', tag: 'Explore' },
]

const activity = [
  { title: 'SHA-256 hash generated', detail: 'Hash Converter', time: '12 min ago', tone: 'dashboard-dot-cyan' },
  { title: 'Hash candidates identified', detail: 'Identify Hash Function', time: 'Yesterday', tone: 'dashboard-dot-violet' },
  { title: 'Base64 payload decoded', detail: 'Payload Tools', time: '2 days ago', tone: 'dashboard-dot-amber' },
]

export function DashboardShell() {
  const apiStatus = useApiStatus()
  const apiStatusLabel = apiStatus === 'online' ? 'API online' : apiStatus === 'offline' ? 'API offline' : 'Checking API'

  return (
    <main className="dashboard-page">
      <div className="dashboard-container">
        <section className="dashboard-hero" aria-labelledby="workspace-heading">
          <div className="dashboard-hero-grid" aria-hidden="true" />
          <div className="dashboard-hero-glow" aria-hidden="true" />
          <div className="dashboard-hero-content">
            <div className="dashboard-eyebrow"><span className="dashboard-eyebrow-dot" />Secure environment</div>
            <h2 id="workspace-heading" className="dashboard-hero-title">Your Security Workspace</h2>
            <p className="dashboard-hero-copy">A focused command center for inspecting payloads, converting hashes, and validating security signals without leaving your workflow.</p>
            <div className="dashboard-hero-actions">
              <Link href="/payload-tools" className="dashboard-primary-action">Open Payload Tools <ArrowUpRight aria-hidden="true" /></Link>
              <span className="dashboard-status-pill"><span className={`dashboard-status-dot ${apiStatus === 'online' ? 'dashboard-status-online' : apiStatus === 'offline' ? 'dashboard-status-offline' : 'dashboard-status-checking'}`} />{apiStatusLabel}</span>
            </div>
          </div>
          <div className="dashboard-hero-mark" aria-hidden="true"><ShieldCheck /><span>LOCAL<br />WORKSPACE</span></div>
        </section>

        <div className="dashboard-section-heading">
          <div><p className="dashboard-section-kicker">Quick access</p><h2>Choose a tool to get started</h2></div>
          <Link href="/payload-tools" className="dashboard-section-link">View Payload Tools <ChevronRight aria-hidden="true" /></Link>
        </div>
        <div className="dashboard-tool-grid">
          {tools.map(({ title, description, icon: Icon, accent, href, tag }) => (
            <Link key={title} href={href} className="dashboard-tool-card">
              <div className="dashboard-tool-card-top"><span className={`dashboard-tool-icon ${accent}`}><Icon aria-hidden="true" /></span><ArrowUpRight className="dashboard-tool-arrow" aria-hidden="true" /></div>
              <p className="dashboard-tool-tag">{tag}</p><h3>{title}</h3><p className="dashboard-tool-description">{description}</p>
              <span className="dashboard-tool-cta">Launch tool <ChevronRight aria-hidden="true" /></span>
            </Link>
          ))}
        </div>

        <section className="dashboard-lower-grid" aria-label="Workspace overview">
          <div className="dashboard-panel"><div className="dashboard-panel-heading"><div><p className="dashboard-section-kicker">Sample data</p><h2>Recent activity</h2></div><Activity aria-hidden="true" /></div>
            <div className="dashboard-activity-list">{activity.map((item) => <div key={item.title} className="dashboard-activity-row"><span className={`dashboard-activity-dot ${item.tone}`} /><div className="dashboard-activity-copy"><p>{item.title}</p><span>{item.detail}</span></div><time>{item.time}</time></div>)}</div>
          </div>
          <div className="dashboard-panel"><p className="dashboard-section-kicker">Workspace status</p><h2>Ready when you are</h2><p className="dashboard-status-copy">Your tools run through the existing Flask API. Activity shown here is sample data until persistence is added.</p>
            <div className="dashboard-protected"><span><ShieldCheck aria-hidden="true" /></span><div><p>Protected workspace</p><small>No session required</small></div></div>
          </div>
        </section>
      </div>
    </main>
  )
}
