import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowUpRight, Braces, Fingerprint, Hash, TerminalSquare } from 'lucide-react'

export const metadata: Metadata = {
  title: 'Common Tools | SentinelX',
  description: 'Everyday encoding, hashing, and hash identification utilities for SentinelX.',
}

const tools = [
  { title: 'Payload Tools', description: 'Encode and decode Base64, URL, and Hex data in one focused workspace.', href: '/payload-tools', icon: TerminalSquare, accent: 'dashboard-icon-amber', items: ['Base64 encode / decode', 'URL encode / decode', 'Hex encode / decode'] },
  { title: 'Hash Tools', description: 'Generate message digests from text with MD5, SHA-2, SHA-3, and SHAKE.', href: '/hash-tools', icon: Hash, accent: 'dashboard-icon-cyan', items: ['MD5 and SHA-1', 'SHA-2 family', 'SHA-3 family', 'SHAKE-128 / SHAKE-256'] },
  { title: 'Identify Hash', description: 'Inspect a hash signature and review likely algorithms with supporting evidence.', href: '/identify-hash', icon: Fingerprint, accent: 'dashboard-icon-violet', items: ['Pattern analysis', 'Likely algorithms', 'Evidence and guidance'] },
  { title: 'JSON Formatter', description: 'Validate, format, and minify JSON locally in your browser.', href: '/json-formatter', icon: Braces, accent: 'dashboard-icon-emerald', items: ['Validate JSON', 'Pretty-print output', 'Minify safely'] },
]

export default function CommonToolsPage() {
  return (
    <main className="dashboard-page">
      <div className="dashboard-container">
        <section className="dashboard-hero" aria-labelledby="common-tools-heading">
          <div className="dashboard-hero-grid" aria-hidden="true" />
          <div className="dashboard-hero-glow" aria-hidden="true" />
          <div className="dashboard-hero-content">
            <div className="dashboard-eyebrow"><span className="dashboard-eyebrow-dot" />Everyday utilities</div>
            <h1 id="common-tools-heading" className="dashboard-hero-title">Common Tools</h1>
            <p className="dashboard-hero-copy">Encoding, hashing, identification, and conversion utilities for the tasks you reach for most.</p>
          </div>
        </section>

        <div className="dashboard-section-heading">
          <div><p className="dashboard-section-kicker">Toolkit</p><h2>Choose a utility</h2></div>
          <span className="dashboard-section-link">4 tool groups</span>
        </div>
        <div className="dashboard-tool-grid common-tools-grid">
          {tools.map(({ title, description, href, icon: Icon, accent, items }) => (
            <Link key={title} href={href} className="dashboard-tool-card">
              <div className="dashboard-tool-card-top"><span className={`dashboard-tool-icon ${accent}`}><Icon aria-hidden="true" /></span><ArrowUpRight className="dashboard-tool-arrow" aria-hidden="true" /></div>
              <p className="dashboard-tool-tag">Common utility</p><h3>{title}</h3><p className="dashboard-tool-description">{description}</p>
              <ul className="mt-4 flex flex-col gap-2 text-xs text-slate-500">{items.map((item) => <li key={item}>{item}</li>)}</ul>
              <span className="dashboard-tool-cta mt-auto">Open tool <ArrowUpRight aria-hidden="true" /></span>
            </Link>
          ))}
        </div>
      </div>
    </main>
  )
}
