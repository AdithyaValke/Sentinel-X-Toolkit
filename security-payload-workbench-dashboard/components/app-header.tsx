'use client'

import Image from 'next/image'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Moon, Sun } from 'lucide-react'
import { useTheme } from '@/components/theme-provider'

const navigation = [
  { label: 'Dashboard', href: '/dashboard' },
  { label: 'Payload Tools', href: '/payload-tools' },
  { label: 'Hash Converter', href: '/hash-tools' },
  { label: 'Identify Hash', href: '/identify-hash' },
  { label: 'Security Lab', href: '/security-lab' },
]

export function AppHeader() {
  const pathname = usePathname()
  const { isDark, toggleTheme } = useTheme()

  return (
    <header className="app-header">
      <Link href="/dashboard" className="app-brand" aria-label="Payload Workbench dashboard">
        <Image src="/icon.svg" alt="" width={34} height={34} priority className="size-8 shrink-0 rounded-lg sm:size-[34px]" />
        <span>Payload Workbench</span>
      </Link>
      <nav className="app-navigation" aria-label="Application navigation">
        {navigation.map(({ label, href }) => {
          const active = pathname === href || pathname.startsWith(`${href}/`)
          return <Link key={href} href={href} aria-current={active ? 'page' : undefined} className="app-nav-link">{label}</Link>
        })}
      </nav>
      <div className="app-header-actions">
        <button
          type="button"
          className="app-theme-toggle"
          onClick={toggleTheme}
          aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode`}
          title={`Switch to ${isDark ? 'light' : 'dark'} mode`}
        >
          {isDark ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}
        </button>
        <div className="profile-display" aria-label="Profile display: Adithya Valke, Cyber professional">
          <span className="profile-avatar" aria-hidden="true">AV</span>
          <span className="profile-copy"><strong>Adithya Valke</strong><small>Cyber professional</small></span>
        </div>
      </div>
    </header>
  )
}
