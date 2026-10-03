'use client'

import { usePathname } from 'next/navigation'
import { Menu, Moon, Search, Sun } from 'lucide-react'
import { useTheme } from '@/components/theme-provider'

const pages: Record<string, { breadcrumb: string; title: string }> = {
  '/dashboard': { breadcrumb: 'Workspace / Overview', title: 'Dashboard' },
  '/payload-tools': { breadcrumb: 'Workspace / Tools', title: 'Payload Tools' },
  '/hash-tools': { breadcrumb: 'Workspace / Hash Tools', title: 'Hash Converter' },
  '/identify-hash': { breadcrumb: 'Workspace / Hash Tools', title: 'Identify Hash' },
  '/security-lab': { breadcrumb: 'Workspace / Security', title: 'Security Lab' },
}

export function AppHeader({ onOpenNavigation, navigationOpen }: { onOpenNavigation: () => void; navigationOpen: boolean }) {
  const pathname = usePathname()
  const page = pages[pathname] ?? pages['/dashboard']
  const { isDark, toggleTheme } = useTheme()

  return (
    <header className="app-header">
      <div className="app-page-heading">
        <button
          type="button"
          className="app-mobile-menu"
          onClick={onOpenNavigation}
          aria-label="Open main navigation"
          aria-expanded={navigationOpen}
          aria-controls="app-sidebar"
        >
          <Menu aria-hidden="true" />
        </button>
        <div className="min-w-0">
          <p className="app-breadcrumb">{page.breadcrumb}</p>
          <h1 className="app-page-title">{page.title}</h1>
        </div>
      </div>

      <div className="app-header-tools">
        <div className="app-search" aria-label="Tool search">
          <Search aria-hidden="true" />
          <span>Search tools...</span>
          <kbd><span aria-hidden="true">⌘</span>K</kbd>
        </div>
        <span className="app-header-divider" aria-hidden="true" />
        <div className="profile-display" role="group" aria-label="Profile display: Adithya Valke, Cyber professional">
          <span className="profile-avatar" aria-hidden="true">AV</span>
          <span className="profile-copy"><strong>Adithya Valke</strong><small>Cyber professional</small></span>
        </div>
        <button
          type="button"
          className="app-theme-toggle"
          onClick={toggleTheme}
          aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode`}
          title={`Switch to ${isDark ? 'light' : 'dark'} mode`}
        >
          {isDark ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}
        </button>
      </div>
    </header>
  )
}
