'use client'

import { createContext, useContext, useEffect, useRef, useState } from 'react'
import Image from 'next/image'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  Fingerprint,
  FlaskConical,
  Hash,
  LayoutDashboard,
  PanelLeftClose,
  PanelLeftOpen,
  ShieldCheck,
  TerminalSquare,
  X,
} from 'lucide-react'
import { AppHeader } from '@/components/app-header'
import { useTheme } from '@/components/theme-provider'
import { checkBackendHealth } from '@/lib/api'
import { LatestRequest } from '@/lib/latest-request'

const navigation = [
  { label: 'Dashboard', icon: LayoutDashboard, href: '/dashboard' },
  { label: 'Payload Tools', icon: TerminalSquare, href: '/payload-tools' },
  { label: 'Hash Tools', icon: Hash, href: '/hash-tools' },
  { label: 'Identify Hash', icon: Fingerprint, href: '/identify-hash' },
  { label: 'Security Lab', icon: FlaskConical, href: '/security-lab' },
]

type ApiStatus = 'checking' | 'online' | 'offline'
const ApiStatusContext = createContext<ApiStatus>('checking')

export function useApiStatus() {
  return useContext(ApiStatusContext)
}

function Brand({ compact }: { compact: boolean }) {
  return (
    <Link href="/dashboard" className="flex min-h-11 min-w-0 items-center gap-3" aria-label="Payload Workbench dashboard">
      <Image src="/icon.svg" alt="" width={36} height={36} className="size-9 shrink-0 rounded-xl" priority />
      {!compact && <span className="leading-none"><span className="block font-mono text-sm font-bold tracking-tight text-slate-100">Payload</span><span className="block font-mono text-[10px] font-medium uppercase tracking-[0.2em] text-cyan-300">Workbench</span></span>}
    </Link>
  )
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [apiStatus, setApiStatus] = useState<ApiStatus>('checking')
  const latestHealth = useRef(new LatestRequest())
  const pathname = usePathname()
  const { isDark } = useTheme()

  useEffect(() => {
    const request = latestHealth.current.begin()
    checkBackendHealth(request.signal).then((online) => {
      if (latestHealth.current.isCurrent(request.id)) setApiStatus(online ? 'online' : 'offline')
    })
    return () => latestHealth.current.cancel()
  }, [])

  const apiStatusLabel = apiStatus === 'online' ? 'API online' : apiStatus === 'offline' ? 'API offline' : 'Checking API'

  return (
    <ApiStatusContext.Provider value={apiStatus}>
      <div className={`app-shell ${isDark ? 'app-shell-dark' : 'app-shell-light'}`}>
        {mobileOpen && <button type="button" aria-label="Close navigation" className="app-sidebar-backdrop" onClick={() => setMobileOpen(false)} />}
        <aside id="app-sidebar" className={`app-sidebar ${collapsed ? 'app-sidebar-collapsed' : ''} ${mobileOpen ? 'app-sidebar-open' : ''}`}>
          <div className="app-sidebar-brand">
            <Brand compact={collapsed} />
            {!collapsed && <button type="button" className="app-sidebar-collapse" onClick={() => setCollapsed(true)} aria-label="Collapse sidebar"><PanelLeftClose aria-hidden="true" className="size-4" /></button>}
            <button type="button" className="app-sidebar-close" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X aria-hidden="true" className="size-4" /></button>
          </div>
          {collapsed && <button type="button" className="app-sidebar-expand" onClick={() => setCollapsed(false)} aria-label="Expand sidebar"><PanelLeftOpen aria-hidden="true" className="size-4" /></button>}
          <nav className="app-sidebar-nav" aria-label="Main navigation">
            {!collapsed && <p className="app-sidebar-label">Workspace</p>}
            {navigation.map(({ label, icon: Icon, href }) => {
              const active = pathname === href || (href !== '/dashboard' && pathname.startsWith(`${href}/`))
              return (
                <Link
                  key={href}
                  href={href}
                  onClick={() => setMobileOpen(false)}
                  title={collapsed ? label : undefined}
                  aria-current={active ? 'page' : undefined}
                  className={`app-sidebar-link ${active ? 'app-sidebar-link-active' : ''} ${collapsed ? 'app-sidebar-link-collapsed' : ''}`}
                >
                  <Icon aria-hidden="true" className="size-[18px] shrink-0" />
                  {!collapsed && <span>{label}</span>}
                </Link>
              )
            })}
          </nav>
          {!collapsed && <div className="app-sidebar-status"><div className="flex items-center gap-2"><span className={`size-2 rounded-full ${apiStatus === 'online' ? 'bg-emerald-400' : apiStatus === 'offline' ? 'bg-rose-400' : 'bg-amber-400'}`} /><span className={`font-mono text-[10px] uppercase tracking-wider ${apiStatus === 'online' ? 'text-emerald-300' : apiStatus === 'offline' ? 'text-rose-300' : 'text-amber-300'}`}>{apiStatusLabel}</span></div><p className="mt-2 text-xs leading-5 text-slate-600">Health check: Flask /health endpoint.</p></div>}
        </aside>

        <div className="app-main-column">
          <AppHeader onOpenNavigation={() => setMobileOpen(true)} navigationOpen={mobileOpen} />
          {children}
        </div>
      </div>
    </ApiStatusContext.Provider>
  )
}
