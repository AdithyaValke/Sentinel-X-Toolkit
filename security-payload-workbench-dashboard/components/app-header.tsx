'use client'

import { usePathname, useRouter } from 'next/navigation'
import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { ArrowRight, Fingerprint, FlaskConical, Hash, LayoutDashboard, Menu, Moon, Search, Sun, TerminalSquare, X } from 'lucide-react'
import { useTheme } from '@/components/theme-provider'
import { searchGlobal, type SearchEntry } from '@/lib/global-search'

const pages: Record<string, { breadcrumb: string; title: string }> = {
  '/dashboard': { breadcrumb: 'Workspace / Overview', title: 'Dashboard' },
  '/payload-tools': { breadcrumb: 'Workspace / Tools', title: 'Payload Tools' },
  '/chain-builder': { breadcrumb: 'Workspace / Tools', title: 'Chain Builder' },
  '/hash-tools': { breadcrumb: 'Workspace / Hash Tools', title: 'Hash Converter' },
  '/identify-hash': { breadcrumb: 'Workspace / Hash Tools', title: 'Identify Hash' },
  '/security-lab': { breadcrumb: 'Workspace / Security', title: 'Security Lab' },
}

const resultIcons = {
  dashboard: LayoutDashboard,
  payload: TerminalSquare,
  hash: Hash,
  identify: Fingerprint,
  security: FlaskConical,
}

export function AppHeader({ onOpenNavigation, navigationOpen }: { onOpenNavigation: () => void; navigationOpen: boolean }) {
  const pathname = usePathname()
  const router = useRouter()
  const page = pages[pathname] ?? pages['/dashboard']
  const { isDark, toggleTheme } = useTheme()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listId = useId()
  const results = useMemo(() => searchGlobal(query), [query])
  const selectedResult = open ? results[selectedIndex] : undefined

  useEffect(() => {
    setOpen(false)
    setQuery('')
    setSelectedIndex(0)
  }, [pathname])

  useEffect(() => {
    const onGlobalKeyDown = (event: KeyboardEvent) => {
      if (!(event.metaKey || event.ctrlKey) || event.key.toLowerCase() !== 'k' || event.altKey) return
      const target = event.target
      const isSearchInput = target === inputRef.current
      const isEditing = target instanceof HTMLElement && (
        target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)
      )
      if (isEditing && !isSearchInput) return
      event.preventDefault()
      setOpen(true)
      inputRef.current?.focus()
    }
    window.addEventListener('keydown', onGlobalKeyDown)
    return () => window.removeEventListener('keydown', onGlobalKeyDown)
  }, [])

  function openResult(result: SearchEntry) {
    setOpen(false)
    setQuery('')
    setSelectedIndex(0)
    router.push(result.href)
  }

  function handleSearchKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'ArrowDown' && results.length) {
      event.preventDefault()
      setOpen(true)
      setSelectedIndex((current) => Math.min(current + 1, results.length - 1))
    } else if (event.key === 'ArrowUp' && results.length) {
      event.preventDefault()
      setOpen(true)
      setSelectedIndex((current) => Math.max(current - 1, 0))
    } else if (event.key === 'Enter' && open && selectedResult) {
      event.preventDefault()
      openResult(selectedResult)
    } else if (event.key === 'Escape' && open) {
      event.preventDefault()
      setOpen(false)
      setSelectedIndex(0)
    }
  }

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
        <div className="app-search-container">
          <div className={`app-search ${open ? 'app-search-open' : ''}`}>
            <Search aria-hidden="true" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              placeholder="Search tools..."
              aria-label="Search pages and tools"
              aria-autocomplete="list"
              aria-haspopup="listbox"
              aria-expanded={open}
              aria-controls={listId}
              aria-activedescendant={selectedResult ? `${listId}-option-${selectedIndex}` : undefined}
              role="combobox"
              onFocus={() => setOpen(true)}
              onChange={(event) => {
                setQuery(event.target.value)
                setSelectedIndex(0)
                setOpen(true)
              }}
              onKeyDown={handleSearchKeyDown}
              onBlur={() => window.setTimeout(() => setOpen(false), 120)}
            />
            {query ? (
              <button
                type="button"
                className="app-search-clear"
                aria-label="Clear search"
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => { setQuery(''); setSelectedIndex(0); setOpen(true); inputRef.current?.focus() }}
              ><X aria-hidden="true" /></button>
            ) : <kbd><span aria-hidden="true">⌘</span>K</kbd>}
          </div>
          {open && (
            <div className="app-search-results" role="presentation">
              <p className="app-search-caption">{query.trim() ? 'Search results' : 'Quick links'}</p>
              {results.length ? (
                <ul id={listId} role="listbox" aria-label="Search results">
                  {results.map((result, index) => {
                    const Icon = resultIcons[result.icon]
                    return (
                      <li key={result.href} role="presentation">
                        <button
                          id={`${listId}-option-${index}`}
                          type="button"
                          role="option"
                          aria-selected={selectedIndex === index}
                          className={`app-search-result ${selectedIndex === index ? 'app-search-result-active' : ''}`}
                          onMouseDown={(event) => event.preventDefault()}
                          onMouseEnter={() => setSelectedIndex(index)}
                          onClick={() => openResult(result)}
                        >
                          <span className="app-search-result-icon"><Icon aria-hidden="true" /></span>
                          <span className="app-search-result-copy"><strong>{result.title}</strong><small>{result.description}</small></span>
                          <ArrowRight className="app-search-result-arrow" aria-hidden="true" />
                        </button>
                      </li>
                    )
                  })}
                </ul>
              ) : (
                <p className="app-search-empty">No results found. Try another keyword.</p>
              )}
              <span className="sr-only" role="status" aria-live="polite">{query.trim() ? `${results.length} search results` : ''}</span>
            </div>
          )}
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
