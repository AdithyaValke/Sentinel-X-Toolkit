'use client'

import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { isDarkTheme, parseThemePreference, type ThemePreference } from '@/lib/theme-utils'

type Theme = ThemePreference

const ThemeContext = createContext<{ theme: Theme; isDark: boolean; toggleTheme: () => void }>({
  theme: 'system',
  isDark: false,
  toggleTheme: () => undefined,
})

function applyTheme(theme: Theme) {
  const dark = isDarkTheme(theme, window.matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.classList.toggle('dark', dark)
  document.documentElement.classList.toggle('light', !dark)
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<Theme>('system')
  const [isDark, setIsDark] = useState(false)
  const themeRef = useRef<Theme>('system')

  useEffect(() => {
    let saved: Theme = 'system'
    try {
      saved = parseThemePreference(window.localStorage.getItem('payload-workbench-theme'))
    } catch {
      // Keep the system theme when browser storage is unavailable.
    }
    themeRef.current = saved
    setTheme(saved)
    applyTheme(saved)
    setIsDark(document.documentElement.classList.contains('dark'))

    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const updateSystemTheme = () => {
      if (themeRef.current === 'system') {
        applyTheme('system')
        setIsDark(document.documentElement.classList.contains('dark'))
      }
    }
    media.addEventListener('change', updateSystemTheme)
    return () => media.removeEventListener('change', updateSystemTheme)
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme((current) => {
      const next = current === 'dark' ? 'light' : 'dark'
      themeRef.current = next
      try {
        window.localStorage.setItem('payload-workbench-theme', next)
      } catch {
        // Theme still applies for this page when persistence is unavailable.
      }
      applyTheme(next)
      setIsDark(next === 'dark')
      return next
    })
  }, [])

  return <ThemeContext.Provider value={{ theme, isDark, toggleTheme }}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  return useContext(ThemeContext)
}
