'use client'

import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { getCurrentUser, logout } from '@/lib/api'

export interface AuthUser {
  id?: string | number
  display_name?: string | null
  name?: string | null
  email: string
}

type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated' | 'unavailable'

interface AuthContextValue {
  user: AuthUser | null
  status: AuthStatus
  refresh: () => Promise<void>
  signOut: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [status, setStatus] = useState<AuthStatus>('loading')

  const refresh = async () => {
    try {
      const nextUser = await getCurrentUser()
      setUser(nextUser)
      setStatus(nextUser ? 'authenticated' : 'unauthenticated')
    } catch {
      setUser(null)
      setStatus('unavailable')
    }
  }

  useEffect(() => { void refresh() }, [])

  const signOut = async () => {
    await logout()
    setUser(null)
    setStatus('unauthenticated')
  }

  const value = useMemo(() => ({ user, status, refresh, signOut }), [user, status])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside AuthProvider')
  return context
}

export function userDisplayName(user: AuthUser) {
  return user.display_name?.trim() || user.name?.trim() || user.email.split('@')[0] || 'SentinelX user'
}

export function userInitials(user: AuthUser) {
  const name = userDisplayName(user)
  const initials = name.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join('')
  return initials.toUpperCase() || 'SX'
}
