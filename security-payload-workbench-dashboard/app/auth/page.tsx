'use client'

import './auth.css'
import Image from 'next/image'
import Link from 'next/link'
import { FormEvent, useState } from 'react'
import { Eye, EyeOff, LockKeyhole, ShieldCheck } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { login, registerAccount } from '@/lib/api'
import { useAuth } from '@/lib/auth'

export default function AuthPage() {
  const router = useRouter()
  const { refresh } = useAuth()
  const [mode, setMode] = useState<'signin' | 'register'>('signin')
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  function switchMode(nextMode: 'signin' | 'register') {
    setMode(nextMode); setError(''); setPassword('')
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(''); setLoading(true)
    try {
      if (mode === 'register') await registerAccount({ display_name: displayName.trim(), email: email.trim(), password })
      else await login({ email: email.trim(), password })
      await refresh()
      router.replace('/dashboard')
    } catch {
      setError(mode === 'register' ? 'We could not create your account. Check your details and try again.' : 'Sign in failed. Check your email and password and try again.')
    } finally { setLoading(false) }
  }

  return (
    <main className="auth-page">
      <div className="auth-glow auth-glow-one" aria-hidden="true" />
      <div className="auth-glow auth-glow-two" aria-hidden="true" />
      <section className="auth-card" aria-labelledby="auth-title">
        <Link href="/dashboard" className="auth-brand" aria-label="Return to SentinelX dashboard">
          <Image src="/sentinelx-logo.png" alt="" width={44} height={44} className="size-11 rounded-xl bg-white p-1.5 object-contain" priority />
          <span><strong>Sentinel<span>X</span></strong><small>Security Toolkit</small></span>
        </Link>
        <div className="auth-intro"><div className="auth-kicker"><ShieldCheck aria-hidden="true" /> SECURE ACCESS</div><h1 id="auth-title">{mode === 'signin' ? 'Welcome back' : 'Create your account'}</h1><p>Security Analysis. Real Investigations.</p></div>
        <div className="auth-tabs" role="tablist" aria-label="Authentication mode">
          <button type="button" role="tab" aria-selected={mode === 'signin'} className={mode === 'signin' ? 'auth-tab auth-tab-active' : 'auth-tab'} onClick={() => switchMode('signin')}>Sign In</button>
          <button type="button" role="tab" aria-selected={mode === 'register'} className={mode === 'register' ? 'auth-tab auth-tab-active' : 'auth-tab'} onClick={() => switchMode('register')}>Create Account</button>
        </div>
        <form className="auth-form" onSubmit={submit}>
          {mode === 'register' && <label>Display name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} autoComplete="name" required /></label>}
          <label>Email address<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" required /></label>
          <label>Password<div className="auth-password"><input type={showPassword ? 'text' : 'password'} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete={mode === 'signin' ? 'current-password' : 'new-password'} required /><button type="button" onClick={() => setShowPassword((visible) => !visible)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}</button></div></label>
          {error && <p className="auth-error" role="alert">{error}</p>}
          <button className="auth-submit" type="submit" disabled={loading}>{loading ? 'Working…' : mode === 'signin' ? 'Sign In' : 'Create Account'}<LockKeyhole aria-hidden="true" /></button>
        </form>
        <p className="auth-footnote">Your session is protected by a secure HttpOnly cookie.</p>
      </section>
    </main>
  )
}
