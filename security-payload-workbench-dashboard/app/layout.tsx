import { Analytics } from '@vercel/analytics/next'
import type { Metadata, Viewport } from 'next'
import Script from 'next/script'
import { Monitor } from 'lucide-react'
import { AppShell } from '@/components/app-shell'
import { ThemeProvider } from '@/components/theme-provider'
import './globals.css'

export const metadata: Metadata = {
  title: 'SentinelX',
  description: 'A general-purpose cybersecurity toolkit for encoding, hashing, token analysis, and security utilities.',
  generator: 'v0.app',
  icons: { apple: '/apple-icon.png' },
}

export const viewport: Viewport = {
  colorScheme: 'light dark',
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: 'white' },
    { media: '(prefers-color-scheme: dark)', color: 'black' },
  ],
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased">
        <Script id="theme-preference" strategy="beforeInteractive">
          {`try{var t=localStorage.getItem('payload-workbench-theme');var d=t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d);document.documentElement.classList.toggle('light',!d);document.documentElement.style.colorScheme=d?'dark':'light'}catch(e){}`}
        </Script>
        <ThemeProvider>
          <div className="min-h-dvh min-[768px]:contents">
            <main className="relative isolate hidden min-h-dvh w-full place-items-center overflow-hidden bg-[#080b12] px-6 py-12 text-slate-100 max-[768px]:grid" aria-labelledby="desktop-required-heading" aria-describedby="desktop-required-message">
              <div aria-hidden="true" className="pointer-events-none absolute -right-24 -top-32 size-80 rounded-full bg-cyan-400/[0.08] blur-3xl" />
              <section className="relative w-full max-w-lg rounded-3xl border border-cyan-400/15 bg-[#0d1420]/90 p-8 shadow-2xl shadow-black/30 sm:p-10">
                <div className="mb-7 flex size-14 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-400/[0.08] text-cyan-300">
                  <Monitor aria-hidden="true" className="size-7" />
                </div>
                <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.22em] text-cyan-300">SentinelX</p>
                <h1 id="desktop-required-heading" className="text-2xl font-bold tracking-tight text-white sm:text-3xl">Desktop Experience Required</h1>
                <p id="desktop-required-message" className="mt-4 text-sm leading-6 text-slate-300">Open SentinelX on a laptop or desktop for the full security workspace.</p>
                <div aria-hidden="true" className="mt-8 h-px w-full bg-gradient-to-r from-cyan-400/40 via-white/10 to-transparent" />
                <p className="mt-4 font-mono text-[10px] uppercase tracking-wider text-slate-500">A wider screen is needed to use these tools comfortably.</p>
              </section>
            </main>
            <div className="hidden min-[768px]:contents">
              <AppShell>{children}</AppShell>
            </div>
          </div>
          {process.env.NODE_ENV === 'production' && <Analytics />}
        </ThemeProvider>
      </body>
    </html>
  )
}
