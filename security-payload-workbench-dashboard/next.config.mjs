/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    unoptimized: true,
  },
  async headers() {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
    let apiOrigin = ''
    try {
      apiOrigin = new URL(apiUrl).origin
    } catch {
      // An invalid API URL is handled by the client configuration; omit it from CSP.
    }

    // Inline scripts/styles are required by the current theme bootstrap and Next.js runtime.
    // This trades strict script/style CSP for compatibility; a nonce-based CSP needs request rendering.
    const csp = [
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "img-src 'self' data:",
      `connect-src 'self' ${apiOrigin} https://vitals.vercel-insights.com`.trim(),
      "script-src 'self' 'unsafe-inline' https://va.vercel-scripts.com",
      "style-src 'self' 'unsafe-inline'",
    ].join('; ')

    return [{
      source: '/:path*',
      headers: [
        { key: 'Content-Security-Policy', value: csp },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        { key: 'X-Frame-Options', value: 'DENY' },
      ],
    }]
  },
}

export default nextConfig
