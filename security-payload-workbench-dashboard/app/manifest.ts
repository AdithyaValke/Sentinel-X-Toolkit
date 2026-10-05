import type { MetadataRoute } from 'next'

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'SentinelX',
    short_name: 'SentinelX',
    description: 'A general-purpose cybersecurity toolkit for encoding, hashing, token analysis, and security utilities.',
    start_url: '/',
    display: 'standalone',
    background_color: '#080b12',
    theme_color: '#080b12',
    icons: [
      {
        src: '/web-app-manifest-192x192.png',
        sizes: '192x192',
        type: 'image/png',
      },
      {
        src: '/web-app-manifest-512x512.png',
        sizes: '512x512',
        type: 'image/png',
      },
    ],
  }
}
