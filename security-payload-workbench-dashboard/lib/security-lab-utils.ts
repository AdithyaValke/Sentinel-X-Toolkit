export function validateIPv4(ip: string): boolean {
  return /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(ip)
}

export function validateIPv6(ip: string): boolean {
  if (!ip || ip.includes('%') || ip.includes('[') || ip.includes(']')) return false

  try {
    const hostname = new URL(`http://[${ip}]/`).hostname
    return hostname.startsWith('[') && hostname.endsWith(']')
  } catch {
    return false
  }
}

export function validateIP(ip: string): { valid: boolean; message?: string } {
  const trimmed = ip.trim()
  if (!trimmed) return { valid: false, message: 'IP address is required.' }
  if (validateIPv4(trimmed) || validateIPv6(trimmed)) return { valid: true }
  return {
    valid: false,
    message:
      'Enter a valid IPv4 (e.g. 10.0.0.1) or IPv6 (e.g. ::1) address. Hostnames are not accepted.',
  }
}

export function formatHttpUrl(ip: string, port: string | number): string {
  const host = ip.includes(':') ? `[${ip}]` : ip
  return `http://${host}:${port}/`
}
