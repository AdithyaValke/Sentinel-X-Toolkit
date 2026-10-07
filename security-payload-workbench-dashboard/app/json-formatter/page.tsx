import type { Metadata } from 'next'
import { JsonFormatter } from '@/components/json-formatter'

export const metadata: Metadata = {
  title: 'JSON Formatter | SentinelX',
  description: 'Validate, format, and minify JSON locally in your browser.',
}

export default function JsonFormatterPage() {
  return <JsonFormatter />
}
