import { redirect } from 'next/navigation'
import { getLegacyDestination } from '@/lib/legacy-routes'

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>
}) {
  redirect(getLegacyDestination(await searchParams))
}
