import type { Metadata } from 'next'
import { ChainBuilder } from '@/components/chain-builder'

export const metadata: Metadata = { title: 'Chain Builder | SentinelX', description: 'Build and run ordered payload transformations.' }

export default function ChainBuilderPage() { return <ChainBuilder /> }
