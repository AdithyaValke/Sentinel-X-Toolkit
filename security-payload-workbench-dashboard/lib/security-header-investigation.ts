import { ApiError, createInvestigationFinding, type FindingSeverity } from './api.ts'
import type { SecurityHeaderFinding, HeaderFindingSeverity } from './security-headers-analyzer.ts'

export interface HeaderFindingSaveFailure {
  finding: SecurityHeaderFinding
  message: string
}

export interface HeaderFindingSaveResult {
  saved: SecurityHeaderFinding[]
  failed: HeaderFindingSaveFailure[]
  authenticationExpired: boolean
}

const backendSeverity: Record<HeaderFindingSeverity, FindingSeverity> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
}

export function mapHeaderFindingSeverity(severity: HeaderFindingSeverity): FindingSeverity {
  return backendSeverity[severity]
}

export function toggleHeaderFindingSelection(current: ReadonlySet<string>, id: string): Set<string> {
  const next = new Set(current)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  return next
}

export function selectVisibleHeaderFindings(
  current: ReadonlySet<string>,
  visibleIds: readonly string[],
  shouldSelect: boolean,
): Set<string> {
  const next = new Set(current)
  for (const id of visibleIds) {
    if (shouldSelect) next.add(id)
    else next.delete(id)
  }
  return next
}

export function clearHeaderFindingSelection(): Set<string> {
  return new Set()
}

export function removeSavedHeaderFindings(
  current: ReadonlySet<string>,
  saved: readonly SecurityHeaderFinding[],
): Set<string> {
  const savedIds = new Set(saved.map(({ id }) => id))
  return new Set(Array.from(current).filter((id) => !savedIds.has(id)))
}

function truncateForBackend(value: string, limit: number): string {
  const characters = Array.from(value)
  if (characters.length <= limit) return value
  const marker = ' [truncated to fit the Investigation API limit]'
  return `${characters.slice(0, limit - Array.from(marker).length).join('')}${marker}`
}

function safeObservedValue(finding: SecurityHeaderFinding): string | undefined {
  if (!finding.observedValue) return undefined
  // Cookie values may contain session identifiers or other credentials. Preserve
  // only their attributes; never persist the cookie name or value.
  if (finding.id.startsWith('cookie_')) {
    return finding.observedValue.split(';').slice(1).join(';').trim() || undefined
  }
  const potentiallySensitive = /\b(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?(?:key|token)|refresh[_-]?token|session[_-]?(?:id|token|cookie)|csrf[_-]?token|private[_-]?key|secret|token|authorization|set-cookie|cookie)\b\s*(?:[:=]\s*)\S+|\bbearer\s+[A-Za-z0-9._~+/-]{8,}={0,2}|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i
  if (potentiallySensitive.test(finding.observedValue)) return undefined
  return finding.observedValue
}

export function buildHeaderFindingPayload(finding: SecurityHeaderFinding): {
  title: string
  description: string
  severity: FindingSeverity
} {
  const title = truncateForBackend(`Security header: ${finding.header}`, 200)
  const description = [
    'Security Headers Analyzer finding',
    `Header: ${finding.header}`,
    `Analyzer status: ${finding.status}`,
    `Analyzer severity: ${finding.severity}`,
    `Remediation: ${finding.remediation}`,
    ...(finding.example ? [`Example: ${finding.example}`] : []),
    `Explanation: ${finding.explanation}`,
    `Risk: ${finding.risk}`,
    ...(safeObservedValue(finding) ? [`Observed value: ${safeObservedValue(finding)}`] : []),
  ].join('\n')
  return { title, description: truncateForBackend(description, 8000), severity: mapHeaderFindingSeverity(finding.severity) }
}

export async function saveHeaderFindingsToInvestigation(
  investigationId: string,
  findings: readonly SecurityHeaderFinding[],
): Promise<HeaderFindingSaveResult> {
  const result: HeaderFindingSaveResult = { saved: [], failed: [], authenticationExpired: false }
  for (let index = 0; index < findings.length; index += 1) {
    const finding = findings[index]
    try {
      await createInvestigationFinding(investigationId, buildHeaderFindingPayload(finding))
      result.saved.push(finding)
    } catch (cause) {
      result.failed.push({ finding, message: cause instanceof Error ? cause.message : 'The finding could not be added.' })
      if (cause instanceof ApiError && (cause.status === 401 || cause.status === 403)) {
        result.authenticationExpired = true
        for (const pending of findings.slice(index + 1)) {
          result.failed.push({ finding: pending, message: 'Not attempted because the session expired.' })
        }
        break
      }
    }
  }
  return result
}
