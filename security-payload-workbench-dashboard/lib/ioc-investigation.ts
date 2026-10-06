import { ApiError, createInvestigationIOC, type IocResult } from './api.ts'

export interface ExtractedIndicator extends IocResult {
  id: string
}

export interface IndicatorSaveFailure {
  indicator: ExtractedIndicator
  message: string
}

export interface IndicatorSaveResult {
  saved: ExtractedIndicator[]
  failed: IndicatorSaveFailure[]
  authenticationExpired: boolean
}

/** Prepare an extracted value for the Investigation API without changing the displayed result. */
export function canonicalizeExtractedIocForPersistence(category: ExtractedIndicator['category'], value: string): string {
  if (category === 'ip') return value.replace(/\[\.\]/g, '.')
  if (category === 'hash') return value

  if (category === 'email') {
    return value
      .replace(/\[@\]|\[at\]|\(@\)|\{@\}/gi, '@')
      .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
  }

  const refanged = value
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/^hxxp:\/\//i, 'http://')
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')

  // The extractor puts complete URLs in the domain category, while the Investigation
  // API's domain IOC contract accepts hostnames only. Parse locally; never fetch the URL.
  if (/^https?:\/\//i.test(refanged)) {
    try {
      const parsed = new URL(refanged)
      if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && !parsed.username && !parsed.password) {
        return parsed.hostname
      }
    } catch {
      // Leave malformed input for the backend's authoritative validation.
    }
  }
  return refanged
}

export function toggleIndicatorSelection(current: ReadonlySet<string>, id: string): Set<string> {
  const next = new Set(current)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  return next
}

export function selectVisibleIndicators(
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

export function canPersistIndicators(authenticated: boolean, selectedCount: number, isSaving: boolean): boolean {
  return authenticated && selectedCount > 0 && !isSaving
}

export async function saveIndicatorsToInvestigation(
  investigationId: string,
  indicators: readonly ExtractedIndicator[],
): Promise<IndicatorSaveResult> {
  const result: IndicatorSaveResult = { saved: [], failed: [], authenticationExpired: false }
  for (let index = 0; index < indicators.length; index += 1) {
    const indicator = indicators[index]
    try {
      await createInvestigationIOC(investigationId, {
        ioc_type: indicator.category,
        value: canonicalizeExtractedIocForPersistence(indicator.category, indicator.value),
        source: 'extractor',
      })
      result.saved.push(indicator)
    } catch (cause) {
      result.failed.push({ indicator, message: cause instanceof Error ? cause.message : 'The indicator could not be added.' })
      if (cause instanceof ApiError && (cause.status === 401 || cause.status === 403)) {
        result.authenticationExpired = true
        for (const pending of indicators.slice(index + 1)) {
          result.failed.push({ indicator: pending, message: 'Not attempted because the session expired.' })
        }
        break
      }
    }
  }
  return result
}
