export const MAX_REGEX_INPUT_LENGTH = 100_000

export const REGEX_PRESETS = {
  IPv4: { pattern: String.raw`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b`, flags: 'g' },
  Email: { pattern: String.raw`[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}`, flags: 'gi' },
  Domain: { pattern: String.raw`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`, flags: 'gi' },
  URL: { pattern: String.raw`https?:\/\/[^\s/$.?#].[^\s]*`, flags: 'gi' },
  'SHA-256': { pattern: String.raw`\b[a-fA-F0-9]{64}\b`, flags: 'gi' },
} as const

export type RegexPreset = keyof typeof REGEX_PRESETS
export type RegexMatch = { index: number; value: string; line: number; column: number; endColumn: number; context: string; groups: string[] }

export function analyzeRegex(pattern: string, input: string, flags: string): { matches: RegexMatch[]; error?: string } {
  if (input.length > MAX_REGEX_INPUT_LENGTH) return { matches: [], error: `Input is limited to ${MAX_REGEX_INPUT_LENGTH.toLocaleString()} characters.` }
  let regex: RegExp
  try { regex = new RegExp(pattern, flags) } catch (error) { return { matches: [], error: error instanceof Error ? error.message : 'Invalid regular expression.' } }
  const matches: RegexMatch[] = []
  const source = input
  const addMatch = (match: RegExpExecArray) => {
    const index = match.index
    const before = source.slice(0, index)
    const line = before.split('\n').length
    const column = index - before.lastIndexOf('\n')
    const value = match[0]
    const contextStart = Math.max(0, index - 24)
    const contextEnd = Math.min(source.length, index + value.length + 24)
    matches.push({ index, value, line, column, endColumn: column + value.length - 1, context: source.slice(contextStart, contextEnd).replace(/\n/g, ' ↵ '), groups: match.slice(1).map((group) => group ?? '' ) })
  }
  if (regex.global) {
    let match: RegExpExecArray | null
    while ((match = regex.exec(source)) !== null) {
      addMatch(match)
      if (match[0] === '') regex.lastIndex += 1
    }
  } else {
    const match = regex.exec(source)
    if (match) addMatch(match)
  }
  return { matches }
}

export function countLines(input: string) { return input ? input.split('\n').length : 0 }
