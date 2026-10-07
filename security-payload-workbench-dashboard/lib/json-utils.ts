export type JsonIndentation = 2 | 4 | 'tab'

export function parseJsonInput(input: string): unknown {
  return JSON.parse(input)
}

export function formatJsonValue(value: unknown, indentation: JsonIndentation): string {
  return JSON.stringify(value, null, indentation === 'tab' ? '\t' : indentation)
}

export function minifyJsonValue(value: unknown): string {
  return JSON.stringify(value)
}

export function formatJsonInput(input: string, indentation: JsonIndentation): string {
  return formatJsonValue(parseJsonInput(input), indentation)
}

export function minifyJsonInput(input: string): string {
  return minifyJsonValue(parseJsonInput(input))
}

export function getJsonErrorMessage(error: unknown): string {
  return error instanceof SyntaxError ? error.message : 'Unable to parse this JSON value.'
}

export function validateJsonInput(input: string): { valid: true; value: unknown } | { valid: false; error: string } {
  if (!input.trim()) return { valid: false, error: 'Enter JSON to validate.' }
  try {
    return { valid: true, value: parseJsonInput(input) }
  } catch (error) {
    return { valid: false, error: getJsonErrorMessage(error) }
  }
}

export function indentLabel(indentation: JsonIndentation) {
  return indentation === 'tab' ? 'Tabs' : `${indentation} spaces`
}

export function getJsonErrorLine(input: string, errorMessage: string) {
  const position = errorMessage.match(/position (\d+)/i)?.[1]
  if (!position) return null
  return input.slice(0, Number(position)).split('\n').length
}

export function validateAndFormatJson(input: string, indentation: JsonIndentation) {
  const result = validateJsonInput(input)
  if (!result.valid) return result
  return { valid: true as const, value: result.value, formatted: formatJsonValue(result.value, indentation), minified: minifyJsonValue(result.value) }
}

export function formatJsonError(input: string, error: unknown) {
  const message = getJsonErrorMessage(error)
  const line = getJsonErrorLine(input, message)
  return line ? `${message} (line ${line})` : message
}
