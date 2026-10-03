export type ThemePreference = 'light' | 'dark' | 'system'

export function parseThemePreference(value: string | null | undefined): ThemePreference {
  return value === 'light' || value === 'dark' || value === 'system' ? value : 'system'
}

export function isDarkTheme(preference: ThemePreference, systemPrefersDark: boolean): boolean {
  return preference === 'dark' || (preference === 'system' && systemPrefersDark)
}
