import { useI18n, type Locale } from '../i18n'

const LOCALE_NAMES: Record<Locale, string> = {
  'en-US': 'English (US)',
  'es-ES': 'Español',
  'fr-FR': 'Français',
  'hi-IN': 'हिन्दी',
}

export default function LocaleSwitcher() {
  const { locale, setLocale, available } = useI18n()
  return (
    <label className="flex items-center gap-2 text-sm text-slate-300" aria-label="Interface language">
      <span aria-hidden="true">🌐</span>
      <select
        value={locale}
        onChange={(e) => setLocale(e.target.value as Locale)}
        className="bg-ink-800 border border-ink-700 rounded px-2 py-1 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-forest-500"
      >
        {available.map((l) => (
          <option key={l} value={l}>
            {LOCALE_NAMES[l]}
          </option>
        ))}
      </select>
    </label>
  )
}
