import { useCallback, useEffect, useState } from "react";

export type Locale = "en-US" | "es-ES" | "fr-FR" | "hi-IN";

export const SUPPORTED_LOCALES: Locale[] = ["en-US", "es-ES", "fr-FR", "hi-IN"];

const STORAGE_KEY = "aegis.locale";
const FALLBACK: Locale = "en-US";

type Messages = Record<string, string>;

// Cache loaded locale payloads so subsequent calls don't re-fetch.
const cache = new Map<Locale, Messages>();

async function loadMessages(locale: Locale): Promise<Messages> {
  if (cache.has(locale)) return cache.get(locale)!;
  const res = await fetch(`/locales/${locale}.json`);
  if (!res.ok) throw new Error(`failed to load locale ${locale}: ${res.status}`);
  const data = (await res.json()) as { messages: Messages };
  cache.set(locale, data.messages);
  return data.messages;
}

/**
 * Interpolation: replace {key} occurrences in the message template with the
 * values from vars. Unknown keys are left intact (helps detect missing
 * translations in dev).
 */
function interpolate(template: string, vars?: Record<string, string | number>): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (m, key) => {
    return Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : m;
  });
}

export interface I18nAPI {
  locale: Locale;
  setLocale: (l: Locale) => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
  available: Locale[];
}

/**
 * useI18n — minimal React hook providing locale + translator. Persists
 * choice in localStorage and falls back to en-US if a key is missing
 * (instead of throwing).
 */
export function useI18n(): I18nAPI {
  const stored = (typeof window !== "undefined" && (localStorage.getItem(STORAGE_KEY) as Locale)) || FALLBACK;
  const [locale, setLocaleState] = useState<Locale>(SUPPORTED_LOCALES.includes(stored) ? stored : FALLBACK);
  const [messages, setMessages] = useState<Messages>(() => cache.get(FALLBACK)! ?? {});

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const m = await loadMessages(locale);
        if (!cancelled) setMessages(m);
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn(`[i18n] failed to load ${locale}, using fallback: ${e}`);
        if (locale !== FALLBACK) {
          const fb = await loadMessages(FALLBACK);
          if (!cancelled) setMessages(fb);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [locale]);

  const setLocale = useCallback((l: Locale) => {
    if (!SUPPORTED_LOCALES.includes(l)) return;
    try {
      localStorage.setItem(STORAGE_KEY, l);
    } catch {
      // storage may be disabled (private mode)
    }
    setLocaleState(l);
  }, []);

  const t = useCallback(
    (key: string, vars?: Record<string, string | number>): string => {
      const tmpl = messages[key];
      if (tmpl === undefined) {
        // missing translation — emit key so dev sees it. Always non-empty.
        return key;
      }
      return interpolate(tmpl, vars);
    },
    [messages],
  );

  return { locale, setLocale, t, available: SUPPORTED_LOCALES };
}
