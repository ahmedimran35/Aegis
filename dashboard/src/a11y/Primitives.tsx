import type { ReactNode } from "react";

/**
 * SkipLink — WCAG 2.4.1 Bypass Blocks: keyboard-only "Skip to main content"
 * link invisible until focused. Toggled via tabindex/style for SR users too.
 */
export function SkipLink({ targetId = "main-content", children = "Skip to main content" }: { targetId?: string; children?: ReactNode }) {
  return (
    <a
      href={`#${targetId}`}
      className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-[200] focus:rounded focus:bg-ink-900 focus:px-3 focus:py-2 focus:text-ink-50 focus:shadow"
    >
      {children}
    </a>
  );
}

/**
 * VisuallyHidden — for SR-only labels (aria-label companions).
 */
export function VisuallyHidden({ children }: { children: ReactNode }) {
  return <span className="sr-only">{children}</span>;
}

/**
 * A11yLiveRegion — polite live region for status/error announcements.
 * Add this once at the root. Push messages via window.aegisAnnounce.
 */
export function A11yLiveRegion() {
  if (typeof window !== "undefined") {
    (window as any).aegisAnnounce = (msg: string) => {
      const el = document.getElementById("aegis-live");
      if (el) el.textContent = msg;
    };
  }
  return (
    <div
      id="aegis-live"
      role="status"
      aria-live="polite"
      aria-atomic="true"
      className="sr-only"
    />
  );
}
