// Pattern validation helpers for user-supplied regex patterns.
//
// P-FIX (M-6): a user-controlled regex is a ReDoS attack surface.
// We surface a few warning levels to the UI:
//   - invalid   : pattern does not compile
//   - too_long  : pattern exceeds 1024 chars (server limit)
//   - nested    : pattern contains nested quantifiers like (a+)+ or
//                 (.*)* which can blow up CPU on adversarial input
//   - looks_risky: pattern has overlapping or unbounded quantifiers
//                  (.*, .+, or [.*]+) — not strictly dangerous but worth
//                  warning the operator before they ship it

export type RegexCheckLevel = 'ok' | 'warning' | 'invalid'

export interface RegexCheckResult {
  level: RegexCheckLevel
  reason?: string
}

const MAX_PATTERN_LEN = 1024

// Nested-quantifier detector. Walks the pattern looking for a quantified
// group immediately followed by another quantifier (e.g. `(a+)+`,
// `(?:x*)*`, `(ab+){2,5}`). The actual dangerous form is when both
// quantifiers are unbounded, but flagging all of them is conservative.
function hasNestedQuantifier(pattern: string): boolean {
  let depth = 0
  let i = 0
  for (; i < pattern.length; i++) {
    const c = pattern[i]
    if (c === '\\') { i++; continue }
    if (c === '[') {
      // Skip character class entirely; we do not analyze inside [...] as
      // quantifiers there are literals.
      while (i < pattern.length && pattern[i] !== ']') {
        if (pattern[i] === '\\') i++
        i++
      }
      continue
    }
    if (c === '(') { depth++; continue }
    if (c === ')') {
      depth--
      // Look at next char — if it's a quantifier, flag it.
      const next = pattern[i + 1]
      if (next && '*+?{'.includes(next)) {
        return true
      }
      continue
    }
  }
  // Also detect quantifier-of-quantifier inside: e.g. `+?` (lazy) is
  // fine; `*+` (possessive, if supported) is fine; but `++` etc. are
  // technically invalid. The above check catches the common cases.
  return false
}

// Heuristic for "looks risky" patterns. Not exhaustive — just a hint.
function looksRisky(pattern: string): boolean {
  // `.*` / `.+` followed by `*` / `+` is the canonical ReDoS source.
  // (`.*.*` and similar). We don't try to fully analyze; we look for
  // a quantifier directly adjacent to another quantifier outside a class.
  if (/[+*]\s*[+*]/.test(pattern)) return true
  if (/\.\*.*\*\)/.test(pattern)) return true
  if (/\.\+.*\+\)/.test(pattern)) return true
  return false
}

export function checkRegexPattern(pattern: string): RegexCheckResult {
  if (!pattern) return { level: 'invalid', reason: 'Pattern is empty' }
  if (pattern.length > MAX_PATTERN_LEN) {
    return { level: 'invalid', reason: `Pattern too long (max ${MAX_PATTERN_LEN} chars)` }
  }
  try {
    // Compile without the `u` flag — the engine is Go's RE2-compatible
    // subset, which already avoids catastrophic backtracking. The UI
    // check is a defense-in-depth hint, not the primary safeguard.
    new RegExp(pattern)
  } catch (e) {
    return { level: 'invalid', reason: e instanceof Error ? e.message : 'Invalid regex' }
  }
  if (hasNestedQuantifier(pattern)) {
    return {
      level: 'warning',
      reason: 'Pattern contains nested quantifiers (e.g. (a+)+). May cause high CPU on adversarial input.',
    }
  }
  if (looksRisky(pattern)) {
    return {
      level: 'warning',
      reason: 'Pattern looks risky: overlapping or unbounded quantifiers. Review before saving.',
    }
  }
  return { level: 'ok' }
}
