// Tool names, descriptions, server names and server error text come from whatever is being
// scanned. A terminal acts on escape sequences in them: a hostile server could erase a finding,
// print a fake all-clear, or reorder text with bidi controls. Anything shown to a person goes
// through printable() first.

/** C0 and C1 controls (ESC, CR, ...) and DEL, plus the bidi controls that reorder text. */
const UNPRINTABLE = /\p{Cc}|[‪-‮⁦-⁩]/gu;
const UNPRINTABLE_KEEPING_NEWLINES = /(?!\n)\p{Cc}|[‪-‮⁦-⁩]/gu;

/**
 * Shows control characters as escapes ("\x1b", "‮") instead of letting them act.
 * With `newlines`, "\n" stays a line break: only for text whose line breaks are Hecate's own.
 */
export function printable(text: string, { newlines = false } = {}): string {
  return text.replace(newlines ? UNPRINTABLE_KEEPING_NEWLINES : UNPRINTABLE, (c) => {
    const code = c.codePointAt(0) ?? 0;
    return code < 0x100
      ? `\\x${code.toString(16).padStart(2, "0")}`
      : `\\u${code.toString(16).padStart(4, "0")}`;
  });
}
