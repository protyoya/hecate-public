/** Whole-string, case-insensitive match where `*` matches anything (including "/"). */
export function globMatch(pattern: string, value: string): boolean {
  const source = pattern.split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"));
  return new RegExp(`^${source.join(".*")}$`, "i").test(value);
}
