export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Deterministic JSON: object keys sorted by UTF-16 code unit (as in RFC 8785),
 * no whitespace, undefined object values dropped. Array order is kept — it can
 * be meaningful (e.g. enum, anyOf).
 */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isObject(value)) {
    const members = Object.keys(value)
      .sort()
      .filter((key) => value[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
    return `{${members.join(",")}}`;
  }
  // JSON.stringify(undefined) is undefined; inside arrays JSON writes null.
  return JSON.stringify(value) ?? "null";
}
