import { describe, expect, it } from "vitest";
import { canonicalJson } from "./json.js";

describe("canonicalJson", () => {
  it("sorts object keys recursively and drops whitespace", () => {
    expect(canonicalJson({ b: 1, a: { d: [3, 1], c: "x" } })).toBe(
      '{"a":{"c":"x","d":[3,1]},"b":1}',
    );
  });

  it("is independent of key insertion order", () => {
    expect(canonicalJson({ x: 1, y: { p: 1, q: 2 } })).toBe(
      canonicalJson({ y: { q: 2, p: 1 }, x: 1 }),
    );
  });

  it("drops undefined object values and writes undefined array items as null", () => {
    expect(canonicalJson({ a: undefined, b: [undefined] })).toBe('{"b":[null]}');
  });

  it("escapes strings exactly like JSON.stringify", () => {
    const s = 'quote " backslash \\ newline \n zero-width ​';
    expect(canonicalJson({ s })).toBe(`{"s":${JSON.stringify(s)}}`);
  });
});
