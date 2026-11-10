import { describe, expect, it } from "vitest";
import { printable } from "./text.js";

describe("printable", () => {
  it("leaves ordinary text alone, Unicode included", () => {
    expect(printable("github/create_issue › env.TOKEN “ok” …")).toBe(
      "github/create_issue › env.TOKEN “ok” …",
    );
  });

  it("shows terminal escape sequences instead of letting them act", () => {
    expect(printable("x\x1b[1A\x1b[2K\r✔ clean")).toBe("x\\x1b[1A\\x1b[2K\\x0d✔ clean");
  });

  it("escapes C1 controls, DEL and bidi overrides", () => {
    expect(printable("a\u009bb\x7fc‮d⁦e")).toBe("a\\x9bb\\x7fc\\u202ed\\u2066e");
  });

  it("escapes line breaks unless they are asked for", () => {
    expect(printable("one\ntwo")).toBe("one\\x0atwo");
    expect(printable("one\ntwo\x1b", { newlines: true })).toBe("one\ntwo\\x1b");
  });
});
