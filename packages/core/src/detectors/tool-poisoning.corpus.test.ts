import { describe, expect, it } from "vitest";
import type { MCPTool } from "../types.js";
import { ATTACKS, BENIGN, type Case } from "./tool-poisoning.corpus.js";
import { poisoningHits } from "./tool-poisoning.js";

const tool = (c: Case): MCPTool => ({
  name: "the_tool",
  description: c.description,
  ...(c.param && {
    inputSchema: {
      type: "object",
      properties: { value: { type: "string", description: c.param } },
    },
  }),
});
const explain = (c: Case) =>
  JSON.stringify(poisoningHits(tool(c), c.siblings).hits.map((h) => [h.label, h.evidence]));

describe("MCP001 corpus: legitimate instructions are not flagged", () => {
  for (const c of BENIGN) {
    it(c.why, () => {
      const { severity } = poisoningHits(tool(c), c.siblings);
      expect(severity, explain(c)).toBeUndefined();
    });
  }
});

describe("MCP001 corpus: attacks are flagged", () => {
  for (const c of ATTACKS) {
    it(c.why, () => {
      expect(poisoningHits(tool(c), c.siblings).severity, explain(c)).toBeDefined();
    });
  }
});
