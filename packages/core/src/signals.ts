import { isObject } from "./json.js";
import type { MCPTool } from "./types.js";

// Shared by the heuristic classifiers (MCP004, MCP005): match words in tool
// names and parameter names, and phrases in descriptions, recording what
// matched as evidence.

/** A whole-word alternation, e.g. words("read|get"). */
export const words = (alternatives: string) => new RegExp(`\\b(?:${alternatives})\\b`);

export interface ToolText {
  /** Lower-case words: `sendEmail` and `send_email` both become "send email". */
  name: string;
  /** Original parameter names, with their normalized form. */
  params: { raw: string; words: string }[];
  description: string;
}

export function toolText(tool: MCPTool): ToolText {
  const schema = tool.inputSchema;
  const properties = isObject(schema) && isObject(schema.properties) ? schema.properties : {};
  return {
    name: toWords(tool.name),
    params: Object.keys(properties).map((raw) => ({ raw, words: toWords(raw) })),
    description: (tool.description ?? "").trim().toLowerCase(),
  };
}

export function toWords(identifier: string): string {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/[^A-Za-z0-9]+/g, " ")
    .trim()
    .toLowerCase();
}

export function inName(t: ToolText, first: RegExp, second?: RegExp): string | undefined {
  const a = first.exec(t.name);
  if (!a) return undefined;
  if (!second) return `name: ${a[0]}`;
  // A different word than the verb: "comment" alone is not "comment + issue".
  const b = [...t.name.matchAll(new RegExp(second.source, "g"))].find((m) => m.index !== a.index);
  return b ? `name: ${a[0]} + ${b[0]}` : undefined;
}

export function inParam(t: ToolText, pattern: RegExp): string | undefined {
  const param = t.params.find((p) => pattern.test(p.words));
  return param && `parameter: ${param.raw}`;
}

export function inDescription(t: ToolText, pattern: RegExp): string | undefined {
  const m = pattern.exec(t.description);
  return m ? `description: "${m[0]}"` : undefined;
}
