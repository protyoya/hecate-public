import { isObject } from "../json.js";
import type { Finding, MCPServerSurface, MCPTool, Rule, Severity } from "../types.js";

const ID = "MCP003";
const REFERENCE_TITLE = "Tool description refers to another server's tool (possible shadowing)";
const COLLISION_TITLE = "Tool name is served by more than one server";
/** In the sentence around a mention, these make it an instruction rather than a remark. */
const DIRECTIVE =
  /\b(?:when|whenever|before|after|instead|always|never|must|should|ensure|make sure|override|redirect|replace|important|bcc|cc|forward)\b/;
const EXCERPT_LENGTH = 160;
const COLLISION_WHY =
  "The model can call the wrong one, and a server can squat a trusted tool's name.";
const REFERENCE_WHY =
  "A tool that tells the model how other servers' tools should behave can hijack them, " +
  "e.g. silently adding a BCC to every email.";

export const toolShadowing: Rule = {
  id: ID,
  severity: "high",
  title: "Tool shadowing: a tool describes how another server's tools should behave",
  detectAgent(surfaces: MCPServerSurface[]): Finding[] {
    const servers = new Map<string, Set<string>>(); // tool name -> servers serving it
    for (const surface of surfaces) {
      for (const tool of surface.tools) {
        const set = servers.get(tool.name) ?? new Set();
        servers.set(tool.name, set.add(surface.serverName));
      }
    }
    return [...collisions(surfaces, servers), ...references(surfaces, servers)];
  },
};

function* collisions(
  surfaces: MCPServerSurface[],
  servers: Map<string, Set<string>>,
): Generator<Finding> {
  for (const surface of surfaces) {
    for (const tool of surface.tools) {
      const others = [...(servers.get(tool.name) ?? [])].filter((s) => s !== surface.serverName);
      if (others.length === 0) continue;
      yield {
        ruleId: ID,
        severity: "medium",
        title: COLLISION_TITLE,
        detail: `"${tool.name}" is also served by ${others.map((s) => `"${s}"`).join(", ")}. ${COLLISION_WHY}`,
        serverName: surface.serverName,
        toolName: tool.name,
        remediation:
          "Remove one of the servers, or confirm both are trusted and do the same thing.",
      };
    }
  }
}

function* references(
  surfaces: MCPServerSurface[],
  servers: Map<string, Set<string>>,
): Generator<Finding> {
  for (const surface of surfaces) {
    const own = new Set(surface.tools.map((t) => t.name));
    // Tools of other servers that this server doesn't also serve (then a mention could be its own).
    const foreign = [...servers]
      .filter(([name]) => !own.has(name) && name.length >= 3)
      .map(([name, owners]) => ({ name, owners: [...owners], pattern: mentionPattern(name) }));
    if (foreign.length === 0) continue;

    for (const tool of surface.tools) {
      const reported = new Set<string>();
      for (const [field, text] of descriptions(tool)) {
        for (const { name, owners, pattern } of foreign) {
          const match = pattern.exec(text);
          if (!match || reported.has(name)) continue;
          reported.add(name);
          const sentence = sentenceAround(text, match.index);
          const severity: Severity = DIRECTIVE.test(sentence.toLowerCase()) ? "high" : "medium";
          yield {
            ruleId: ID,
            severity,
            title: REFERENCE_TITLE,
            detail: `Tool "${tool.name}" mentions "${owners[0]}/${name}" from another server: "${excerpt(sentence)}". ${REFERENCE_WHY}`,
            serverName: surface.serverName,
            toolName: tool.name,
            field,
            remediation:
              "Check why this tool describes another server's tool. Tools should only describe " +
              "themselves; if this isn't expected, remove the server.",
          };
        }
      }
    }
  }
}

/**
 * Identifier-like names (send_email, db.query, getUser) as whole tokens;
 * plain words (search) only when quoted, or English prose would match.
 */
function mentionPattern(name: string): RegExp {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return /[_\-.\d]|[a-z][A-Z]/.test(name)
    ? new RegExp(`(?<![\\w-])${escaped}(?![\\w-])`, "i")
    : new RegExp(`[\`"']${escaped}[\`"']`, "i");
}

/** The tool's description and every description inside its input schema. */
function* descriptions(tool: MCPTool): Generator<[string, string]> {
  if (tool.description) yield ["description", tool.description];
  function* walk(value: unknown, field: string): Generator<[string, string]> {
    if (!isObject(value)) return;
    for (const [key, child] of Object.entries(value)) {
      const at = `${field}.${key}`;
      if (key === "description" && typeof child === "string") yield [at, child];
      else yield* walk(child, at);
    }
  }
  yield* walk(tool.inputSchema, "inputSchema");
}

function sentenceAround(text: string, index: number): string {
  const before = text.slice(0, index).search(/[.!?\n][^.!?\n]*$/);
  const after = text.slice(index).search(/[.!?\n](?:\s|$)/);
  return text.slice(before + 1, after < 0 ? undefined : index + after + 1).trim();
}

function excerpt(sentence: string): string {
  const clean = sentence.replace(/\p{Cc}/gu, " ").replace(/[.!?]$/, "");
  return clean.length > EXCERPT_LENGTH ? `${clean.slice(0, EXCERPT_LENGTH)}…` : clean;
}
