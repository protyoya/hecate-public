import { hashTool } from "../pins.js";
import type { Finding, MCPServerSurface, RuleInfo, ServerPins } from "../types.js";

const ID = "MCP002";

export const rugPull: RuleInfo = {
  id: ID,
  severity: "high",
  title: "Tool definitions changed since they were pinned (rug pull)",
};
const WHY =
  "MCP servers can change tool definitions after you approve them (a rug pull) " +
  "to inject instructions or widen what a tool does.";

/**
 * MCP002 rug pull: diffs a server's tools against its pinned snapshot.
 * Unlike the rules in the registry it needs a baseline, so it runs here
 * (`hecate check`) rather than through scan(). `pinned` is undefined when the
 * server has never been pinned: every tool is then unapproved.
 */
export async function checkPins(
  surface: MCPServerSurface,
  pinned: ServerPins | undefined,
): Promise<Finding[]> {
  const pins = pinned?.tools ?? {};
  const findings: Finding[] = [];
  const served = new Set<string>();

  // Duplicate names are checked one by one, so a second, different definition
  // under a pinned name is still caught.
  for (const tool of surface.tools) {
    served.add(tool.name);
    const expected = Object.hasOwn(pins, tool.name) ? pins[tool.name] : undefined;
    if (expected === undefined) {
      findings.push({
        ruleId: ID,
        severity: "high",
        title: "Tool is not in the pinned snapshot",
        detail:
          pinned === undefined
            ? `Server "${surface.serverName}" has no pinned snapshot, so tool "${tool.name}" was never approved.`
            : `Tool "${tool.name}" was not served when "${surface.serverName}" was pinned. ${WHY}`,
        serverName: surface.serverName,
        toolName: tool.name,
        remediation: "Review the tool (run `hecate scan`), then approve it with `hecate pin`.",
      });
      continue;
    }
    const actual = await hashTool(tool);
    if (actual !== expected) {
      findings.push({
        ruleId: ID,
        severity: "high",
        title: "Tool definition changed since it was pinned (possible rug pull)",
        detail: `Tool "${tool.name}" no longer matches its pinned hash (pinned ${short(expected)}, now ${short(actual)}). ${WHY}`,
        serverName: surface.serverName,
        toolName: tool.name,
        remediation:
          "Diff the definition against the one you approved. If the change is expected, " +
          "re-approve it with `hecate pin`; otherwise stop using this server.",
      });
    }
  }

  for (const name of Object.keys(pins)) {
    if (served.has(name)) continue;
    findings.push({
      ruleId: ID,
      severity: "low",
      title: "Pinned tool is no longer served",
      detail: `Tool "${name}" was pinned for "${surface.serverName}" but is no longer served.`,
      serverName: surface.serverName,
      toolName: name,
      remediation: "If this is expected, run `hecate pin` to update the snapshot.",
    });
  }

  return findings;
}

const short = (hash: string) => `${hash.slice(0, "sha256:".length + 12)}…`;
