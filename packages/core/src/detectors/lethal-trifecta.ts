import { CAPABILITIES, attackGraph } from "../capabilities.js";
import type { Finding, MCPServerSurface, Rule, RuleContext } from "../types.js";

const ID = "MCP005";
const SEVERITY = "high" as const;
const TITLE = "Lethal trifecta: untrusted content, private data and external communication";
const WHY =
  "One agent can read content an attacker controls, access private data, and send data " +
  "out. Text from the first can instruct it to do the other two.";

export const lethalTrifecta: Rule = {
  id: ID,
  severity: SEVERITY,
  title: TITLE,
  detectAgent(surfaces: MCPServerSurface[], ctx: RuleContext): Finding[] {
    const graph = attackGraph(surfaces, ctx.policy.capabilities);
    if (CAPABILITIES.some((capability) => graph[capability].length === 0)) return [];

    const servers = [
      ...new Set(CAPABILITIES.flatMap((capability) => graph[capability].map((t) => t.serverName))),
    ];
    const where =
      servers.length === 1
        ? `Server "${servers[0]}" provides all three legs on its own.`
        : `The legs span ${servers.length} servers (${servers.join(", ")}).`;
    return [
      {
        ruleId: ID,
        severity: SEVERITY,
        title: TITLE,
        detail: `${WHY} ${where}`,
        remediation:
          "Remove a leg for this agent: drop one group of tools, split them across separate " +
          "agents, or require human approval before external-communication tools run. " +
          "Classification is heuristic; see the evidence with `hecate graph --format json`.",
        attackGraph: graph,
      },
    ];
  },
};
