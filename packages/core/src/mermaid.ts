import { CAPABILITIES, CAPABILITY_LABELS } from "./capabilities.js";
import type { AttackGraph, Capability } from "./types.js";

const IDS: Record<Capability, string> = {
  "untrusted-content": "untrusted",
  "private-data": "privdata",
  "external-comms": "egress",
};

/** Mermaid flowchart of the trifecta legs; renders in GitHub markdown and PR comments. */
export function attackGraphToMermaid(graph: AttackGraph): string {
  const lines = ["flowchart LR"];
  for (const [i, capability] of CAPABILITIES.entries()) {
    const id = IDS[capability];
    lines.push(`  subgraph ${id}["${i + 1}. ${CAPABILITY_LABELS[capability]}"]`);
    const refs = graph[capability];
    if (refs.length === 0) lines.push(`    ${id}_none["none found"]`);
    for (const [j, ref] of refs.entries()) {
      lines.push(`    ${id}_${j}["${label(`${ref.serverName}/${ref.toolName}`)}"]`);
    }
    lines.push("  end");
  }
  lines.push(`  ${IDS["untrusted-content"]} -->|"injected instructions"| ${IDS["private-data"]}`);
  lines.push(`  ${IDS["private-data"]} -->|"stolen data"| ${IDS["external-comms"]}`);
  return lines.join("\n");
}

/** Tool and server names come from the scanned server: escape them for Mermaid. */
function label(text: string): string {
  return text
    .replace(/\p{Cc}/gu, " ")
    .replace(/#/g, "#35;")
    .replace(/"/g, "#quot;")
    .replace(/</g, "#lt;")
    .replace(/>/g, "#gt;")
    .replace(/`/g, "#96;");
}
