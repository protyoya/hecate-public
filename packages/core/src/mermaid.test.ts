import { describe, expect, it } from "vitest";
import { attackGraphToMermaid } from "./mermaid.js";
import type { AttackGraph } from "./types.js";

const ref = (serverName: string, toolName: string) => ({ serverName, toolName, evidence: [] });

describe("attackGraphToMermaid", () => {
  it("draws one subgraph per leg, linked in attack order", () => {
    const graph: AttackGraph = {
      "untrusted-content": [ref("fetch", "fetch")],
      "private-data": [ref("filesystem", "read_file"), ref("filesystem", "list_directory")],
      "external-comms": [ref("fetch", "fetch")],
    };
    expect(attackGraphToMermaid(graph)).toBe(
      [
        "flowchart LR",
        '  subgraph untrusted["1. Untrusted content"]',
        '    untrusted_0["fetch/fetch"]',
        "  end",
        '  subgraph privdata["2. Private data"]',
        '    privdata_0["filesystem/read_file"]',
        '    privdata_1["filesystem/list_directory"]',
        "  end",
        '  subgraph egress["3. External communication"]',
        '    egress_0["fetch/fetch"]',
        "  end",
        '  untrusted -->|"injected instructions"| privdata',
        '  privdata -->|"stolen data"| egress',
      ].join("\n"),
    );
  });

  it("marks an empty leg", () => {
    const graph: AttackGraph = {
      "untrusted-content": [],
      "private-data": [],
      "external-comms": [],
    };
    expect(attackGraphToMermaid(graph)).toContain('untrusted_none["none found"]');
  });

  it("escapes names that could break out of a label", () => {
    const graph: AttackGraph = {
      "untrusted-content": [ref('evil"]\n  click x', "<b>#`x`</b>")],
      "private-data": [],
      "external-comms": [],
    };
    const line = attackGraphToMermaid(graph).split("\n")[2];
    expect(line).toBe('    untrusted_0["evil#quot;]   click x/#lt;b#gt;#35;#96;x#96;#lt;/b#gt;"]');
  });
});
