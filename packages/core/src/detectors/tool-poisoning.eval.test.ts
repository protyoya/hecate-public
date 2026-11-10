// MCP001 against MCPTox (Wang et al., AAAI 2026, https://arxiv.org/abs/2508.14925): the real tool
// definitions of 45 MCP servers, and the poisoned tools written for them. Skipped unless the data
// has been fetched (it has no license, so it isn't committed):
//   node scripts/fetch-mcptox.mjs && MCPTOX_DIR=.cache/mcptox pnpm --filter @hecate-mcp/core test
// The poisoned tools are split in half by a hash of their id. Rule changes are tuned against the
// dev half only; the held-out half is the honest number, and the one reported.
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { MCPTool } from "../types.js";
import { toolPoisoning } from "./tool-poisoning.js";

const dir = process.env.MCPTOX_DIR && resolve(process.cwd(), "../..", process.env.MCPTOX_DIR);
const ready = !!dir && existsSync(join(dir, "benign.json"));

interface Benign {
  server: string;
  tool: MCPTool;
}
interface Attack extends Benign {
  id: string;
  risk: string;
  template: string;
}

const flagged = (server: string, tool: MCPTool) =>
  toolPoisoning.detect?.(
    { serverName: server, source: "mcptox", tools: [tool] },
    {
      policy: { version: 1, capabilities: [], ignore: [] },
    },
  ).length !== 0;

const heldOut = (id: string) => createHash("sha256").update(id).digest()[0] % 2 === 1;
const pct = (n: number, of: number) => `${((100 * n) / of).toFixed(1)}% (${n}/${of})`;

describe.skipIf(!ready)("MCP001 on MCPTox", () => {
  const benign: Benign[] = ready ? JSON.parse(readFileSync(join(dir, "benign.json"), "utf8")) : [];
  const attacks: Attack[] = ready
    ? JSON.parse(readFileSync(join(dir, "attacks.json"), "utf8"))
    : [];

  it("reports detection and false positives", () => {
    const falsePositives = benign.filter((b) => flagged(b.server, b.tool));
    const split = (held: boolean) => attacks.filter((a) => heldOut(a.id) === held);
    const caught = (list: Attack[]) => list.filter((a) => flagged(a.server, a.tool));
    const byGroup = (list: Attack[], key: "template" | "risk") =>
      Object.fromEntries(
        [...new Set(list.map((a) => a[key]))]
          .sort()
          .map((g) => [
            g,
            pct(
              caught(list.filter((a) => a[key] === g)).length,
              list.filter((a) => a[key] === g).length,
            ),
          ]),
      );
    const held = split(true);
    const dev = split(false);
    console.log(
      JSON.stringify(
        {
          falsePositives: pct(falsePositives.length, benign.length),
          heldOutDetection: pct(caught(held).length, held.length),
          devDetection: pct(caught(dev).length, dev.length),
          heldOutByTemplate: byGroup(held, "template"),
          heldOutByRisk: byGroup(held, "risk"),
          falsePositiveTools: falsePositives.map((b) => `${b.server}/${b.tool.name}`),
        },
        null,
        2,
      ),
    );
    if (process.env.MCPTOX_DEV) {
      // Tuning aid: the dev half's misses. Never print the held-out half's.
      for (const a of dev.filter((x) => !flagged(x.server, x.tool)))
        console.log(`MISS ${a.template} ${a.risk}: ${a.tool.description?.slice(0, 220)}`);
    }
    expect(benign.length).toBeGreaterThan(300);
  });
});
