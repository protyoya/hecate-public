import { describe, expect, it } from "vitest";
import { attackGraph } from "./capabilities.js";
import { scan } from "./index.js";
import { applyIgnores, expiredIgnores, parsePolicy } from "./policy.js";
import type { Finding, MCPServerSurface, Policy } from "./types.js";

const policy = (p: Partial<Policy>): Policy => ({ version: 1, capabilities: [], ignore: [], ...p });
const finding = (f: Partial<Finding>): Finding => ({
  ruleId: "MCP001",
  severity: "critical",
  title: "t",
  detail: "d",
  remediation: "r",
  ...f,
});
const on = (date: string) => new Date(`${date}T12:00:00Z`);

describe("parsePolicy", () => {
  it("accepts a full policy and defaults missing sections", () => {
    const raw = {
      $schema: "./hecate.policy.schema.json",
      version: 1,
      capabilities: [{ server: "fetch", tool: "fetch", "external-comms": false, reason: "proxy" }],
      ignore: [{ rule: "MCP005", reason: "sandboxed", expires: "2026-12-31" }],
    };
    expect(parsePolicy(raw)).toEqual({
      version: 1,
      capabilities: raw.capabilities,
      ignore: raw.ignore,
    });
    expect(parsePolicy({ version: 1 })).toEqual(policy({}));
  });

  it.each([
    ["an unsupported version", { version: 2 }, /Unsupported policy version 2/],
    [
      "a typo'd capability",
      { version: 1, capabilities: [{ server: "s", "privat-data": false, reason: "r" }] },
      /unknown key "privat-data"/,
    ],
    [
      "an override that sets nothing",
      { version: 1, capabilities: [{ server: "s", reason: "r" }] },
      /set at least one/,
    ],
    [
      "a non-boolean capability",
      { version: 1, capabilities: [{ server: "s", "private-data": "no", reason: "r" }] },
      /true or false/,
    ],
    [
      "an unknown rule",
      { version: 1, ignore: [{ rule: "MCP05", reason: "r" }] },
      /unknown rule "MCP05"/,
    ],
    [
      "a missing reason",
      { version: 1, ignore: [{ rule: "MCP005" }] },
      /"reason" must be a non-empty string/,
    ],
    ["a blank reason", { version: 1, ignore: [{ rule: "MCP005", reason: "  " }] }, /"reason"/],
    [
      "a malformed expiry",
      { version: 1, ignore: [{ rule: "MCP005", reason: "r", expires: "31/12/2026" }] },
      /"expires"/,
    ],
    [
      "ignore that is not a list",
      { version: 1, ignore: { rule: "MCP005" } },
      /ignore must be an array/,
    ],
  ])("rejects %s", (_label, raw, error) => {
    expect(() => parsePolicy(raw)).toThrow(error);
  });
});

describe("applyIgnores", () => {
  const poisoned = finding({ ruleId: "MCP001", serverName: "trivia", toolName: "get_trivia" });
  const trifecta = finding({ ruleId: "MCP005", severity: "high" });

  it("suppresses matching findings, keeping the reason", () => {
    const p = policy({
      ignore: [{ rule: "MCP001", server: "trivia", tool: "get_trivia", reason: "reviewed" }],
    });
    const [f] = applyIgnores([poisoned], p);
    expect(f.suppressed).toEqual({ reason: "reviewed" });
  });

  it("does not match when server or tool differ", () => {
    const p = policy({ ignore: [{ rule: "MCP001", tool: "other", reason: "r" }] });
    expect(applyIgnores([poisoned], p)[0].suppressed).toBeUndefined();
  });

  it("matches agent-level findings only with rule-wide entries", () => {
    const scoped = policy({ ignore: [{ rule: "MCP005", server: "fetch", reason: "r" }] });
    expect(applyIgnores([trifecta], scoped)[0].suppressed).toBeUndefined();
    const ruleWide = policy({ ignore: [{ rule: "MCP005", reason: "r" }] });
    expect(applyIgnores([trifecta], ruleWide)[0].suppressed).toEqual({ reason: "r" });
  });

  it("applies through the expiry day (UTC) and not after", () => {
    const p = policy({ ignore: [{ rule: "MCP005", reason: "r", expires: "2026-06-30" }] });
    expect(applyIgnores([trifecta], p, on("2026-06-30"))[0].suppressed).toEqual({
      reason: "r",
      expires: "2026-06-30",
    });
    expect(applyIgnores([trifecta], p, on("2026-07-01"))[0].suppressed).toBeUndefined();
    expect(expiredIgnores(p, on("2026-07-01"))).toEqual(p.ignore);
    expect(expiredIgnores(p, on("2026-06-30"))).toEqual([]);
  });
});

describe("policy in scan", () => {
  const params = (...names: string[]) => ({
    type: "object",
    properties: Object.fromEntries(names.map((n) => [n, {}])),
  });
  const fetchServer: MCPServerSurface = {
    serverName: "fetch",
    source: "t",
    tools: [{ name: "fetch", inputSchema: params("url") }],
  };
  const filesystem: MCPServerSurface = {
    serverName: "fs",
    source: "t",
    tools: [{ name: "read_file" }],
  };
  const mcp005 = (p: Policy) =>
    scan([fetchServer, filesystem], { policy: p }).filter((f) => f.ruleId === "MCP005");

  it("a capability override that removes a leg breaks the trifecta", () => {
    const p = policy({
      capabilities: [
        { server: "fetch", tool: "fetch", "external-comms": false, reason: "allowlisted egress" },
      ],
    });
    expect(mcp005(policy({}))).toHaveLength(1);
    expect(mcp005(p)).toEqual([]);
  });

  it("an ignore entry keeps the trifecta visible but suppressed", () => {
    const [f] = mcp005(policy({ ignore: [{ rule: "MCP005", reason: "sandboxed agent" }] }));
    expect(f.suppressed).toEqual({ reason: "sandboxed agent" });
  });

  it("overrides can add a leg the heuristics missed, for every tool on a server", () => {
    const custom: MCPServerSurface = {
      serverName: "crm",
      source: "t",
      tools: [{ name: "a" }, { name: "b" }],
    };
    const graph = attackGraph(
      [custom],
      [{ server: "crm", "private-data": true, reason: "customer records" }],
    );
    expect(graph["private-data"]).toEqual([
      { serverName: "crm", toolName: "a", evidence: ["policy: customer records"] },
      { serverName: "crm", toolName: "b", evidence: ["policy: customer records"] },
    ]);
  });

  it("later overrides win", () => {
    const graph = attackGraph(
      [filesystem],
      [
        { server: "fs", "private-data": false, reason: "a" },
        { server: "fs", tool: "read_file", "private-data": true, reason: "b" },
      ],
    );
    expect(graph["private-data"].map((t) => t.evidence)).toEqual([["policy: b"]]);
  });
});

describe("parsePolicy guard section", () => {
  it("fills safe defaults", () => {
    expect(parsePolicy({ version: 1, guard: {} }).guard).toEqual({
      tools: { allow: [], deny: [] },
      approve: [],
      approveExec: true,
      approveEgressAfterUntrusted: true,
    });
  });

  it("reads every field", () => {
    const guard = {
      tools: { allow: ["github/*"], deny: ["github/delete_*"] },
      approve: ["*/send_*"],
      approveExec: false,
      approveEgressAfterUntrusted: false,
      egress: { allow: ["api.github.com", "*.slack.com"] },
    };
    expect(parsePolicy({ version: 1, guard }).guard).toEqual(guard);
  });

  it.each([
    ["an unknown key", { aprove: [] }, /unknown key "aprove"/],
    [
      "a bare tool name",
      { approve: ["send_email"] },
      /must be "server\/tool" \(use "\*\/send_email"/,
    ],
    ["a non-boolean flag", { approveExec: "yes" }, /"approveExec" must be true or false/],
    [
      "an empty host",
      { egress: { allow: [""] } },
      /guard.egress.allow\[0\] must be a non-empty string/,
    ],
  ])("rejects %s", (_label, guard, error) => {
    expect(() => parsePolicy({ version: 1, guard })).toThrow(error);
  });
});
