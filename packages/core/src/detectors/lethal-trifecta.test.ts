import { describe, expect, it } from "vitest";
import { scan } from "../index.js";
import type { MCPServerSurface } from "../types.js";

const params = (...names: string[]) => ({
  type: "object",
  properties: Object.fromEntries(names.map((n) => [n, { type: "string" }])),
});
const fetchServer: MCPServerSurface = {
  serverName: "fetch",
  source: "test",
  tools: [{ name: "fetch", description: "Fetches a URL.", inputSchema: params("url") }],
};
const filesystem: MCPServerSurface = {
  serverName: "filesystem",
  source: "test",
  tools: [
    { name: "read_file", inputSchema: params("path") },
    { name: "write_file", inputSchema: params("path", "content") },
  ],
};
const github: MCPServerSurface = {
  serverName: "github",
  source: "test",
  tools: [
    { name: "get_issue", inputSchema: params("owner", "repo", "issue_number") },
    { name: "get_file_contents", inputSchema: params("owner", "repo", "path") },
    { name: "create_pull_request", inputSchema: params("owner", "repo", "title", "body") },
  ],
};
const mcp005 = (surfaces: MCPServerSurface[]) =>
  scan(surfaces).filter((f) => f.ruleId === "MCP005");

describe("lethal trifecta (MCP005)", () => {
  it("flags a trifecta that only exists across servers", () => {
    const [finding, ...rest] = mcp005([fetchServer, filesystem]);
    expect(rest).toEqual([]);
    expect(finding.severity).toBe("high");
    expect(finding.serverName).toBeUndefined(); // an agent-level finding
    expect(finding.detail).toMatch(/span 2 servers \(fetch, filesystem\)/);
    expect(finding.attackGraph?.["private-data"].map((t) => t.toolName)).toEqual(["read_file"]);
  });

  it("does not flag either of those servers on its own", () => {
    expect(mcp005([fetchServer])).toEqual([]);
    expect(mcp005([filesystem])).toEqual([]);
  });

  it("flags a single server that provides all three legs", () => {
    const [finding] = mcp005([github]);
    expect(finding.detail).toMatch(/"github" provides all three legs/);
  });

  it("runs once per agent, not once per server", () => {
    expect(mcp005([github, fetchServer, filesystem])).toHaveLength(1);
  });
});
