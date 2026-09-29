import { describe, expect, it } from "vitest";
import { surfacesFromJson } from "../config.js";
import { parsePolicy, scan } from "../index.js";
import type { Policy } from "../types.js";

const findings = (servers: Record<string, unknown>, rule: string, policy?: Policy) =>
  scan(surfacesFromJson({ mcpServers: servers }, "c.json"), { policy })
    .filter((f) => f.ruleId === rule)
    .map((f) => [f.serverName, f.severity, f.title, f.field]);

describe("known-bad servers (MCP007)", () => {
  it("flags a known-malicious package at any version", () => {
    expect(findings({ mail: { command: "npx", args: ["-y", "postmark-mcp"] } }, "MCP007")).toEqual([
      ["mail", "critical", "Known-malicious MCP server package", "args[1]"],
    ]);
  });

  it("flags a known-vulnerable version only when it is pinned inside the affected range", () => {
    const at = (version?: string) =>
      findings(
        {
          r: {
            command: "npx",
            args: [version ? `mcp-remote@${version}` : "mcp-remote", "https://x"],
          },
        },
        "MCP007",
      );
    expect(at("0.1.15")).toEqual([
      ["r", "high", "MCP server version with a known exploitable vulnerability", "args[0]"],
    ]);
    expect(at("0.1.16")).toEqual([]);
    expect(at("0.0.4")).toEqual([]);
    expect(at()).toEqual([]); // unpinned resolves to the fixed latest (MCP008 flags the pinning)
  });

  const policy = parsePolicy({
    version: 1,
    servers: {
      allow: [
        { package: "@modelcontextprotocol/*", reason: "official reference servers" },
        { url: "https://mcp.linear.app/*", reason: "vendor-hosted" },
        { image: "ghcr.io/github/github-mcp-server", reason: "official image" },
      ],
      deny: [
        {
          package: "@modelcontextprotocol/server-everything",
          reason: "test server, exposes everything",
        },
      ],
    },
  });

  it("enforces the policy deny list and allowlist", () => {
    const servers = {
      fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] },
      linear: { url: "https://mcp.linear.app/sse" },
      gh: { command: "docker", args: ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"] },
      everything: { command: "npx", args: ["@modelcontextprotocol/server-everything"] },
      random: { command: "npx", args: ["-y", "some-random-mcp"] },
      local: { command: "node", args: ["server.js"] },
    };
    expect(findings(servers, "MCP007", policy)).toEqual([
      ["everything", "high", "Server is on the policy deny list", "args[0]"],
      ["random", "high", "Server is not on the policy allowlist", "args[1]"],
      ["local", "high", "Server is not on the policy allowlist", "command"],
    ]);
  });

  it.each([
    ["an unknown list", { allowed: [] }, /unknown key "allowed"/],
    ["an entry without a matcher", { deny: [{ reason: "r" }] }, /set at least one of package/],
    ["an entry without a reason", { allow: [{ package: "x" }] }, /"reason"/],
  ])("rejects a policy with %s", (_label, servers, error) => {
    expect(() => parsePolicy({ version: 1, servers })).toThrow(error);
  });
});

describe("unpinned or insecure source (MCP008)", () => {
  it("flags packages and images that aren't pinned to one release", () => {
    const servers = {
      a: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem"] },
      b: { command: "npx", args: ["pkg@^1.0.0"] },
      c: { command: "npx", args: ["pkg@1.0.0"] },
      d: { command: "uvx", args: ["mcp-server-git"] },
      e: { command: "uvx", args: ["mcp-server-git==2025.1.14"] },
      f: { command: "docker", args: ["run", "mcp/fetch"] },
      g: { command: "docker", args: ["run", "mcp/fetch:latest"] },
      h: { command: "docker", args: ["run", "mcp/fetch:1.2"] },
      i: { command: "node", args: ["server.js"] },
    };
    expect(
      findings(servers, "MCP008").map(([server, severity, title]) => [server, severity, title]),
    ).toEqual([
      ["a", "medium", "Package version is not pinned"],
      ["b", "medium", "Package version is not pinned"],
      ["d", "medium", "Package version is not pinned"],
      ["f", "medium", "Container image is not pinned"],
      ["g", "medium", "Container image is not pinned"],
    ]);
  });

  it("flags remote servers over plain HTTP, except on this machine", () => {
    const servers = {
      remote: { url: "http://mcp.example.com/mcp" },
      tls: { url: "https://mcp.example.com/mcp" },
      local: { url: "http://localhost:3000/mcp" },
      loopback: { type: "sse", url: "http://127.0.0.1:8080/sse" },
    };
    expect(findings(servers, "MCP008")).toEqual([
      ["remote", "high", "Remote server over plain HTTP", "url"],
    ]);
  });
});
