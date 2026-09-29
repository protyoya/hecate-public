import { describe, expect, it } from "vitest";
import { surfacesFromJson } from "../config.js";
import { scan } from "../index.js";
import type { MCPServerSurface } from "../types.js";

// Assembled at runtime so no token-shaped literal is committed (secret scanners).
const fake = (...parts: string[]) => parts.join("");
const GITHUB = fake("ghp", "_", "a1B2".repeat(9));
const ANTHROPIC = fake("sk-", "ant-", "api03-", "x".repeat(40));
const AWS = fake("AKIA", "IOSFODNN7", "EXAMPLE");

const mcp006 = (entry: Record<string, unknown>) =>
  scan(surfacesFromJson({ mcpServers: { srv: entry } }, "cfg.json")).filter(
    (f) => f.ruleId === "MCP006",
  );
const fields = (entry: Record<string, unknown>) => mcp006(entry).map((f) => [f.field, f.severity]);

describe("secrets exposure (MCP006) in client configs", () => {
  it("flags known token formats as high, wherever they are", () => {
    expect(
      fields({
        command: "npx",
        args: ["server", `--key=${AWS}`],
        env: { GITHUB_PERSONAL_ACCESS_TOKEN: GITHUB, ANTHROPIC_API_KEY: ANTHROPIC },
      }),
    ).toEqual([
      ["args[1]", "high"],
      ["env.GITHUB_PERSONAL_ACCESS_TOKEN", "high"],
      ["env.ANTHROPIC_API_KEY", "high"],
    ]);
  });

  it("never puts the secret itself in a finding", () => {
    const findings = mcp006({
      command: "x",
      env: { TOKEN: GITHUB, DB_PASSWORD: "correct-horse-battery" },
    });
    expect(findings).toHaveLength(2);
    const text = JSON.stringify(findings);
    expect(text).not.toContain(GITHUB.slice(4));
    expect(text).not.toContain("correct-horse");
    expect(findings[0].detail).toContain("a GitHub token (40 characters)");
  });

  it("flags literal values of secret-named keys and flags as medium", () => {
    expect(
      fields({
        command: "server",
        args: ["--api-key", "s3cr3t-value-123", "--token=abcdefgh1234"],
        env: { STRIPE_API_KEY: "rk_test_notarealkey123", clientSecret: "q9w8e7r6t5y4" },
      }),
    ).toEqual([
      ["args[1]", "medium"],
      ["args[2]", "medium"],
      ["env.STRIPE_API_KEY", "medium"],
      ["env.clientSecret", "medium"],
    ]);
  });

  it("flags literal credentials in headers and URLs", () => {
    expect(
      fields({
        url: "https://mcp.example.com/sse?api_key=abcdef123456",
        headers: { Authorization: "Bearer abcdefgh12345678" },
      }),
    ).toEqual([
      ["url", "medium"],
      ["headers.Authorization", "medium"],
    ]);
    expect(
      fields({ command: "x", args: ["postgresql://app:hunter2hunter2@db:5432/prod"] }),
    ).toEqual([["args[0]", "medium"]]);
  });

  it.each([
    [
      "env references",
      { command: "x", env: { GITHUB_TOKEN: "${env:GITHUB_TOKEN}", API_KEY: "${API_KEY}" } },
    ],
    [
      "a referenced bearer token",
      { url: "https://a.example/mcp", headers: { Authorization: "Bearer ${input:token}" } },
    ],
    [
      "placeholders",
      {
        command: "x",
        env: { API_KEY: "<your-api-key>", TOKEN: "your-token-here", SECRET: "xxxxxxxx" },
      },
    ],
    [
      "values about a secret, not the secret",
      {
        command: "x",
        env: { PUBLIC_KEY: "abcdefghijk", TOKEN_PATH: "/etc/token", API_KEY_ID: "key-1234567" },
      },
    ],
    [
      "URLs without credentials",
      { command: "x", args: ["postgresql://app@db/prod", "postgres://app:${DB_PASSWORD}@db/prod"] },
    ],
    [
      "ordinary arguments",
      {
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"],
      },
    ],
  ])("ignores %s", (_label, entry) => {
    expect(mcp006(entry)).toEqual([]);
  });
});

describe("secrets exposure (MCP006) in tool definitions", () => {
  const surface = (tool: Record<string, unknown>): MCPServerSurface => ({
    serverName: "srv",
    source: "t.json",
    tools: [{ name: "t", ...tool }],
  });

  it("flags known token formats anywhere in a tool", () => {
    const tool = {
      description: "Looks things up.",
      inputSchema: { type: "object", properties: { key: { type: "string", default: ANTHROPIC } } },
    };
    const [finding] = scan(surface(tool)).filter((f) => f.ruleId === "MCP006");
    expect(finding).toMatchObject({
      severity: "high",
      toolName: "t",
      field: "inputSchema.properties.key.default",
      title: "Tool definition contains a secret",
    });
  });

  it("does not guess from key names in tools", () => {
    const tool = {
      inputSchema: { type: "object", properties: { password: { description: "Your password" } } },
    };
    expect(scan(surface(tool)).filter((f) => f.ruleId === "MCP006")).toEqual([]);
  });
});
