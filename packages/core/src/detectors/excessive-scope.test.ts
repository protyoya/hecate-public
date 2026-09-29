import { describe, expect, it } from "vitest";
import { surfacesFromJson } from "../config.js";
import { scan } from "../index.js";
import { classifyScope } from "../scope.js";
import type { MCPServerSurface, MCPTool, Policy } from "../types.js";

const params = (...names: string[]) => ({
  type: "object",
  properties: Object.fromEntries(names.map((n) => [n, { type: "string" }])),
});
const server = (serverName: string, tools: MCPTool[]): MCPServerSurface => ({
  serverName,
  source: "t",
  tools,
});
const mcp004 = (surfaces: MCPServerSurface[], policy?: Policy) =>
  scan(surfaces, { policy }).filter((f) => f.ruleId === "MCP004");

describe("classifyScope", () => {
  it.each<[MCPTool, string[]]>([
    [{ name: "run_command", inputSchema: params("command") }, ["exec"]],
    [{ name: "execute_code", inputSchema: params("language", "source") }, ["exec"]],
    [{ name: "shell" }, ["exec"]],
    [{ name: "puppeteer_evaluate", inputSchema: params("script") }, ["exec"]],
    [{ name: "helper", description: "Runs a shell command and returns its output." }, ["exec"]],
    [{ name: "write_file", inputSchema: params("path", "content") }, ["file-write"]],
    [{ name: "create_directory", inputSchema: params("path") }, ["file-write"]],
    [{ name: "apply", inputSchema: params("file_path", "edits") }, ["file-write"]],
    [{ name: "execute_query", inputSchema: params("sql") }, []],
    [{ name: "evaluate_expression", inputSchema: params("expression") }, []],
    [{ name: "format_code", inputSchema: params("code") }, []],
    [{ name: "read_file", inputSchema: params("path") }, []],
    [{ name: "list_directory", inputSchema: params("path") }, []],
    [{ name: "send_email", inputSchema: params("to", "body") }, []],
  ])("classifies %j", (tool, expected) => {
    expect(Object.keys(classifyScope(tool))).toEqual(expected);
  });
});

describe("excessive scope (MCP004)", () => {
  const shell = server("shell", [{ name: "run_command", inputSchema: params("command") }]);
  const web = server("web", [{ name: "fetch", inputSchema: params("url") }]);
  const fs = server("fs", [
    { name: "read_file", inputSchema: params("path") },
    { name: "write_file", inputSchema: params("path", "content") },
  ]);

  it("flags a command-execution tool as high on its own", () => {
    expect(mcp004([shell])).toMatchObject([
      {
        severity: "high",
        serverName: "shell",
        toolName: "run_command",
        title: "Tool can run arbitrary commands or code",
      },
    ]);
  });

  it("raises it to critical when the agent also reads untrusted content", () => {
    const [finding] = mcp004([shell, web]);
    expect(finding).toMatchObject({
      severity: "critical",
      title: "Prompt injection can reach command execution",
    });
    expect(finding.detail).toContain("untrusted content (web/fetch)");
  });

  it("respects policy corrections to what counts as untrusted content", () => {
    const policy: Policy = {
      version: 1,
      capabilities: [{ server: "web", "untrusted-content": false, reason: "internal docs only" }],
      ignore: [],
    };
    expect(mcp004([shell, web], policy).map((f) => f.severity)).toEqual(["high"]);
  });

  it("flags file writes only where untrusted content can steer them, once per server", () => {
    expect(mcp004([fs])).toEqual([]);
    expect(mcp004([fs, web])).toMatchObject([
      { severity: "medium", serverName: "fs", title: "Untrusted content can steer file writes" },
    ]);
  });

  it("flags servers launched with the filesystem root or a home directory", () => {
    const config = {
      mcpServers: {
        everything: { command: "npx", args: ["-y", "fs-server", "/"] },
        home: { command: "npx", args: ["-y", "fs-server", "/Users/alice/"] },
        tilde: { command: "fs-server", args: ["--root=~"] },
        windows: { command: "fs-server.exe", args: ["C:\\Users\\bob"] },
        project: { command: "npx", args: ["-y", "fs-server", "/Users/alice/projects/app"] },
        remote: { url: "https://example.com/mcp" },
      },
    };
    const findings = scan(surfacesFromJson(config, "c.json")).filter((f) => f.ruleId === "MCP004");
    expect(findings.map((f) => [f.serverName, f.field, f.severity])).toEqual([
      ["everything", "args[2]", "high"],
      ["home", "args[2]", "medium"],
      ["tilde", "args[0]", "medium"],
      ["windows", "args[0]", "medium"],
    ]);
    expect(JSON.stringify(findings)).not.toContain("alice"); // no usernames in CI logs
  });
});
