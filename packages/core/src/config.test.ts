import { describe, expect, it } from "vitest";
import { surfacesFromJson } from "./config.js";

const launches = (raw: unknown) =>
  Object.fromEntries(surfacesFromJson(raw, "cfg.json").map((s) => [s.serverName, s.launch]));

describe("surfacesFromJson with client configs", () => {
  it("reads Claude Desktop / Cursor style mcpServers, one surface per server", () => {
    const raw = {
      mcpServers: {
        filesystem: {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        },
        github: {
          command: "docker",
          args: ["run", "ghcr.io/github/github-mcp-server"],
          env: { GITHUB_TOKEN: "x" },
        },
      },
    };
    const surfaces = surfacesFromJson(raw, "cfg.json");
    expect(surfaces.map((s) => [s.serverName, s.tools, s.source])).toEqual([
      ["filesystem", [], "cfg.json"],
      ["github", [], "cfg.json"],
    ]);
    expect(surfaces[1].launch).toEqual({
      transport: "stdio",
      command: "docker",
      args: ["run", "ghcr.io/github/github-mcp-server"],
      env: { GITHUB_TOKEN: "x" },
    });
    expect(surfaces[1].config).toBe(raw.mcpServers.github);
  });

  it("reads remote servers: explicit transports, and HTTP with SSE fallback when unspecified", () => {
    expect(
      launches({
        mcpServers: {
          a: { type: "http", url: "https://a.example/mcp", headers: { Authorization: "Bearer t" } },
          b: { type: "sse", url: "https://b.example/sse" },
          c: { url: "https://c.example/mcp" },
          d: { serverUrl: "https://d.example/mcp" },
        },
      }),
    ).toEqual({
      a: {
        transport: "http",
        url: "https://a.example/mcp",
        headers: { Authorization: "Bearer t" },
      },
      b: { transport: "sse", url: "https://b.example/sse", headers: {} },
      c: { transport: "http", url: "https://c.example/mcp", headers: {}, sseFallback: true },
      d: { transport: "http", url: "https://d.example/mcp", headers: {}, sseFallback: true },
    });
  });

  it("reads VS Code configs (servers, and mcp.servers in settings.json)", () => {
    const entry = { type: "stdio", command: "node", args: ["s.js"], cwd: "/w" };
    const expected = { transport: "stdio", command: "node", args: ["s.js"], env: {}, cwd: "/w" };
    expect(launches({ servers: { s: entry } })).toEqual({ s: expected });
    expect(launches({ "editor.fontSize": 12, mcp: { servers: { s: entry } } })).toEqual({
      s: expected,
    });
  });

  it("skips disabled servers", () => {
    const raw = { mcpServers: { on: { command: "a" }, off: { command: "b", disabled: true } } };
    expect(surfacesFromJson(raw, "c").map((s) => s.serverName)).toEqual(["on"]);
  });

  it("still reads tools lists", () => {
    const [s] = surfacesFromJson({ serverName: "w", tools: [{ name: "t" }] }, "t.json");
    expect(s).toEqual({ serverName: "w", tools: [{ name: "t" }], source: "t.json" });
  });

  it.each([
    ["an entry that is not an object", { mcpServers: { x: "npx" } }, /"x": expected an object/],
    ["neither command nor url", { mcpServers: { x: { args: [] } } }, /"x": expected "command"/],
    [
      "non-string args",
      { mcpServers: { x: { command: "a", args: [1] } } },
      /"args" must be an array of strings/,
    ],
    [
      "non-string env values",
      { mcpServers: { x: { command: "a", env: { K: 1 } } } },
      /"env" must map/,
    ],
    [
      "an unknown remote transport",
      { servers: { x: { type: "ws", url: "wss://x" } } },
      /unsupported transport "ws"/,
    ],
  ])("rejects %s, naming the server", (_label, raw, error) => {
    expect(() => surfacesFromJson(raw, "c")).toThrow(error);
  });
});
