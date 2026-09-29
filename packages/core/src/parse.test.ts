import { describe, expect, it } from "vitest";
import { surfaceFromToolsJson } from "./parse.js";

const tools = [{ name: "get_weather", description: "Returns the weather." }];

describe("surfaceFromToolsJson", () => {
  it.each([
    ["a bare tools array", tools],
    ["{ tools }", { tools }],
    ["a raw tools/list response", { jsonrpc: "2.0", id: 1, result: { tools } }],
  ])("accepts %s", (_label, raw) => {
    expect(surfaceFromToolsJson(raw, "test").tools).toEqual(tools);
  });

  it("reads serverName when present", () => {
    const s = surfaceFromToolsJson({ serverName: "weather", tools }, "f.json");
    expect(s).toEqual({ serverName: "weather", tools, source: "f.json" });
  });

  it("accepts an empty tool list", () => {
    expect(surfaceFromToolsJson({ tools: [] }, "test").tools).toEqual([]);
  });

  it.each([
    ["an empty object", {}],
    ["a string", "tools"],
    ["null", null],
    ["tools that is not an array", { tools: { name: "x" } }],
  ])("rejects %s instead of reporting it clean", (_label, raw) => {
    expect(() => surfaceFromToolsJson(raw, "test")).toThrow(/Unrecognized input/);
  });

  it("rejects client config files with a pointer to what is supported", () => {
    const raw = { mcpServers: { weather: { command: "npx", args: ["weather-mcp"] } } };
    expect(() => surfaceFromToolsJson(raw, "test")).toThrow(/mcpServers/);
  });

  it("rejects tools without a name or with a non-string description", () => {
    expect(() => surfaceFromToolsJson([{ description: "x" }], "t")).toThrow(/index 0/);
    expect(() => surfaceFromToolsJson([null], "t")).toThrow(/index 0/);
    expect(() => surfaceFromToolsJson([{ name: "x", description: 1 }], "t")).toThrow(/"x"/);
  });
});
