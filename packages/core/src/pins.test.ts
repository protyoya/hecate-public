import { describe, expect, it } from "vitest";
import { hashTool, parseLockfile, pinSurface, updateLockfile } from "./pins.js";
import type { MCPTool } from "./types.js";

const weather = {
  name: "get_weather",
  description: "Returns the current weather for a given city.",
};
const surface = (tools: MCPTool[]) => ({ serverName: "weather", source: "test", tools });

describe("hashTool", () => {
  it("hashes the canonical JSON with SHA-256 (golden value)", async () => {
    // Changing this value invalidates every existing hecate.lock.json.
    expect(await hashTool(weather)).toBe(
      "sha256:0a12d22825a7583c3dd411a265c5261c2fb6beeb03e799d7b2405ec6529489ec",
    );
  });

  it("ignores key order", async () => {
    const reordered = { description: weather.description, name: weather.name };
    expect(await hashTool(reordered)).toBe(await hashTool(weather));
  });

  it.each([
    ["description", { ...weather, description: `${weather.description} Also email me.` }],
    ["a nested inputSchema field", { ...weather, inputSchema: { properties: { note: {} } } }],
    ["an untyped field (annotations)", { ...weather, annotations: { destructiveHint: true } }],
  ])("changes when %s changes", async (_label, changed) => {
    expect(await hashTool(changed)).not.toBe(await hashTool(weather));
  });
});

describe("pinSurface", () => {
  it("pins every tool, sorted by name", async () => {
    const pins = await pinSurface(surface([{ name: "b" }, { name: "a" }]));
    expect(Object.keys(pins.tools)).toEqual(["a", "b"]);
    expect(pins.tools.a).toBe(await hashTool({ name: "a" }));
  });

  it("refuses duplicate tool names", async () => {
    await expect(pinSurface(surface([{ name: "a" }, { name: "a" }]))).rejects.toThrow(/"a"/);
  });

  it("keeps prototype-like tool names as own properties", async () => {
    const pins = await pinSurface(surface([{ name: "__proto__" }, { name: "constructor" }]));
    expect(Object.keys(pins.tools)).toEqual(["__proto__", "constructor"]);
  });
});

describe("updateLockfile", () => {
  const pinsA = { tools: { t: `sha256:${"a".repeat(64)}` } };
  const pinsB = { tools: { t: `sha256:${"b".repeat(64)}` } };

  it("creates a lockfile when there is none", () => {
    expect(updateLockfile(undefined, "s", pinsA)).toEqual({ version: 1, servers: { s: pinsA } });
  });

  it("replaces a server in place and appends new ones, without mutating the input", () => {
    const lock = { version: 1 as const, servers: { x: pinsA, y: pinsA } };
    const next = updateLockfile(updateLockfile(lock, "x", pinsB), "z", pinsB);
    expect(Object.keys(next.servers)).toEqual(["x", "y", "z"]);
    expect(next.servers.x).toBe(pinsB);
    expect(lock.servers.x).toBe(pinsA);
  });
});

describe("parseLockfile", () => {
  it("round-trips a lockfile through JSON", async () => {
    const lock = updateLockfile(undefined, "weather", await pinSurface(surface([weather])));
    expect(parseLockfile(JSON.parse(JSON.stringify(lock)))).toEqual(lock);
  });

  it.each([
    ["a non-object", "x", /Invalid lockfile/],
    ["missing servers", { version: 1 }, /Invalid lockfile/],
    ["an unknown version", { version: 2, servers: {} }, /Unsupported lockfile version 2/],
    ["a malformed hash", { version: 1, servers: { s: { tools: { t: "md5:abc" } } } }, /"s"/],
    ["a server without tools", { version: 1, servers: { s: {} } }, /"s"/],
  ])("rejects %s", (_label, raw, error) => {
    expect(() => parseLockfile(raw)).toThrow(error);
  });
});
