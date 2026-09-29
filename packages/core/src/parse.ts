import { isObject } from "./json.js";
import type { MCPServerSurface, MCPTool } from "./types.js";

/**
 * Pure: takes already-parsed JSON (no file I/O here — core is browser-safe).
 * Accepts: MCPTool[], { tools }, { result: { tools } } (raw tools/list
 * response), or { serverName, tools }.
 * Throws on any other shape: scanning zero tools would report a false "clean".
 * Client configs ({ mcpServers }) are handled by surfacesFromJson in config.ts.
 */
export function surfaceFromToolsJson(raw: unknown, source: string): MCPServerSurface {
  let tools: unknown;
  let serverName = "unknown";

  if (Array.isArray(raw)) {
    tools = raw;
  } else if (isObject(raw)) {
    if (typeof raw.serverName === "string") serverName = raw.serverName;
    tools = raw.tools ?? (isObject(raw.result) ? raw.result.tools : undefined);
    if (tools === undefined && "mcpServers" in raw) {
      throw new Error("This is an MCP client config (mcpServers); use surfacesFromJson.");
    }
  }

  if (!Array.isArray(tools)) {
    throw new Error(
      "Unrecognized input: expected a tools array, { tools: [...] }, or a tools/list " +
        "response ({ result: { tools: [...] } }).",
    );
  }
  for (const [i, tool] of tools.entries()) {
    if (!isObject(tool) || typeof tool.name !== "string") {
      throw new Error(`Invalid tool at index ${i}: expected an object with a string "name".`);
    }
    if (tool.description !== undefined && typeof tool.description !== "string") {
      throw new Error(`Invalid tool "${tool.name}": "description" must be a string.`);
    }
  }

  return { serverName, tools: tools as MCPTool[], source };
}
