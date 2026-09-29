import { isObject } from "./json.js";
import { surfaceFromToolsJson } from "./parse.js";
import type { MCPServerSurface, ServerLaunch } from "./types.js";

/**
 * Any supported input: a client config (one surface per server) or a tools
 * list (one surface). Pure: takes already-parsed JSON.
 */
export function surfacesFromJson(raw: unknown, source: string): MCPServerSurface[] {
  const servers = configServers(raw);
  return servers ? surfacesFromConfig(servers, source) : [surfaceFromToolsJson(raw, source)];
}

/**
 * The server map of an MCP client config, or undefined if `raw` is not one:
 * - { mcpServers }: Claude Desktop, Claude Code (.mcp.json), Cursor, Windsurf
 * - { servers }: VS Code (.vscode/mcp.json); { mcp: { servers } } in settings.json
 */
export function configServers(raw: unknown): Record<string, unknown> | undefined {
  if (!isObject(raw)) return undefined;
  if (isObject(raw.mcpServers)) return raw.mcpServers;
  if (isObject(raw.servers)) return raw.servers;
  if (isObject(raw.mcp) && isObject(raw.mcp.servers)) return raw.mcp.servers;
  return undefined;
}

/**
 * One surface per enabled server, with no tools yet: a config only says how
 * to start or reach each server. Invalid entries throw, naming the server.
 */
function surfacesFromConfig(servers: Record<string, unknown>, source: string): MCPServerSurface[] {
  const surfaces: MCPServerSurface[] = [];
  for (const [serverName, entry] of Object.entries(servers)) {
    if (!isObject(entry)) throw new Error(`Server "${serverName}": expected an object.`);
    if (entry.disabled === true) continue;
    surfaces.push({
      serverName,
      tools: [],
      config: entry,
      launch: launchSpec(serverName, entry),
      source,
    });
  }
  return surfaces;
}

function launchSpec(serverName: string, entry: Record<string, unknown>): ServerLaunch {
  const at = `Server "${serverName}"`;
  const url = entry.url ?? entry.serverUrl; // serverUrl: Windsurf
  if (typeof entry.command === "string") {
    if (entry.type !== undefined && entry.type !== "stdio") {
      throw new Error(`${at}: "command" with "type": ${JSON.stringify(entry.type)}.`);
    }
    const launch: ServerLaunch = {
      transport: "stdio",
      command: entry.command,
      args: strings(entry.args, `${at}: "args"`),
      env: stringMap(entry.env, `${at}: "env"`),
    };
    if (typeof entry.cwd === "string") launch.cwd = entry.cwd;
    return launch;
  }
  if (typeof url === "string") {
    const headers = stringMap(entry.headers, `${at}: "headers"`);
    switch (entry.type ?? entry.transport) {
      case "sse":
        return { transport: "sse", url, headers };
      case "http":
      case "streamable-http":
      case "streamableHttp":
        return { transport: "http", url, headers };
      case undefined:
        return { transport: "http", url, headers, sseFallback: true };
      default:
        throw new Error(
          `${at}: unsupported transport ${JSON.stringify(entry.type ?? entry.transport)}.`,
        );
    }
  }
  throw new Error(`${at}: expected "command" (stdio) or "url" (remote).`);
}

function strings(value: unknown, at: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    throw new Error(`${at} must be an array of strings.`);
  }
  return value;
}

function stringMap(value: unknown, at: string): Record<string, string> {
  if (value === undefined) return {};
  if (!isObject(value) || !Object.values(value).every((v) => typeof v === "string")) {
    throw new Error(`${at} must map names to strings.`);
  }
  return value as Record<string, string>;
}
