import { canonicalJson, isObject } from "./json.js";
import type { Lockfile, MCPServerSurface, MCPTool, ServerPins } from "./types.js";

const LOCKFILE_VERSION = 1;
const HASH = /^sha256:[0-9a-f]{64}$/;

/**
 * "sha256:<hex>" of the tool's canonical JSON. Covers the whole definition as
 * served (inputSchema, annotations, _meta, ...), not only the typed fields:
 * a rug pull can hide in any of them.
 */
export async function hashTool(tool: MCPTool): Promise<string> {
  return hashJson(tool);
}

/** "sha256:<hex>" of any JSON value's canonical form (key order doesn't matter). */
export async function hashJson(value: unknown): Promise<string> {
  // Web Crypto: available in browsers and Node >= 20 without imports.
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0"));
  return `sha256:${hex.join("")}`;
}

/** Hashes every tool of a server. Tools are keyed by name, sorted for stable diffs. */
export async function pinSurface(surface: MCPServerSurface): Promise<ServerPins> {
  const hashes = new Map<string, string>();
  for (const tool of surface.tools) {
    if (hashes.has(tool.name)) {
      throw new Error(
        `Cannot pin "${surface.serverName}": it serves more than one tool named "${tool.name}".`,
      );
    }
    hashes.set(tool.name, await hashTool(tool));
  }
  const sorted = [...hashes].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  // Object.fromEntries defines own properties, so names like "__proto__" are safe.
  return { tools: Object.fromEntries(sorted) };
}

/** Returns a new lockfile with `server`'s pins replaced, keeping server order stable. */
export function updateLockfile(
  lock: Lockfile | undefined,
  server: string,
  pins: ServerPins,
): Lockfile {
  const entries = Object.entries(lock?.servers ?? {});
  const i = entries.findIndex(([name]) => name === server);
  if (i === -1) entries.push([server, pins]);
  else entries[i] = [server, pins];
  return { version: LOCKFILE_VERSION, servers: Object.fromEntries(entries) };
}

/** Validates already-parsed lockfile JSON (no file I/O — core is browser-safe). */
export function parseLockfile(raw: unknown): Lockfile {
  if (!isObject(raw) || !isObject(raw.servers)) {
    throw new Error('Invalid lockfile: expected { "version": 1, "servers": { ... } }.');
  }
  if (raw.version !== LOCKFILE_VERSION) {
    throw new Error(
      `Unsupported lockfile version ${JSON.stringify(raw.version)} (expected ${LOCKFILE_VERSION}).`,
    );
  }
  for (const [server, pins] of Object.entries(raw.servers)) {
    const tools = isObject(pins) ? pins.tools : undefined;
    if (
      !isObject(tools) ||
      !Object.values(tools).every((h) => typeof h === "string" && HASH.test(h))
    ) {
      throw new Error(
        `Invalid lockfile entry for server "${server}": expected { "tools": { "<name>": "sha256:<hex>" } }.`,
      );
    }
  }
  return raw as unknown as Lockfile;
}
