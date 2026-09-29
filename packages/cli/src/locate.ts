import { readFileSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import type { MCPServerSurface, SarifLocation } from "@hecate-mcp/core";

/**
 * Where a server, tool or field is defined in the scanned files, so code
 * scanning can annotate the right line: the tool's "name" in a tools file or
 * the server's entry (a config key, or "serverName" in a tools file), then the
 * field's key after that, e.g. "GITHUB_TOKEN" for env.GITHUB_TOKEN.
 */
export function locator(
  surfaces: MCPServerSurface[],
): (serverName: string, toolName?: string, field?: string) => SarifLocation | undefined {
  const sources = new Map<string, string>();
  for (const s of surfaces) if (!sources.has(s.serverName)) sources.set(s.serverName, s.source);
  const texts = new Map<string, string>();

  return (serverName, toolName, field) => {
    const source = sources.get(serverName);
    if (source === undefined) return undefined;
    if (!texts.has(source)) texts.set(source, readFileSync(source, "utf8"));
    const text = texts.get(source) ?? "";
    const base = [
      toolName === undefined ? -1 : text.search(member("name", toolName)),
      text.search(new RegExp(`${quoted(serverName)}\\s*:`)),
      text.search(member("serverName", serverName)),
    ].find((i) => i >= 0);
    // The last named key of the field: "env.GITHUB_TOKEN" -> "GITHUB_TOKEN", "args[2]" -> "args".
    const key = field
      ?.split(/[.[\]]/)
      .filter((k) => k !== "" && !/^\d+$/.test(k))
      .pop();
    const offset =
      base !== undefined && key !== undefined
        ? text.slice(base).search(new RegExp(`${quoted(key)}\\s*:`))
        : -1;
    const index = base !== undefined && offset >= 0 ? base + offset : base;
    return {
      uri: toUri(source),
      ...(index !== undefined && { line: text.slice(0, index).split("\n").length }),
    };
  };
}

function member(key: string, value: string): RegExp {
  return new RegExp(`${quoted(key)}\\s*:\\s*${quoted(value)}`);
}

/** The JSON-encoded string, escaped for use in a RegExp. */
function quoted(value: string): string {
  return JSON.stringify(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Repository-relative when the file is under the working directory, else a file:// URI. */
function toUri(source: string): string {
  const path = relative(process.cwd(), resolve(source));
  if (path.startsWith("..") || isAbsolute(path)) return pathToFileURL(resolve(source)).href;
  return encodeURI(path.split(sep).join("/"));
}
