import type { MCPServerSurface, MCPTool, ServerLaunch } from "@hecate-mcp/core";
import { surfaceFromToolsJson } from "@hecate-mcp/core";
import {
  Client,
  SSEClientTransport,
  StreamableHTTPClientTransport,
  type Transport,
} from "@modelcontextprotocol/client";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/client/stdio";
import { z } from "zod";
import { VERSION } from "./version.js";

// Not the SDK's ListToolsResultSchema: it strips fields it doesn't know from
// each tool, and a rug pull can hide in exactly those. Keep tools verbatim and
// validate them with core's parser instead.
const RawToolsPage = z.looseObject({
  tools: z.array(z.unknown()),
  nextCursor: z.string().optional(),
});

const STDERR_TAIL = 2000;

/** Starts or connects to the server, lists every tool (all pages), and disconnects. */
export async function listTools(surface: MCPServerSurface, timeoutMs: number): Promise<MCPTool[]> {
  const launch = surface.launch;
  if (!launch) return surface.tools;
  if (launch.transport === "http" && launch.sseFallback) {
    try {
      return await listToolsOver(httpTransport(launch), surface, timeoutMs);
    } catch (httpError) {
      try {
        return await listToolsOver(sseTransport(launch), surface, timeoutMs);
      } catch (sseError) {
        const reasons = [httpError, sseError].map((e) => (e as Error).message);
        throw new Error(`streamable HTTP: ${reasons[0]}; SSE: ${reasons[1]}`);
      }
    }
  }
  const transport =
    launch.transport === "stdio"
      ? stdioTransport(launch)
      : launch.transport === "sse"
        ? sseTransport(launch)
        : httpTransport(launch);
  return listToolsOver(transport, surface, timeoutMs);
}

async function listToolsOver(
  transport: Transport,
  surface: MCPServerSurface,
  timeoutMs: number,
): Promise<MCPTool[]> {
  // Keep the end of the server's stderr for error messages; don't mix its logs into ours.
  let stderr = "";
  if (transport instanceof StdioClientTransport) {
    transport.stderr?.on("data", (chunk: Buffer) => {
      stderr = (stderr + chunk.toString()).slice(-STDERR_TAIL);
    });
  }
  const client = new Client({ name: "hecate", version: VERSION });
  try {
    await client.connect(transport, { timeout: timeoutMs });
    const tools: unknown[] = [];
    let cursor: string | undefined;
    do {
      const page = await client.request(
        { method: "tools/list", params: cursor ? { cursor } : {} },
        RawToolsPage,
        { timeout: timeoutMs },
      );
      tools.push(...page.tools);
      cursor = page.nextCursor;
    } while (cursor);
    return surfaceFromToolsJson({ tools }, surface.source).tools;
  } catch (err) {
    const tail = stderr.trim()
      ? `\n    server stderr: ${stderr.trim().split("\n").slice(-3).join("\n    ")}`
      : "";
    throw new Error(`${(err as Error).message}${tail}`);
  } finally {
    await client.close().catch(() => {});
  }
}

function stdioTransport(launch: Extract<ServerLaunch, { transport: "stdio" }>): Transport {
  return new StdioClientTransport({
    command: launch.command,
    args: launch.args,
    // What MCP clients pass: a minimal safe environment plus the config's env.
    env: { ...getDefaultEnvironment(), ...launch.env },
    cwd: launch.cwd,
    stderr: "pipe",
  });
}

function httpTransport(launch: Extract<ServerLaunch, { transport: "http" | "sse" }>): Transport {
  return new StreamableHTTPClientTransport(new URL(launch.url), {
    requestInit: { headers: launch.headers },
  });
}

function sseTransport(launch: Extract<ServerLaunch, { transport: "http" | "sse" }>): Transport {
  return new SSEClientTransport(new URL(launch.url), {
    requestInit: { headers: launch.headers },
    // The SSE GET stream doesn't use requestInit; pass the headers there too.
    eventSourceInit: {
      fetch: (url, init) =>
        fetch(url, { ...init, headers: { ...init?.headers, ...launch.headers } }),
    },
  });
}
