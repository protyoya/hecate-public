#!/usr/bin/env node
// Minimal MCP stdio server for tests and demos: serves the tools of a Hecate
// fixture, two per tools/list page so clients must paginate, and answers
// tools/call with a canned reply. No dependencies.
// Usage: node fixtures/servers/serve-tools.mjs fixtures/fetch-server.json
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";

const { tools } = JSON.parse(readFileSync(process.argv[2], "utf8"));
const PAGE_SIZE = 2;

const send = (message) =>
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);

function handle(method, params) {
  switch (method) {
    case "initialize":
      return {
        protocolVersion: params.protocolVersion,
        capabilities: { tools: {} },
        serverInfo: { name: "hecate-fixture", version: "0.0.0" },
      };
    case "tools/list": {
      const start = Number(params?.cursor ?? 0);
      const end = start + PAGE_SIZE;
      const page = { tools: tools.slice(start, end) };
      return end < tools.length ? { ...page, nextCursor: String(end) } : page;
    }
    case "tools/call": {
      const known = tools.some((tool) => tool.name === params?.name);
      const text = known ? `(fixture) ${params.name} ran` : `Unknown tool ${params?.name}`;
      return { content: [{ type: "text", text }], isError: !known };
    }
    case "ping":
      return {};
    default:
      return undefined;
  }
}

createInterface({ input: process.stdin }).on("line", (line) => {
  const { id, method, params } = JSON.parse(line);
  if (id === undefined) return; // a notification
  const result = handle(method, params);
  send(
    result ? { id, result } : { id, error: { code: -32601, message: `Unknown method ${method}` } },
  );
});
