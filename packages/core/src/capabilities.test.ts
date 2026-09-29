import { describe, expect, it } from "vitest";
import { attackGraph, classifyTool } from "./capabilities.js";
import type { Capability, MCPTool } from "./types.js";

const params = (...names: string[]) => ({
  type: "object",
  properties: Object.fromEntries(names.map((n) => [n, { type: "string" }])),
});
const legs = (tool: MCPTool) => Object.keys(classifyTool(tool)).sort() as Capability[];

describe("classifyTool", () => {
  it.each<[string, MCPTool, Capability[]]>([
    [
      "a URL fetcher (in and out)",
      {
        name: "fetch",
        description: "Fetches a URL from the internet.",
        inputSchema: params("url"),
      },
      ["external-comms", "untrusted-content"],
    ],
    [
      "a web search",
      { name: "brave_web_search", inputSchema: params("query") },
      ["untrusted-content"],
    ],
    ["a file read", { name: "read_file", inputSchema: params("path") }, ["private-data"]],
    [
      "a directory listing",
      { name: "list_directory", inputSchema: params("path") },
      ["private-data"],
    ],
    [
      "a file write (local only)",
      { name: "write_file", inputSchema: params("path", "content") },
      [],
    ],
    [
      "a SQL query tool, via its description",
      { name: "query", description: "Run a read-only SQL query.", inputSchema: params("sql") },
      ["private-data"],
    ],
    [
      "an inbox read (others write it, and it is private)",
      { name: "read_email", inputSchema: params("id") },
      ["private-data", "untrusted-content"],
    ],
    [
      "an email send, via recipient + body parameters",
      { name: "deliver", inputSchema: params("to", "subject", "body") },
      ["external-comms"],
    ],
    ["camelCase names", { name: "sendEmail", inputSchema: params("address") }, ["external-comms"]],
    [
      "a GitHub issue read",
      { name: "get_issue", inputSchema: params("owner", "repo") },
      ["untrusted-content"],
    ],
    [
      "a GitHub issue create",
      { name: "create_issue", inputSchema: params("title", "body") },
      ["external-comms"],
    ],
    [
      "a pull request read (not an HTTP request)",
      { name: "get_pull_request", inputSchema: params("pull_number") },
      ["untrusted-content"],
    ],
    [
      "a repo file read",
      { name: "get_file_contents", inputSchema: params("path") },
      ["private-data"],
    ],
    [
      "a Slack post, via channel + text parameters",
      { name: "slack_post_message", inputSchema: params("channel_id", "text") },
      ["external-comms"],
    ],
    [
      "a Slack history read",
      { name: "slack_get_channel_history", inputSchema: params("channel_id") },
      ["private-data", "untrusted-content"],
    ],
    [
      "a knowledge-graph memory read",
      { name: "read_graph", description: "Read the entire knowledge graph." },
      ["private-data"],
    ],
    [
      "a webhook caller",
      { name: "notify", inputSchema: params("webhook_url", "payload") },
      ["external-comms", "untrusted-content"],
    ],
  ])("classifies %s", (_label, tool, expected) => {
    expect(legs(tool)).toEqual(expected);
  });

  it.each<[string, MCPTool]>([
    [
      "a weather lookup",
      { name: "get_weather", description: "Returns the current weather for a given city." },
    ],
    [
      "incidental words in a description",
      { name: "convert", description: "Returns an error message if the file type is unknown." },
    ],
    [
      "a lookup keyed by email (no message body)",
      { name: "get_user", inputSchema: params("email") },
    ],
    ["a bare verb that is also a noun", { name: "comment" }],
  ])("does not classify %s", (_label, tool) => {
    expect(classifyTool(tool)).toEqual({});
  });

  it("records the evidence behind each leg", () => {
    const tool = {
      name: "fetch",
      description: "Fetches a URL from the internet.",
      inputSchema: params("url"),
    };
    expect(classifyTool(tool)).toEqual({
      "untrusted-content": ["name: fetch", "parameter: url", 'description: "the internet"'],
      "external-comms": ["parameter: url"],
    });
  });
});

describe("attackGraph", () => {
  it("groups tools from every server by leg, keeping server names", () => {
    const graph = attackGraph([
      { serverName: "web", source: "a", tools: [{ name: "fetch", inputSchema: params("url") }] },
      { serverName: "fs", source: "b", tools: [{ name: "read_file" }, { name: "write_file" }] },
    ]);
    const names = (c: Capability) => graph[c].map((t) => `${t.serverName}/${t.toolName}`);
    expect(names("untrusted-content")).toEqual(["web/fetch"]);
    expect(names("private-data")).toEqual(["fs/read_file"]);
    expect(names("external-comms")).toEqual(["web/fetch"]);
  });
});
