import { type ToolText, inDescription, inName, inParam, toolText, words } from "./signals.js";
import type {
  AttackGraph,
  Capability,
  CapabilityOverride,
  MCPServerSurface,
  MCPTool,
} from "./types.js";

export const CAPABILITIES: readonly Capability[] = [
  "untrusted-content",
  "private-data",
  "external-comms",
];

export const CAPABILITY_LABELS: Record<Capability, string> = {
  "untrusted-content": "Untrusted content",
  "private-data": "Private data",
  "external-comms": "External communication",
};

// Heuristics over the tool name, parameter names and description. Names and
// parameters carry most of the weight. Descriptions only count for specific
// phrases, because incidental words ("error message", "file") are everywhere.
// Every match is recorded as evidence so a user can judge the classification.

const READ_VERB = words(
  "get|read|list|fetch|search|find|view|show|retrieve|query|lookup|download|export|browse",
);
const CREATE_VERB = words("create|add|open|write|leave|make|comment");
/** Content that other people write: reading it lets them talk to the agent. */
const INBOUND_NOUN = words(
  "emails?|mails?|inbox|messages?|dms?|chats?|history|threads?|replies|comments?|issues?|" +
    "pull requests?|tickets?|reviews?|posts|tweets?|feeds?|notifications?|mentions?",
);
const PRIVATE_NOUN = words(
  "files?|director(?:y|ies)|dirs?|folders?|documents?|docs?|notes?|databases?|dbs?|sql|" +
    "tables?|records?|rows?|secrets?|credentials?|passwords?|tokens?|keys?|env|environment|" +
    "variables?|keychain|vault|contacts?|calendars?|events?|inbox|emails?|mails?|messages?|" +
    "dms?|history|clipboard|screenshots?|photos?|repos?|repositor(?:y|ies)|code|customers?|" +
    "accounts?|profiles?|memor(?:y|ies)|drive|spreadsheets?|sheets?",
);
/** Things that, once created, other people can see. */
const PUBLIC_NOUN = words(
  "issues?|comments?|pull requests?|prs?|gists?|posts?|tweets?|messages?|replies|reviews?|" +
    "releases?|discussions?|events?|invit(?:es?|ations?)",
);

const UNTRUSTED_NAME = words(
  "fetch|scrape|crawl|browse|browser|navigate|web|webpage|website|url|http|rss",
);
const PRIVATE_NAME = words("sql|database|db");
// "request" but not "pull request".
const EGRESS_NAME =
  /\b(?:send|post|publish|upload|share|notify|forward|reply|tweet|submit|invite|push|webhooks?|curl|http)\b|(?<!pull )\brequests?\b/;

/** A parameter that takes a URL: the tool reaches a caller-chosen host. */
const URL_PARAM = /(?:^| )(?:url|urls|uri|href|endpoint|webhook)$/;
const RECIPIENT_PARAM =
  /^(?:to|recipients?|cc|bcc|channel(?: id| name)?|chat id|email address|phone(?: number)?|room(?: id)?|conversation(?: id)?)$/;
const CONTENT_PARAM = /^(?:body|message|text|content|subject|html|markdown|blocks|attachments?)$/;

const UNTRUSTED_DESC =
  /\b(?:web ?pages?|websites?|the (?:web|internet)|(?:any|arbitrary) urls?|search results|scrap(?:e|es|ing)|crawl(?:s|ing)?|incoming (?:emails?|messages?))\b/;
const PRIVATE_DESC =
  /\b(?:file ?system|local files?|databases?|sql|environment variables?|credentials|secrets|passwords?|api keys?|ssh keys?|private (?:repositor(?:y|ies)|repos?|data|files?|messages?)|knowledge graph|personal (?:data|information))\b/;
const EGRESS_DESC_START =
  /^(?:sends?|posts?|publish(?:es)?|uploads?|shares?|forwards?|emails?|tweets?)\b/;
const EGRESS_DESC = /\b(?:http (?:post|put|request)s?|webhooks?)\b/;

type Signal = (tool: ToolText) => string | undefined;

const SIGNALS: Record<Capability, Signal[]> = {
  "untrusted-content": [
    (t) => inName(t, UNTRUSTED_NAME),
    (t) => inName(t, READ_VERB, INBOUND_NOUN),
    (t) => inParam(t, URL_PARAM),
    (t) => inDescription(t, UNTRUSTED_DESC),
  ],
  "private-data": [
    (t) => inName(t, READ_VERB, PRIVATE_NOUN),
    (t) => inName(t, PRIVATE_NAME),
    (t) => inDescription(t, PRIVATE_DESC),
  ],
  "external-comms": [
    (t) => inName(t, EGRESS_NAME),
    (t) => inName(t, CREATE_VERB, PUBLIC_NOUN),
    (t) => inParam(t, URL_PARAM),
    (t) => {
      const to = t.params.find((p) => RECIPIENT_PARAM.test(p.words));
      const body = t.params.find((p) => CONTENT_PARAM.test(p.words));
      return to && body ? `parameters: ${to.raw} + ${body.raw}` : undefined;
    },
    (t) => inDescription(t, EGRESS_DESC_START) ?? inDescription(t, EGRESS_DESC),
  ],
};

/** Which trifecta legs a tool provides, with the evidence for each. */
export function classifyTool(tool: MCPTool): Partial<Record<Capability, string[]>> {
  const text = toolText(tool);
  const result: Partial<Record<Capability, string[]>> = {};
  for (const capability of CAPABILITIES) {
    const evidence = SIGNALS[capability]
      .map((signal) => signal(text))
      .filter((e) => e !== undefined);
    if (evidence.length > 0) result[capability] = evidence;
  }
  return result;
}

/**
 * Classifies every tool the agent can reach, grouped by trifecta leg.
 * Policy overrides apply after the heuristics; later overrides win.
 */
export function attackGraph(
  surfaces: MCPServerSurface[],
  overrides: readonly CapabilityOverride[] = [],
): AttackGraph {
  const graph: AttackGraph = { "untrusted-content": [], "private-data": [], "external-comms": [] };
  for (const surface of surfaces) {
    for (const tool of surface.tools) {
      const capabilities = classifyTool(tool);
      for (const override of overrides) {
        if (override.server !== surface.serverName) continue;
        if (override.tool !== undefined && override.tool !== tool.name) continue;
        for (const capability of CAPABILITIES) {
          if (override[capability] === true) {
            capabilities[capability] = [
              ...(capabilities[capability] ?? []),
              `policy: ${override.reason}`,
            ];
          } else if (override[capability] === false) {
            delete capabilities[capability];
          }
        }
      }
      for (const capability of CAPABILITIES) {
        const evidence = capabilities[capability];
        if (evidence)
          graph[capability].push({ serverName: surface.serverName, toolName: tool.name, evidence });
      }
    }
  }
  return graph;
}
