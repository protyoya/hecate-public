import { isObject } from "../json.js";
import { toWords } from "../signals.js";
import type { Finding, MCPServerSurface, Rule, Severity } from "../types.js";

const ID = "MCP006";
const CONFIG_TITLE = "Secret in plain text in the client config";
const TOOL_TITLE = "Tool definition contains a secret";

/** Formats specific enough to report as high without looking at the key name. */
const TOKENS: { name: string; pattern: RegExp }[] = [
  { name: "a private key", pattern: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----/ },
  { name: "an Anthropic API key", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: "an OpenAI API key", pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/ },
  { name: "a GitHub token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_\w{22,})/ },
  { name: "a GitLab token", pattern: /\bglpat-[A-Za-z0-9_-]{20,}/ },
  { name: "an AWS access key ID", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { name: "a Slack token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { name: "a Slack webhook URL", pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/ },
  { name: "a Stripe live key", pattern: /\b[rs]k_live_[A-Za-z0-9]{20,}/ },
  { name: "a Google API key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "an npm token", pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: "a Hugging Face token", pattern: /\bhf_[A-Za-z0-9]{30,}/ },
  { name: "a Linear API key", pattern: /\blin_api_[A-Za-z0-9]{32,}/ },
  { name: "a Notion token", pattern: /\bntn_[A-Za-z0-9]{40,}/ },
];

/** Key names (as words) whose values are secrets; "key" only as the last word. */
const SECRET_KEY =
  /\b(?:token|secret|password|passwd|pwd|api ?key|access key|private key|client secret|credentials?|authorization|bearer)\b|\bkey$/;
/** ...unless the value is something else about the secret. */
const NOT_SECRET_KEY = /\bpublic\b|\b(?:path|file|url|uri|dir|name|id|endpoint|type|header)$/;
/** Variable references: ${VAR}, ${env:VAR}, ${input:id}, $VAR, %VAR%, {{var}}. */
const REFERENCE = /\$\{[^}]*\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{\{[^}]*\}\}/g;
const PLACEHOLDER =
  /^(?:<.*>|\[.*\]|your\b.*|.*[-_ ]here|x{3,}|\*+|\.+|changeme|replace[-_ ]?me|todo|example|placeholder|none|null|true|false|\d+)$/i;
const URL_IN_TEXT = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi;

const CONFIG_WHY =
  "Anything that can read this file can use it, including an agent with a file-reading " +
  "tool, and project configs (.mcp.json, .vscode/mcp.json, .cursor/mcp.json) are often committed.";

const TOOL_WHY =
  "Tool definitions are sent to the model and often logged, so every conversation sees it.";

export const secretsExposure: Rule = {
  id: ID,
  severity: "high",
  title: "Secret exposed in an MCP config or tool definition",
  detect(surface: MCPServerSurface): Finding[] {
    const findings: Finding[] = [];
    if (surface.config) {
      for (const [field, value, key] of strings(surface.config)) {
        const secret = tokenIn(value) ?? genericSecret(value, key);
        if (!secret) continue;
        findings.push({
          ruleId: ID,
          severity: secret.severity,
          title: CONFIG_TITLE,
          detail: `Server "${surface.serverName}" has ${secret.what} in ${field}. ${CONFIG_WHY}`,
          serverName: surface.serverName,
          field,
          remediation:
            "Move the secret into the environment and reference it where the client supports " +
            'that (VS Code and Cursor: "${env:NAME}"; Claude Code .mcp.json: "${NAME}"). ' +
            "Rotate it if this file was ever committed or shared.",
        });
      }
    }
    for (const tool of surface.tools) {
      for (const [field, value] of strings(tool)) {
        // Descriptions document formats with examples ("hooks.slack.com/services/T000/B000/XXXX");
        // a config value is always the real thing, so only here are examples let through.
        const secret = tokenIn(value, { examples: true });
        if (!secret) continue;
        findings.push({
          ruleId: ID,
          severity: secret.severity,
          title: TOOL_TITLE,
          detail: `Tool "${tool.name}" has ${secret.what} in ${field}. ${TOOL_WHY}`,
          serverName: surface.serverName,
          toolName: tool.name,
          field,
          remediation: "Remove the secret from the server's tool definition and rotate it.",
        });
      }
    }
    return findings;
  },
};

interface Secret {
  severity: Severity;
  /** What was found, never the value itself: findings end up in CI logs and SARIF uploads. */
  what: string;
}

/** Documented example tokens: runs of X or 0, "EXAMPLE", "your", template placeholders. */
const EXAMPLE_TOKEN = /x{4,}|0{4,}|(?:^|\/)[tb]0{3,}(?:\/|$)|example|your|\.{3}|<[^>]*>|\{[^}]*\}/i;

function tokenIn(value: string, { examples = false } = {}): Secret | undefined {
  for (const { name, pattern } of TOKENS) {
    const match = pattern.exec(value);
    if (match && !(examples && EXAMPLE_TOKEN.test(match[0])))
      return { severity: "high", what: `${name} (${match[0].length} characters)` };
  }
  return undefined;
}

/** Literal secrets recognized by where they sit: a secret-named key or flag, or a URL. */
function genericSecret(value: string, key: string | undefined): Secret | undefined {
  for (const text of value.match(URL_IN_TEXT) ?? []) {
    let url: URL;
    try {
      url = new URL(text);
    } catch {
      continue;
    }
    if (isLiteral(decodeURIComponent(url.password))) {
      return { severity: "medium", what: `a password in a ${url.protocol.slice(0, -1)} URL` };
    }
    for (const [param, paramValue] of url.searchParams) {
      if (isSecretKey(param) && isLiteral(paramValue)) {
        return { severity: "medium", what: `a literal "${param}" in a URL query string` };
      }
    }
  }
  // URLs were handled above; a URL under a secret-named key is not itself the secret.
  if (key !== undefined && isSecretKey(key) && isLiteral(value) && !value.includes("://")) {
    return {
      severity: "medium",
      what: `a literal value for "${key}" (${value.length} characters)`,
    };
  }
  return undefined;
}

function isSecretKey(key: string): boolean {
  const name = toWords(key);
  return SECRET_KEY.test(name) && !NOT_SECRET_KEY.test(name);
}

/** A value that is itself a secret, not a reference to one or a placeholder. */
function isLiteral(value: string): boolean {
  const rest = value
    .replace(REFERENCE, "")
    .replace(/^\s*(?:bearer|basic|token)\s+/i, "")
    .trim();
  return rest.length >= 8 && !PLACEHOLDER.test(rest) && !/^(?:\/|\.\.?\/|~)/.test(rest);
}

/**
 * Every string in a JSON value, as [field, value, key]. `key` names what the
 * value is for: its property name, or the flag in args ("--api-key=v" or
 * "--api-key", "v").
 */
function* strings(value: unknown, field = "", key?: string): Generator<[string, string, string?]> {
  if (typeof value === "string") {
    yield [field, value, key];
  } else if (Array.isArray(value)) {
    for (const [i, item] of value.entries()) {
      const at = `${field}[${i}]`;
      const flag = typeof item === "string" ? /^--?([\w-]+)=(.*)$/s.exec(item) : null;
      if (flag) {
        yield [at, flag[2], flag[1]];
        continue;
      }
      const previous = value[i - 1];
      const flagKey =
        typeof previous === "string" && /^--?[\w-]+$/.test(previous) && typeof item === "string"
          ? previous.replace(/^--?/, "")
          : undefined;
      yield* strings(item, at, flagKey);
    }
  } else if (isObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (field === "" && k === "name") continue; // a tool's name
      yield* strings(v, field ? `${field}.${k}` : k, k);
    }
  }
}
