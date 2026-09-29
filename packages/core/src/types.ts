export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface MCPServerSurface {
  serverName: string;
  tools: MCPTool[];
  /** Raw client-config entry, if scanned from a config file. */
  config?: Record<string, unknown>;
  /** How to start or reach the server, if it came from a client config. */
  launch?: ServerLaunch;
  /** File path, URL, or "playground" — where the surface came from. */
  source: string;
}

/** A client-config entry, normalized. */
export type ServerLaunch =
  | {
      transport: "stdio";
      command: string;
      args: string[];
      env: Record<string, string>;
      cwd?: string;
    }
  | {
      transport: "http" | "sse";
      url: string;
      headers: Record<string, string>;
      /** The config names no transport: try streamable HTTP, then SSE. */
      sseFallback?: boolean;
    };

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  detail: string;
  serverName?: string;
  toolName?: string;
  /** Where in the server's config entry or tool definition, e.g. `env.GITHUB_TOKEN`. */
  field?: string;
  remediation: string;
  /** MCP005: the tools that form each leg of the lethal trifecta. */
  attackGraph?: AttackGraph;
  /** Set when a policy `ignore` entry accepted this finding: it no longer fails the run. */
  suppressed?: { reason: string; expires?: string };
}

/** What a rule is, independent of how it runs (MCP002 runs outside scan()). */
export interface RuleInfo {
  id: string;
  severity: Severity;
  title: string;
}

export interface RuleContext {
  policy: Policy;
}

/** Implement `detect`, `detectAgent`, or both. */
export interface Rule extends RuleInfo {
  /** Checks one server. */
  detect?(surface: MCPServerSurface, ctx: RuleContext): Finding[];
  /** Checks every server one agent can reach, for risks that only appear in combination. */
  detectAgent?(surfaces: MCPServerSurface[], ctx: RuleContext): Finding[];
}

/** The three legs of the lethal trifecta. */
export type Capability = "untrusted-content" | "private-data" | "external-comms";

export interface ToolRef {
  serverName: string;
  toolName: string;
  /** Why the tool was put in this leg, e.g. `name: read + file`, `parameter: url`. */
  evidence: string[];
}

/** Tools per trifecta leg. Any tool from each leg, in order, is an exfiltration path. */
export type AttackGraph = Record<Capability, ToolRef[]>;

/** hecate.policy.json: reviewed exceptions. Every entry carries a reason. */
export interface Policy {
  version: 1;
  /** Corrections to the heuristic trifecta classification (MCP005). */
  capabilities: CapabilityOverride[];
  /** Accepted findings: still reported, as suppressed, but they don't fail the run. */
  ignore: IgnoreEntry[];
  /** Which servers may run (MCP007). */
  servers?: { allow: ServerMatch[]; deny: ServerMatch[] };
  /** Runtime rules for @hecate-mcp/sdk. */
  guard?: GuardPolicy;
}

/** Runtime rules for the SDK guard. Tool patterns are "server/tool" globs, e.g. "github/*". */
export interface GuardPolicy {
  /** Tools hidden from the model and blocked; with `allow`, every other tool is too. */
  tools: { allow: string[]; deny: string[] };
  /** Calls that always need human approval. */
  approve: string[];
  /** Tools that run commands or code (MCP004) need approval. */
  approveExec: boolean;
  /**
   * Once any tool has returned untrusted content in the session, tools that can
   * send data out need approval: the lethal trifecta (MCP005), broken at runtime.
   */
  approveEgressAfterUntrusted: boolean;
  /** Hosts that URLs in call arguments may point to (e.g. "*.github.com"); any host when omitted. */
  egress?: { allow: string[] };
}

/**
 * Matches a configured server by what it runs. Every given field must match;
 * `*` is a wildcard, e.g. "@modelcontextprotocol/*" or "https://mcp.example.com/*".
 */
export interface ServerMatch {
  /** npm or PyPI package name run by npx, uvx, pipx, ... */
  package?: string;
  /** Container image repository run by docker/podman, without tag. */
  image?: string;
  /** Remote server URL. */
  url?: string;
  /** The launch command itself, e.g. "/opt/mcp/bin/server". */
  command?: string;
  reason: string;
}

/** `true` puts the tool in that leg, `false` takes it out. Omit `tool` for every tool on the server. */
export type CapabilityOverride = {
  server: string;
  tool?: string;
  reason: string;
} & Partial<Record<Capability, boolean>>;

/** Matches findings of `rule`; `server` and `tool` narrow it. */
export interface IgnoreEntry {
  rule: string;
  server?: string;
  tool?: string;
  reason: string;
  /** YYYY-MM-DD: the last day (UTC) the entry applies. */
  expires?: string;
}

/** hecate.lock.json: approved tool-definition hashes, per server name. */
export interface Lockfile {
  version: 1;
  servers: Record<string, ServerPins>;
}

export interface ServerPins {
  /** Tool name → "sha256:<hex>" of the tool's canonical JSON definition. */
  tools: Record<string, string>;
}
