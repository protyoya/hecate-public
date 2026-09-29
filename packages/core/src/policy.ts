import { CAPABILITIES } from "./capabilities.js";
import { isObject } from "./json.js";
import { ruleCatalog } from "./registry.js";
import type {
  CapabilityOverride,
  Finding,
  GuardPolicy,
  IgnoreEntry,
  Policy,
  ServerMatch,
} from "./types.js";

export const EMPTY_POLICY: Policy = { version: 1, capabilities: [], ignore: [] };

/** What the SDK guard does when the policy has no `guard` section: the safe defaults. */
export const DEFAULT_GUARD_POLICY: GuardPolicy = {
  tools: { allow: [], deny: [] },
  approve: [],
  approveExec: true,
  approveEgressAfterUntrusted: true,
};

const DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Validates already-parsed policy JSON. Strict on purpose: a typo in a
 * security exception ("privat-data", "MCP05") must fail loudly, not silently
 * do nothing.
 */
export function parsePolicy(raw: unknown): Policy {
  const policy = object(raw, "policy");
  allowKeys(policy, ["$schema", "version", "capabilities", "ignore", "servers", "guard"], "policy");
  if (policy.version !== 1) {
    throw new Error(`Unsupported policy version ${JSON.stringify(policy.version)} (expected 1).`);
  }
  return {
    version: 1,
    capabilities: list(policy.capabilities, "capabilities").map(parseOverride),
    ignore: list(policy.ignore, "ignore").map(parseIgnore),
    ...(policy.servers !== undefined && { servers: parseServers(policy.servers) }),
    ...(policy.guard !== undefined && { guard: parseGuard(policy.guard) }),
  };
}

/** Marks findings accepted by a live (unexpired) ignore entry as suppressed. */
export function applyIgnores(findings: Finding[], policy: Policy, now = new Date()): Finding[] {
  const live = policy.ignore.filter((entry) => !isExpired(entry, now));
  if (live.length === 0) return findings;
  return findings.map((finding) => {
    const entry = live.find((e) => matches(e, finding));
    if (!entry) return finding;
    const { reason, expires } = entry;
    return { ...finding, suppressed: expires ? { reason, expires } : { reason } };
  });
}

/** Ignore entries past their expiry date: their findings count again. */
export function expiredIgnores(policy: Policy, now = new Date()): IgnoreEntry[] {
  return policy.ignore.filter((entry) => isExpired(entry, now));
}

function isExpired(entry: IgnoreEntry, now: Date): boolean {
  return entry.expires !== undefined && now.toISOString().slice(0, 10) > entry.expires;
}

function matches(entry: IgnoreEntry, finding: Finding): boolean {
  return (
    entry.rule === finding.ruleId &&
    (entry.server === undefined || entry.server === finding.serverName) &&
    (entry.tool === undefined || entry.tool === finding.toolName)
  );
}

function parseOverride(raw: unknown, i: number): CapabilityOverride {
  const at = `capabilities[${i}]`;
  const entry = object(raw, at);
  allowKeys(entry, ["server", "tool", "reason", ...CAPABILITIES], at);
  const override: CapabilityOverride = {
    server: text(entry, "server", at),
    reason: text(entry, "reason", at),
  };
  if (entry.tool !== undefined) override.tool = text(entry, "tool", at);
  for (const capability of CAPABILITIES) {
    const value = entry[capability];
    if (value === undefined) continue;
    if (typeof value !== "boolean")
      throw new Error(`${at}: "${capability}" must be true or false.`);
    override[capability] = value;
  }
  if (!CAPABILITIES.some((capability) => capability in override)) {
    throw new Error(`${at}: set at least one of ${CAPABILITIES.join(", ")}.`);
  }
  return override;
}

function parseIgnore(raw: unknown, i: number): IgnoreEntry {
  const at = `ignore[${i}]`;
  const entry = object(raw, at);
  allowKeys(entry, ["rule", "server", "tool", "reason", "expires"], at);
  const ignore: IgnoreEntry = { rule: text(entry, "rule", at), reason: text(entry, "reason", at) };
  const known = ruleCatalog.map((r) => r.id);
  if (!known.includes(ignore.rule)) {
    throw new Error(`${at}: unknown rule "${ignore.rule}" (known: ${known.join(", ")}).`);
  }
  if (entry.server !== undefined) ignore.server = text(entry, "server", at);
  if (entry.tool !== undefined) ignore.tool = text(entry, "tool", at);
  if (entry.expires !== undefined) {
    const expires = text(entry, "expires", at);
    if (!DATE.test(expires) || Number.isNaN(Date.parse(expires))) {
      throw new Error(`${at}: "expires" must be a date like 2026-12-31.`);
    }
    ignore.expires = expires;
  }
  return ignore;
}

function parseServers(raw: unknown): NonNullable<Policy["servers"]> {
  const servers = object(raw, "servers");
  allowKeys(servers, ["allow", "deny"], "servers");
  const parse = (kind: "allow" | "deny") =>
    list(servers[kind], `servers.${kind}`).map((entry, i): ServerMatch => {
      const at = `servers.${kind}[${i}]`;
      const match = object(entry, at);
      const fields = ["package", "image", "url", "command"] as const;
      allowKeys(match, [...fields, "reason"], at);
      const result: ServerMatch = { reason: text(match, "reason", at) };
      for (const field of fields)
        if (match[field] !== undefined) result[field] = text(match, field, at);
      if (!fields.some((field) => field in result)) {
        throw new Error(`${at}: set at least one of ${fields.join(", ")}.`);
      }
      return result;
    });
  return { allow: parse("allow"), deny: parse("deny") };
}

function parseGuard(raw: unknown): GuardPolicy {
  const guard = object(raw, "guard");
  const keys = ["tools", "approve", "approveExec", "approveEgressAfterUntrusted", "egress"];
  allowKeys(guard, keys, "guard");
  const tools = guard.tools === undefined ? {} : object(guard.tools, "guard.tools");
  allowKeys(tools, ["allow", "deny"], "guard.tools");
  const flag = (key: "approveExec" | "approveEgressAfterUntrusted"): boolean => {
    if (guard[key] === undefined) return DEFAULT_GUARD_POLICY[key];
    if (typeof guard[key] !== "boolean") throw new Error(`guard: "${key}" must be true or false.`);
    return guard[key];
  };
  const result: GuardPolicy = {
    tools: {
      allow: toolPatterns(tools.allow, "guard.tools.allow"),
      deny: toolPatterns(tools.deny, "guard.tools.deny"),
    },
    approve: toolPatterns(guard.approve, "guard.approve"),
    approveExec: flag("approveExec"),
    approveEgressAfterUntrusted: flag("approveEgressAfterUntrusted"),
  };
  if (guard.egress !== undefined) {
    const egress = object(guard.egress, "guard.egress");
    allowKeys(egress, ["allow"], "guard.egress");
    result.egress = {
      allow: list(egress.allow, "guard.egress.allow").map((p, i) =>
        pattern(p, `guard.egress.allow[${i}]`),
      ),
    };
  }
  return result;
}

/** "server/tool" globs: a bare tool name would never match, so it's an error. */
function toolPatterns(value: unknown, at: string): string[] {
  return list(value, at).map((raw, i) => {
    const p = pattern(raw, `${at}[${i}]`);
    if (!p.includes("/")) {
      throw new Error(`${at}[${i}]: "${p}" must be "server/tool" (use "*/${p}" for any server).`);
    }
    return p;
  });
}

function pattern(value: unknown, at: string): string {
  if (typeof value !== "string" || value.trim() === "")
    throw new Error(`${at} must be a non-empty string.`);
  return value;
}

function object(value: unknown, at: string): Record<string, unknown> {
  if (!isObject(value)) throw new Error(`${at} must be an object.`);
  return value;
}

function list(value: unknown, at: string): unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${at} must be an array.`);
  return value;
}

function allowKeys(entry: Record<string, unknown>, allowed: readonly string[], at: string): void {
  const unknown = Object.keys(entry).find((key) => !allowed.includes(key));
  if (unknown !== undefined) {
    throw new Error(`${at}: unknown key "${unknown}" (allowed: ${allowed.join(", ")}).`);
  }
}

function text(entry: Record<string, unknown>, key: string, at: string): string {
  const value = entry[key];
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${at}: "${key}" must be a non-empty string.`);
  }
  return value;
}
