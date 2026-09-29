import { EMPTY_POLICY, applyIgnores } from "./policy.js";
import { rules as defaultRules } from "./registry.js";
import type { Finding, MCPServerSurface, Policy, Rule } from "./types.js";

export * from "./types.js";
export { ruleCatalog, rules } from "./registry.js";
export {
  DEFAULT_GUARD_POLICY,
  EMPTY_POLICY,
  applyIgnores,
  expiredIgnores,
  parsePolicy,
} from "./policy.js";
export { globMatch } from "./glob.js";
export { surfaceFromToolsJson } from "./parse.js";
export { configServers, surfacesFromJson } from "./config.js";
export { hashJson, hashTool, parseLockfile, pinSurface, updateLockfile } from "./pins.js";
export { checkPins } from "./detectors/rug-pull.js";
export { CAPABILITIES, CAPABILITY_LABELS, attackGraph, classifyTool } from "./capabilities.js";
export { classifyScope, type Scope } from "./scope.js";
export { type PackageRef, launchPackage } from "./packages.js";
export { KNOWN_BAD, type KnownBadPackage } from "./known-bad.js";
export { attackGraphToMermaid } from "./mermaid.js";
export { toSarif, type SarifLocation, type SarifLog, type SarifOptions } from "./sarif.js";

export interface ScanOptions {
  rules?: Rule[];
  policy?: Policy;
  /** For policy expiry; defaults to the current time. */
  now?: Date;
}

/**
 * Pass every server one agent is connected to: per-server rules run on each,
 * agent rules (e.g. MCP005) on all of them together. Findings accepted by the
 * policy come back with `suppressed` set.
 */
export function scan(
  input: MCPServerSurface | MCPServerSurface[],
  { rules = defaultRules, policy = EMPTY_POLICY, now }: ScanOptions = {},
): Finding[] {
  const surfaces = Array.isArray(input) ? input : [input];
  const ctx = { policy };
  const findings = rules.flatMap((rule) => [
    ...surfaces.flatMap((surface) => rule.detect?.(surface, ctx) ?? []),
    ...(rule.detectAgent?.(surfaces, ctx) ?? []),
  ]);
  return applyIgnores(findings, policy, now);
}

/**
 * Findings about the tool definitions themselves (poisoning, a secret inside a
 * definition): what should stop definitions being approved (`hecate pin`) or
 * shown to the model (the SDK guard). Only the per-server checks run: agent-level
 * risks (MCP004 exec, MCP005) depend on what else is connected, and config
 * findings (MCP006 in env, MCP007, MCP008) aren't about the tools.
 */
export function definitionFindings(
  input: MCPServerSurface | MCPServerSurface[],
  { policy = EMPTY_POLICY, now }: Omit<ScanOptions, "rules"> = {},
): Finding[] {
  const surfaces = Array.isArray(input) ? input : [input];
  const ctx = { policy };
  const findings = defaultRules.flatMap((rule) =>
    surfaces.flatMap((surface) => rule.detect?.(surface, ctx) ?? []),
  );
  return applyIgnores(findings, policy, now).filter((f) => f.toolName !== undefined);
}
