import type { Severity } from "./types.js";

/**
 * Built-in list of MCP server packages that are known to be malicious or to
 * have a known-exploitable version. Keep it small and sourced: add an entry
 * only with a public report or advisory, and say what it is in `reason`.
 */
export interface KnownBadPackage {
  ecosystem: "npm" | "pypi" | "docker";
  name: string;
  kind: "malicious" | "vulnerable";
  /** Affected versions as [introduced, fixed); every version when omitted. */
  affected?: { introduced?: string; fixed: string };
  severity: Severity;
  reason: string;
}

export const KNOWN_BAD: KnownBadPackage[] = [
  {
    ecosystem: "npm",
    name: "postmark-mcp",
    kind: "malicious",
    severity: "critical",
    reason:
      "Unofficial package impersonating Postmark's MCP server; version 1.0.16 and later " +
      "secretly BCC'd every email it sent to an attacker (publicly reported, September 2025).",
  },
  {
    ecosystem: "npm",
    name: "mcp-remote",
    kind: "vulnerable",
    affected: { introduced: "0.0.5", fixed: "0.1.16" },
    severity: "high",
    reason:
      "CVE-2025-6514: connecting to an untrusted server can run OS commands on this machine. " +
      "Fixed in 0.1.16.",
  },
];
