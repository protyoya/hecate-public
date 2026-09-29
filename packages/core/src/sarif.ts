import { CAPABILITIES, CAPABILITY_LABELS } from "./capabilities.js";
import { ruleCatalog } from "./registry.js";
import type { Finding, Severity } from "./types.js";

export interface SarifLocation {
  /** Relative to the repository root, or an absolute file:// URI. */
  uri: string;
  line?: number;
}

export interface SarifOptions {
  toolVersion: string;
  /** Where a server (or one of its tools, or a field of either) is defined. */
  locate?: (serverName: string, toolName?: string, field?: string) => SarifLocation | undefined;
}

type Level = "error" | "warning" | "note";

// The subset of SARIF 2.1.0 that Hecate writes.
export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: {
    tool: { driver: { name: string; semanticVersion: string; rules: SarifRule[] } };
    results: SarifResult[];
  }[];
}

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: Level };
  properties: { "security-severity": string; tags: string[] };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: Level;
  message: { text: string };
  locations: {
    physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number } };
    logicalLocations?: { name: string; fullyQualifiedName: string; kind: string }[];
  }[];
  partialFingerprints: Record<string, string>;
  properties: { severity: Severity };
  suppressions?: { kind: "external"; status: "accepted"; justification: string }[];
}

const LEVEL: Record<Severity, Level> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

// GitHub code scanning buckets: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, below that low.
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "1.0",
};

/**
 * SARIF 2.1.0, e.g. for GitHub code scanning. Suppressed findings are
 * included and marked with an accepted suppression carrying the policy reason.
 */
export function toSarif(findings: Finding[], { toolVersion, locate }: SarifOptions): SarifLog {
  const ruleIndex = new Map(ruleCatalog.map((rule, i) => [rule.id, i]));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Hecate",
            semanticVersion: toolVersion,
            rules: ruleCatalog.map((rule) => ({
              id: rule.id,
              shortDescription: { text: rule.title },
              defaultConfiguration: { level: LEVEL[rule.severity] },
              properties: {
                "security-severity": SECURITY_SEVERITY[rule.severity],
                tags: ["security", "mcp"],
              },
            })),
          },
        },
        results: findings.map((finding) => toResult(finding, ruleIndex, locate)),
      },
    ],
  };
}

function toResult(
  finding: Finding,
  ruleIndex: Map<string, number>,
  locate: SarifOptions["locate"],
): SarifResult {
  // An agent-level finding (MCP005) points at every tool in its attack graph.
  const tools = finding.attackGraph
    ? CAPABILITIES.flatMap((capability) => finding.attackGraph?.[capability] ?? [])
    : finding.serverName !== undefined
      ? [{ serverName: finding.serverName, toolName: finding.toolName, field: finding.field }]
      : [];

  const seen = new Set<string>();
  const locations: SarifResult["locations"] = [];
  for (const { serverName, toolName, field } of tools as {
    serverName: string;
    toolName?: string;
    field?: string;
  }[]) {
    const where = locate?.(serverName, toolName, field);
    const key = `${where?.uri}:${where?.line}:${serverName}/${toolName}`;
    if (!where || seen.has(key)) continue;
    seen.add(key);
    locations.push({
      physicalLocation: {
        artifactLocation: { uri: where.uri },
        ...(where.line !== undefined && { region: { startLine: where.line } }),
      },
      ...(toolName !== undefined && {
        logicalLocations: [
          { name: toolName, fullyQualifiedName: `${serverName}/${toolName}`, kind: "function" },
        ],
      }),
    });
  }

  return {
    ruleId: finding.ruleId,
    ruleIndex: ruleIndex.get(finding.ruleId) ?? -1,
    level: LEVEL[finding.severity],
    message: { text: message(finding) },
    locations,
    // Stable across runs, so code scanning tracks one alert per server/tool.
    partialFingerprints: {
      "hecateFinding/v1": [finding.ruleId, finding.serverName ?? "", finding.toolName ?? ""].join(
        ":",
      ),
    },
    properties: { severity: finding.severity },
    ...(finding.suppressed && {
      suppressions: [
        { kind: "external", status: "accepted", justification: finding.suppressed.reason },
      ],
    }),
  };
}

function message(finding: Finding): string {
  const graph = finding.attackGraph;
  if (!graph) return finding.detail;
  const legs = CAPABILITIES.map((capability) => {
    const tools = graph[capability].map((t) => `${t.serverName}/${t.toolName}`);
    return `${CAPABILITY_LABELS[capability]}: ${tools.join(", ")}.`;
  });
  return `${finding.detail} ${legs.join(" ")}`;
}
