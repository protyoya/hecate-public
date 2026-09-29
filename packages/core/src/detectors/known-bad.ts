import { globMatch as glob } from "../glob.js";
import { KNOWN_BAD } from "../known-bad.js";
import { type PackageRef, compareVersions, launchPackage } from "../packages.js";
import type {
  Finding,
  MCPServerSurface,
  Rule,
  RuleContext,
  ServerLaunch,
  ServerMatch,
} from "../types.js";

const ID = "MCP007";

export const knownBad: Rule = {
  id: ID,
  severity: "critical",
  title: "Known-bad or disallowed MCP server",
  detect(surface: MCPServerSurface, ctx: RuleContext): Finding[] {
    const launch = surface.launch;
    if (!launch) return [];
    const pkg = launchPackage(launch);
    const at = pkg?.field ?? (launch.transport === "stdio" ? "command" : "url");
    const runs = pkg ? `${pkg.name}${pkg.version ? `@${pkg.version}` : ""}` : describe(launch);
    const finding = (
      f: Pick<Finding, "severity" | "title" | "detail" | "remediation">,
    ): Finding => ({
      ruleId: ID,
      ...f,
      serverName: surface.serverName,
      field: at,
    });
    const findings: Finding[] = [];

    for (const bad of KNOWN_BAD) {
      if (!pkg || pkg.ecosystem !== bad.ecosystem || pkg.name !== bad.name) continue;
      if (bad.affected && !(pkg.exact && pkg.version && isAffected(pkg.version, bad.affected))) {
        continue; // unpinned resolves to the latest release, which is fixed
      }
      findings.push(
        finding({
          severity: bad.severity,
          title:
            bad.kind === "malicious"
              ? "Known-malicious MCP server package"
              : "MCP server version with a known exploitable vulnerability",
          detail: `Server "${surface.serverName}" runs ${runs}. ${bad.reason}`,
          remediation:
            bad.kind === "malicious"
              ? "Remove the server now and rotate any credentials it could reach."
              : `Upgrade to ${bad.affected?.fixed} or later.`,
        }),
      );
    }

    const lists = ctx.policy.servers;
    for (const entry of lists?.deny ?? []) {
      if (!matches(entry, launch, pkg)) continue;
      findings.push(
        finding({
          severity: "high",
          title: "Server is on the policy deny list",
          detail: `Server "${surface.serverName}" runs ${runs}, which the policy denies: ${entry.reason}`,
          remediation: "Remove the server from this config.",
        }),
      );
    }
    if (
      lists &&
      lists.allow.length > 0 &&
      !lists.allow.some((entry) => matches(entry, launch, pkg))
    ) {
      findings.push(
        finding({
          severity: "high",
          title: "Server is not on the policy allowlist",
          detail: `Server "${surface.serverName}" runs ${runs}, which no servers.allow entry matches.`,
          remediation: "Remove the server, or have it reviewed and added to servers.allow.",
        }),
      );
    }
    return findings;
  },
};

function isAffected(version: string, affected: { introduced?: string; fixed: string }): boolean {
  const from =
    affected.introduced === undefined || compareVersions(version, affected.introduced) >= 0;
  return from && compareVersions(version, affected.fixed) < 0;
}

function matches(entry: ServerMatch, launch: ServerLaunch, pkg: PackageRef | undefined): boolean {
  const checks: boolean[] = [];
  if (entry.package !== undefined) {
    checks.push(pkg !== undefined && pkg.ecosystem !== "docker" && glob(entry.package, pkg.name));
  }
  if (entry.image !== undefined) {
    checks.push(pkg?.ecosystem === "docker" && glob(entry.image, pkg.name));
  }
  if (entry.url !== undefined) {
    checks.push(launch.transport !== "stdio" && glob(entry.url, launch.url));
  }
  if (entry.command !== undefined) {
    checks.push(launch.transport === "stdio" && glob(entry.command, launch.command));
  }
  return checks.length > 0 && checks.every(Boolean);
}

function describe(launch: ServerLaunch): string {
  return launch.transport === "stdio" ? `"${launch.command}"` : launch.url;
}
