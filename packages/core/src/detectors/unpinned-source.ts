import { launchPackage } from "../packages.js";
import type { Finding, MCPServerSurface, Rule } from "../types.js";

const ID = "MCP008";
const LOCAL_HOST = /^(?:localhost|127(?:\.\d+){3}|\[::1\]|0\.0\.0\.0|.+\.localhost)$/i;
const UNPINNED_WHY =
  "Every launch can pull a new release, so a compromised publish reaches the agent on its " +
  "next start without anyone approving it.";

/**
 * Supply-chain hygiene, kept apart from MCP007 so that accepting "we don't pin"
 * in the policy can't also hide a known-bad package.
 */
export const unpinnedSource: Rule = {
  id: ID,
  severity: "high",
  title: "Server source is not pinned or not secure",
  detect(surface: MCPServerSurface): Finding[] {
    const launch = surface.launch;
    if (!launch) return [];
    const base = { ruleId: ID, serverName: surface.serverName };

    if (launch.transport !== "stdio") {
      let url: URL;
      try {
        url = new URL(launch.url);
      } catch {
        return [];
      }
      if (url.protocol !== "http:" || LOCAL_HOST.test(url.hostname)) return [];
      return [
        {
          ...base,
          severity: "high",
          title: "Remote server over plain HTTP",
          detail: `Server "${surface.serverName}" is reached over http:// at ${url.host}. Anyone on the network path can read its headers (credentials included) and change its tool definitions.`,
          field: "url",
          remediation: "Use https://.",
        },
      ];
    }

    const pkg = launchPackage(launch);
    if (!pkg) return [];
    if (pkg.ecosystem === "docker") {
      if (pkg.exact || (pkg.version !== undefined && pkg.version !== "latest")) return [];
      return [
        {
          ...base,
          severity: "medium",
          title: "Container image is not pinned",
          detail: `Server "${surface.serverName}" runs image ${pkg.name}${pkg.version ? ":latest" : " without a tag"}. ${UNPINNED_WHY}`,
          field: pkg.field,
          remediation: `Pin a digest, e.g. ${pkg.name}@sha256:<digest>, and update deliberately.`,
        },
      ];
    }
    if (pkg.exact) return [];
    const example = pkg.ecosystem === "npm" ? `${pkg.name}@1.2.3` : `${pkg.name}==1.2.3`;
    const how = pkg.version ? `at "${pkg.version}", a range or tag` : "without a version";
    return [
      {
        ...base,
        severity: "medium",
        title: "Package version is not pinned",
        detail: `Server "${surface.serverName}" runs ${pkg.ecosystem} package ${pkg.name} ${how}. ${UNPINNED_WHY}`,
        field: pkg.field,
        remediation: `Pin an exact version, e.g. "${example}", and update deliberately.`,
      },
    ];
  },
};
