import { describe, expect, it } from "vitest";
import { compareVersions, launchPackage } from "./packages.js";

const stdio = (command: string, ...args: string[]) =>
  launchPackage({ transport: "stdio", command, args, env: {} });

describe("launchPackage", () => {
  it.each([
    [
      "npx, no version",
      stdio("npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"),
      {
        ecosystem: "npm",
        name: "@modelcontextprotocol/server-filesystem",
        exact: false,
        field: "args[1]",
      },
    ],
    [
      "npx, exact version",
      stdio("npx", "-y", "mcp-remote@0.1.15", "https://x"),
      { ecosystem: "npm", name: "mcp-remote", version: "0.1.15", exact: true, field: "args[1]" },
    ],
    [
      "npx, range",
      stdio("npx", "@scope/pkg@^1.2.0"),
      { name: "@scope/pkg", version: "^1.2.0", exact: false, field: "args[0]" },
    ],
    [
      "npx --package=",
      stdio("npx", "--yes", "--package=pkg@2.0.0", "bin"),
      { name: "pkg", version: "2.0.0", exact: true, field: "args[1]" },
    ],
    ["npx -p", stdio("npx", "-p", "pkg", "bin"), { name: "pkg", field: "args[1]" }],
    ["a full path to npx", stdio("/usr/local/bin/npx", "pkg"), { name: "pkg" }],
    ["npx.cmd", stdio("C:\\Program Files\\nodejs\\npx.cmd", "-y", "pkg"), { name: "pkg" }],
    [
      "cmd /c npx",
      stdio("cmd", "/c", "npx", "-y", "pkg@1.0.0"),
      { name: "pkg", exact: true, field: "args[3]" },
    ],
    ["bunx", stdio("bunx", "pkg"), { ecosystem: "npm", name: "pkg" }],
    ["pnpm dlx", stdio("pnpm", "dlx", "pkg"), { name: "pkg", field: "args[1]" }],
    ["npm exec --", stdio("npm", "exec", "--", "pkg"), { name: "pkg", field: "args[2]" }],
    [
      "uvx",
      stdio("uvx", "mcp-server-git", "--repository", "."),
      { ecosystem: "pypi", name: "mcp-server-git", exact: false, field: "args[0]" },
    ],
    [
      "uvx pkg@version",
      stdio("uvx", "Mcp_Server.Time@1.2.0"),
      { name: "mcp-server-time", version: "1.2.0", exact: true },
    ],
    [
      "uvx --from pkg==version",
      stdio("uvx", "--python", "3.12", "--from", "pkg[extra]==2.1", "bin"),
      { name: "pkg", version: "2.1", exact: true, field: "args[3]" },
    ],
    ["uvx with a range", stdio("uvx", "pkg>=1.0"), { name: "pkg", version: ">=1.0", exact: false }],
    [
      "pipx run --spec",
      stdio("pipx", "run", "--spec", "pkg==3.0.0", "bin"),
      { name: "pkg", exact: true, field: "args[2]" },
    ],
    [
      "docker, no tag",
      stdio("docker", "run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/github/github-mcp-server"),
      {
        ecosystem: "docker",
        name: "ghcr.io/github/github-mcp-server",
        exact: false,
        field: "args[5]",
      },
    ],
    [
      "docker, tag",
      stdio("docker", "run", "--env=A=b", "mcp/fetch:1.0"),
      { name: "mcp/fetch", version: "1.0", exact: false },
    ],
    [
      "docker, registry port + digest",
      stdio("podman", "run", `localhost:5000/mcp/x@sha256:${"a".repeat(64)}`),
      { name: "localhost:5000/mcp/x", exact: true },
    ],
  ])("reads %s", (_label, ref, expected) => {
    expect(ref).toMatchObject(expected);
  });

  it.each([
    ["a local script", stdio("node", "build/index.js")],
    ["a git spec", stdio("npx", "github:user/repo")],
    ["a git URL for uvx", stdio("uvx", "--from", "git+https://github.com/u/r", "bin")],
    ["docker without run", stdio("docker", "compose", "up")],
    ["a remote server", launchPackage({ transport: "http", url: "https://x", headers: {} })],
  ])("ignores %s", (_label, ref) => {
    expect(ref).toBeUndefined();
  });
});

describe("compareVersions", () => {
  it("compares numerically, part by part", () => {
    expect(compareVersions("0.1.15", "0.1.16")).toBe(-1);
    expect(compareVersions("0.1.16", "0.1.16")).toBe(0);
    expect(compareVersions("0.10.0", "0.9.9")).toBe(1);
    expect(compareVersions("1.0.0-beta.1", "1.0.0")).toBe(0);
  });
});
