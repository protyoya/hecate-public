import type { ServerLaunch } from "./types.js";

/** The package a stdio launch command runs, e.g. `npx -y @scope/server@1.2.3`. */
export interface PackageRef {
  ecosystem: "npm" | "pypi" | "docker";
  /** npm name, normalized PyPI name (PEP 503), or image repository without tag. */
  name: string;
  /** Version, range or tag as written; undefined when none was given. */
  version?: string;
  /** One specific release: an exact version (npm, PyPI) or an image digest (docker). */
  exact: boolean;
  /** The argument holding the package, e.g. "args[1]". */
  field: string;
}

const EXACT_SEMVER = /^\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?$/;
const NPM_VALUE_FLAGS = new Set([
  "-c",
  "--call",
  "--registry",
  "--cache",
  "--userconfig",
  "-w",
  "--workspace",
]);
const UV_VALUE_FLAGS = new Set([
  "--with",
  "-w",
  "--with-requirements",
  "--python",
  "-p",
  "--index",
  "--index-url",
  "--extra-index-url",
  "--default-index",
  "--directory",
  "--project",
  "--cache-dir",
  "--pip-args",
]);
const DOCKER_VALUE_FLAGS = new Set(
  (
    "-e --env --env-file -v --volume --mount --name -p --publish --network --net -w --workdir " +
    "-u --user --entrypoint --platform -l --label --add-host --cpus -m --memory --pull --restart " +
    "-h --hostname --dns --cap-add --cap-drop --device --gpus --ulimit --log-driver --log-opt " +
    "--security-opt --tmpfs --ipc --pid --runtime --shm-size --stop-signal --expose --group-add"
  ).split(" "),
);

/** Which package a launch runs, if it goes through a package runner; else undefined. */
export function launchPackage(launch: ServerLaunch): PackageRef | undefined {
  if (launch.transport !== "stdio") return undefined;
  let command = basename(launch.command);
  let args = launch.args;
  let offset = 0;
  // Windows configs often wrap the runner: "cmd" "/c" "npx" "-y" "pkg".
  if (command === "cmd" && /^\/c$/i.test(args[0] ?? "")) {
    command = basename(args[1] ?? "");
    args = args.slice(2);
    offset = 2;
  }
  const after = (n: number) => ({ args: args.slice(n), offset: offset + n });
  switch (command) {
    case "npx":
    case "bunx":
      return npm(args, offset);
    case "pnpm":
    case "yarn":
      return args[0] === "dlx" ? npm(...spread(after(1))) : undefined;
    case "npm":
    case "bun":
      return args[0] === "exec" || args[0] === "x" ? npm(...spread(after(1))) : undefined;
    case "uvx":
      return pypi(args, offset);
    case "uv":
      return args[0] === "tool" && args[1] === "run" ? pypi(...spread(after(2))) : undefined;
    case "pipx":
      return args[0] === "run" ? pypi(...spread(after(1))) : undefined;
    case "docker":
    case "podman":
      return args[0] === "run" ? docker(...spread(after(1))) : undefined;
    default:
      return undefined;
  }
}

const spread = ({ args, offset }: { args: string[]; offset: number }) => [args, offset] as const;

function basename(command: string): string {
  const base = command.split(/[\\/]/).pop() ?? "";
  return base.replace(/\.(?:cmd|exe|bat|ps1)$/i, "").toLowerCase();
}

function npm(args: string[], offset: number): PackageRef | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--") continue;
    const inline = /^--package=(.+)$/.exec(arg);
    if (inline) return npmSpec(inline[1], offset + i);
    if (arg === "-p" || arg === "--package") return npmSpec(args[i + 1], offset + i + 1);
    if (arg.startsWith("-")) {
      if (NPM_VALUE_FLAGS.has(arg)) i++;
      continue;
    }
    return npmSpec(arg, offset + i);
  }
  return undefined;
}

function npmSpec(spec: string | undefined, index: number): PackageRef | undefined {
  // Git, URL, alias, tarball and path specs aren't registry packages.
  if (!spec || /^(?:[a-z][a-z+]*:|\.{0,2}\/|~)/i.test(spec) || spec.endsWith(".tgz"))
    return undefined;
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  const name = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? spec.slice(at + 1) : undefined;
  const exact = version !== undefined && EXACT_SEMVER.test(version);
  return { ecosystem: "npm", name, ...(version && { version }), exact, field: `args[${index}]` };
}

function pypi(args: string[], offset: number): PackageRef | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const inline = /^--(?:from|spec)=(.+)$/.exec(arg);
    if (inline) return pypiSpec(inline[1], offset + i);
    if (arg === "--from" || arg === "--spec") return pypiSpec(args[i + 1], offset + i + 1);
    if (arg.startsWith("-")) {
      if (UV_VALUE_FLAGS.has(arg)) i++;
      continue;
    }
    return pypiSpec(arg, offset + i);
  }
  return undefined;
}

function pypiSpec(spec: string | undefined, index: number): PackageRef | undefined {
  if (!spec) return undefined;
  const m =
    /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(==|@)\s*([^\s,;]+)|([<>=!~].*))?$/.exec(
      spec,
    );
  if (!m) return undefined; // git+https://..., paths, URLs
  const name = m[1].toLowerCase().replace(/[-_.]+/g, "-");
  const version = m[3] ?? m[4];
  const exact = m[3] !== undefined && /^\d+(?:\.\d+)*(?:[a-z0-9.+-]*)$/i.test(m[3]);
  return { ecosystem: "pypi", name, ...(version && { version }), exact, field: `args[${index}]` };
}

function docker(args: string[], offset: number): PackageRef | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("-")) {
      if (!arg.includes("=") && DOCKER_VALUE_FLAGS.has(arg)) i++;
      continue;
    }
    const [image, digest] = arg.split("@");
    const colon = image.lastIndexOf(":");
    const tagged = colon > image.lastIndexOf("/");
    const version = tagged ? image.slice(colon + 1) : undefined;
    return {
      ecosystem: "docker",
      name: tagged ? image.slice(0, colon) : image,
      ...(version && { version }),
      exact: digest !== undefined,
      field: `args[${offset + i}]`,
    };
  }
  return undefined;
}

/** Compares dotted numeric versions ("0.1.15" < "0.1.16"); pre-release suffixes are ignored. */
export function compareVersions(a: string, b: string): number {
  const parts = (v: string) =>
    v
      .split(/[-+]/)[0]
      .split(".")
      .map((n) => Number.parseInt(n, 10) || 0);
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  return 0;
}
