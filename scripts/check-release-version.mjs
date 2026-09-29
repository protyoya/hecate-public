// The release tag (vX.Y.Z) must match the version of every published package.
// Prereleases (vX.Y.Z-beta.N) publish to the npm dist-tag named by their
// identifier ("beta"), so they never become `latest`; the tag is written to
// $GITHUB_OUTPUT as dist_tag.
import { appendFileSync, readFileSync } from "node:fs";

const tag = process.argv[2] ?? "";
const version = tag.replace(/^v/, "");
const packages = ["packages/cli/package.json", "packages/sdk/package.json"];

const mismatches = packages
  .map((path) => [path, JSON.parse(readFileSync(path, "utf8")).version])
  .filter(([, packageVersion]) => packageVersion !== version);

if (!/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(version) || mismatches.length > 0) {
  console.error(`Tag "${tag}" doesn't match the package versions:`);
  for (const [path, packageVersion] of mismatches) console.error(`  ${path}: ${packageVersion}`);
  process.exit(1);
}
const distTag = version.includes("-") ? version.split("-")[1].split(".")[0] : "latest";
if (!/^[a-z][a-z0-9]*$/.test(distTag)) {
  console.error(`Can't derive an npm dist-tag from "${version}".`);
  process.exit(1);
}
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `dist_tag=${distTag}\n`);
console.log(`Releasing ${version} to the "${distTag}" dist-tag.`);
