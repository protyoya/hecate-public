# Contributing to Hecate

- Sign off every commit (DCO): `git commit -s`.
- Keep @hecate-mcp/core browser-safe: no Node APIs, no runtime dependencies.
- Run `pnpm build && pnpm test && pnpm typecheck && pnpm lint` before pushing.

## Releasing

`hecate-mcp` and `@hecate-mcp/sdk` are released together, at the same version.

1. Bump `version` in `packages/cli/package.json` and `packages/sdk/package.json`,
   commit, and push a matching tag, e.g. `git tag v0.1.0-beta.1 && git push origin v0.1.0-beta.1`.
   A prerelease (`-beta.N`) publishes to the npm `beta` dist-tag and never
   becomes `latest`; a plain `vX.Y.Z` publishes to `latest`. While Hecate is in
   beta, the READMEs install `@beta`; drop that for the first stable release.
2. `.github/workflows/release.yml` checks the tag against both versions, runs
   the build, tests, typecheck, lint and the package smoke test, then publishes
   both packages with npm provenance through trusted publishing: no npm token is
   stored in GitHub.

Setup, once:

- The first version of each package has to be published by hand, because npm
  attaches trusted publishers to existing packages: `npm login` (with 2FA),
  `pnpm install && pnpm build`, then `pnpm publish --tag beta` in
  `packages/cli` and in `packages/sdk`. Always publish with pnpm: it rewrites `workspace:*`
  dependencies, and `prepack` adds NOTICE to the tarball.
- On npmjs.com, add a trusted publisher to each package: GitHub Actions, this
  repository, workflow `release.yml`, environment `npm`.
