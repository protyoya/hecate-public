import pkg from "../package.json" with { type: "json" };

/** From package.json, so a release bumps the version in one place (inlined by the build). */
export const VERSION: string = pkg.version;
