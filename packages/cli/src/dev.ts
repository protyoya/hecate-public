import process from "node:process";

// `pnpm --filter hecate-mcp dev …` runs from packages/cli; resolve file
// arguments against the directory pnpm was invoked from instead.
process.chdir(process.env.INIT_CWD ?? process.cwd());
await import("./index.js");
