import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  platform: "node",
  target: "node20",
  clean: true,
  noExternal: ["@hecate-mcp/core"], // bundle core, as the CLI does
  dts: { resolve: ["@hecate-mcp/core"] }, // and inline its types
});
