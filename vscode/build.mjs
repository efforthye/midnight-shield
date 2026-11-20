// Bundles the extension and the analyzer into one CommonJS file.
import { build } from "esbuild";

await build({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node18",
  external: ["vscode"],
  outfile: "dist/extension.js",
  sourcemap: false,
  minify: true,
});
console.log("dist/extension.js");
