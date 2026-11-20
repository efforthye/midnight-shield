// Builds the web playground into playground/dist/index.html: one self-contained
// file with the analyzer bundled in, ready for GitHub Pages or any static host.
import { build } from "esbuild";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

const examples = [
  { name: "vulnerable", label: "Vulnerable contract (all Compact rules)", lang: "compact", file: "examples/vulnerable.compact" },
  { name: "safe", label: "Safe contract (no findings)", lang: "compact", file: "examples/safe.compact" },
  { name: "dapp", label: "Vulnerable DApp code (TypeScript)", lang: "ts", file: "examples/dapp/vulnerable.ts" },
].map((e) => ({ ...e, source: readFileSync(e.file, "utf8") }));

writeFileSync("playground/examples.generated.ts", `export const EXAMPLES = ${JSON.stringify(examples.map(({ file, ...e }) => e), null, 2)};\n`);

const result = await build({
  entryPoints: ["playground/app.ts"],
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "es2020",
  minify: true,
  write: false,
  legalComments: "none",
});
const js = result.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");
const html = readFileSync("playground/index.html", "utf8").replace("/*__BUNDLE__*/", () => js);
mkdirSync("playground/dist", { recursive: true });
writeFileSync("playground/dist/index.html", html);
console.log(`playground/dist/index.html (${(html.length / 1024).toFixed(0)} KB)`);
