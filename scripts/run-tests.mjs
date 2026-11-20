// Runs every compiled test file. Works on Node 20+, where `node --test` does
// not expand globs itself.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";

const dir = join("dist", "test");
const files = readdirSync(dir)
  .filter((f) => f.endsWith(".test.js"))
  .sort()
  .map((f) => join(dir, f));

const extra = process.argv.slice(2); // e.g. --experimental-test-coverage
const result = spawnSync(process.execPath, ["--test", ...extra, ...files], { stdio: "inherit" });
process.exit(result.status ?? 1);
