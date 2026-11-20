import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { lintFiles } from "../src/node.js";

// Every labeled benchmark case must give exactly the expected rules, except the
// misses documented as known limits (see bench/RESULTS.md).
const dir = "bench/cases";

describe("benchmark cases", () => {
  for (const f of readdirSync(dir).filter((x) => /\.(compact|tsx?)$/.test(x)).sort()) {
    it(f, () => {
      const path = join(dir, f);
      const text = readFileSync(path, "utf8");
      const expect = (text.match(/^\/\/ expect: (.*)$/m)?.[1] ?? "none").split(",").map((s) => s.trim()).filter((s) => s && s !== "none").sort();
      const knownLimit = /^\/\/ note: .*known limit/m.test(text);
      const got = [...new Set(lintFiles([path]).filter((x) => x.ruleId !== "MS006").map((x) => x.ruleId))].sort();
      const extra = got.filter((id) => !expect.includes(id));
      assert.deepEqual(extra, [], `false positive in ${f}`);
      if (!knownLimit) assert.deepEqual(got, expect, `missed in ${f}`);
    });
  }
});
