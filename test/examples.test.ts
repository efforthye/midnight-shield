import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { lintFiles } from "../src/linter.js";
import { RULES } from "../src/rules.js";

describe("bundled examples", () => {
  it("vulnerable.compact triggers every contract rule exactly once", () => {
    const findings = lintFiles(["examples/vulnerable.compact"]);
    const expected = RULES.map((r) => r.id).filter((id) => id !== "MS000" && id !== "MS006").sort();
    assert.deepEqual(findings.map((f) => f.ruleId).sort(), expected);
  });

  it("safe.compact produces no findings", () => {
    assert.deepEqual(lintFiles(["examples/safe.compact"]), []);
  });
});
