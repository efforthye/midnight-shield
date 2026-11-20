import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { lintFiles } from "../src/node.js";
import { RULES } from "../src/rules.js";

const SDK_RULES = ["MS101", "MS102"];
const NOT_IN_EXAMPLES = ["MS000", "MS006"];

describe("bundled examples", () => {
  it("vulnerable.compact triggers every Compact rule exactly once", () => {
    const findings = lintFiles(["examples/vulnerable.compact"]);
    const expected = RULES.map((r) => r.id)
      .filter((id) => !NOT_IN_EXAMPLES.includes(id) && !SDK_RULES.includes(id))
      .sort();
    assert.deepEqual(findings.map((f) => f.ruleId).sort(), expected);
  });

  it("dapp/vulnerable.ts triggers every TypeScript rule exactly once", () => {
    const findings = lintFiles(["examples/dapp/vulnerable.ts"]);
    assert.deepEqual(findings.map((f) => f.ruleId).sort(), SDK_RULES);
  });

  it("the safe versions produce no findings", () => {
    assert.deepEqual(lintFiles(["examples/safe.compact", "examples/dapp/safe.ts"]), []);
  });
});
