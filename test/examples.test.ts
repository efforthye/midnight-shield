import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { lintFiles } from "../src/node.js";
import { RULES } from "../src/rules.js";

const SDK_RULES = ["MS101", "MS102", "MS103", "MS104", "MS105", "MS106", "MS107", "MS108", "MS109", "MS110", "MS111", "MS112", "MS113", "MS114", "MS115", "MS116", "MS117", "MS118", "MS119", "MS120"];
// MS030 (invisible direction characters) and MS033 (language version) are tested in new-rules.test.ts rather than planted in an example
const NOT_IN_EXAMPLES = ["MS000", "MS006", "MS030", "MS033"];

describe("bundled examples", () => {
  it("the vulnerable examples trigger every Compact rule exactly once", () => {
    const findings = lintFiles(["examples/vulnerable.compact", "examples/locked.compact"]);
    const expected = RULES.map((r) => r.id)
      .filter((id) => !NOT_IN_EXAMPLES.includes(id) && !SDK_RULES.includes(id))
      .sort();
    assert.deepEqual(findings.map((f) => f.ruleId).sort(), expected);
  });

  it("dapp/vulnerable.ts triggers every TypeScript rule exactly once", () => {
    const findings = lintFiles(["examples/dapp/vulnerable.ts", "examples/dapp/BackupPhrase.tsx"]);
    assert.deepEqual(findings.map((f) => f.ruleId).sort(), SDK_RULES);
  });

  it("the safe versions produce no findings", () => {
    assert.deepEqual(lintFiles(["examples/safe.compact", "examples/dapp/safe.ts"]), []);
  });
});
