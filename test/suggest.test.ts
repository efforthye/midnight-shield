import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { lintFiles } from "../src/node.js";
import { formatMarkdown, formatText } from "../src/reporters.js";
import { suggestFix, suggestionDiff } from "../src/suggest.js";

const findings = lintFiles(["examples/vulnerable.compact", "examples/locked.compact", "examples/dapp/vulnerable.ts", "examples/dapp/BackupPhrase.tsx"]);

describe("suggested fixes", () => {
  it("every finding in the examples gets a suggestion that changes the code", () => {
    for (const f of findings) {
      assert.ok(f.suggestion, `${f.ruleId} has no suggestion`);
      const diff = suggestionDiff(f.suggestion);
      // removing dead code is a change too (MS015, MS016)
      assert.ok(diff.some((d) => d.kind !== " "), `${f.ruleId} suggestion changes nothing`);
    }
  });

  it("rewrites the flagged expression itself where it can", () => {
    const after = (id: string) => findings.find((f) => f.ruleId === id)!.suggestion!.after.join("\n");
    assert.match(after("MS001"), /deriveId\(secretKey\(\)\) == owner/);
    assert.match(after("MS003"), /persistentCommit<.*randomness\(\)\)/);
    assert.match(after("MS004"), /persistentCommit<Uint<64>>\(amount, randomness\(\)\)/);
    assert.match(after("MS005"), /\[pad\(32, "myapp:purpose:"\), secretKey\(\)\]/);
    assert.match(after("MS101"), /localhost:6300/);
    assert.doesNotMatch(after("MS102"), /\$\{seed\}/);
    assert.match(after("MS103"), /process\.env\.SEED/);
  });

  it("keeps lines the fix does not change as context", () => {
    const s = suggestFix("MS011", "'setOwner' changes 'ownerId', which …", "  ownerId = disclose(id);")!;
    assert.deepEqual(
      suggestionDiff(s).map((d) => d.kind),
      ["+", " "],
    );
  });

  it("returns nothing rather than a wrong rewrite", () => {
    assert.equal(suggestFix("MS003", "", "  const x = something();"), undefined);
    assert.equal(suggestFix("MS999", "", "x"), undefined);
  });

  it("shows in the text and Markdown reports, and can be turned off", () => {
    assert.match(formatText(findings, 2, { color: false }), /Suggested fix\n\s+- /);
    assert.doesNotMatch(formatText(findings, 2, { color: false, suggestions: false }), /Suggested fix/);
    assert.match(formatMarkdown(findings, 2), /```diff\n- /);
  });
});
