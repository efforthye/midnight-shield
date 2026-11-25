import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { badgeJson } from "../src/badge.js";
import { lintSource, mapDisclosures } from "../src/linter.js";
import { createSnapshot, diffIsEmpty, diffSnapshots, formatDiffMarkdown, readSnapshot } from "../src/privacy-diff.js";

const SAFE = readFileSync("examples/safe.compact", "utf8");
const snap = (src: string) => createSnapshot(lintSource(src, "c.compact"), mapDisclosures(src, "c.compact"), "test");

const UNGUARDED = SAFE.replace(
  /(export circuit transferOwnership[^{]*\{\n)\s*assert\([^\n]*\n/,
  "$1",
);
const RAW = SAFE.replace("committed = persistentCommit<Uint<64>>(amount, randomness());", "committed = disclose(amount as Field as Bytes<32>);");

describe("privacy diff", () => {
  it("is empty for the same code, even when lines move", () => {
    assert.ok(diffIsEmpty(diffSnapshots(snap(SAFE), snap(SAFE))));
    assert.ok(diffIsEmpty(diffSnapshots(snap(SAFE), snap("// a new comment\n\n" + SAFE))));
  });

  it("reports data that becomes public and the findings a change adds", () => {
    assert.notEqual(UNGUARDED, SAFE);
    const d = diffSnapshots(snap(SAFE), snap(UNGUARDED));
    assert.deepEqual(d.newFindings.map((f) => f.ruleId), ["MS011"]);
    const r = diffSnapshots(snap(SAFE), snap(RAW));
    assert.ok([...r.added, ...r.changed.map((c) => c.after)].some((x) => x.circuit === "commitAmount" && x.protection === "raw"));
  });

  it("reports fixed findings when the change goes the other way", () => {
    const d = diffSnapshots(snap(UNGUARDED), snap(SAFE));
    assert.deepEqual(d.fixedFindings.map((f) => f.ruleId), ["MS011"]);
    assert.equal(d.newFindings.length, 0);
  });

  it("renders a pull request comment with a marker to update it in place", () => {
    const md = formatDiffMarkdown(diffSnapshots(snap(SAFE), snap(UNGUARDED)), { marker: "<!-- m -->" });
    assert.match(md, /^<!-- m -->\n## 🛡️ Midnight Shield privacy diff/);
    assert.match(md, /### New findings/);
    assert.match(formatDiffMarkdown(diffSnapshots(snap(SAFE), snap(SAFE))), /does not make anything new public/);
  });

  it("rejects files that are not snapshots", () => {
    assert.throws(() => readSnapshot("{}", "x.json"), /not a Midnight Shield snapshot/);
    assert.throws(() => readSnapshot("nope", "x.json"), /not valid JSON/);
    assert.equal(readSnapshot(JSON.stringify(snap(SAFE)), "s.json").tool, "midnight-shield");
  });
});

describe("status badge", () => {
  it("is green with no findings and names the worst severities otherwise", () => {
    assert.deepEqual([badgeJson([]).message, badgeJson([]).color], ["verified", "brightgreen"]);
    const b = badgeJson(lintSource(readFileSync("examples/vulnerable.compact", "utf8"), "v.compact"));
    assert.equal(b.schemaVersion, 1);
    assert.match(b.message, /^2 critical, \d+ high \+$/);
    assert.equal(b.color, "red");
    assert.match(b.logoSvg, /^<svg/);
  });
});
