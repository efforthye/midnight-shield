import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { lintSource } from "../src/linter.js";
import { formatJson, formatSarif, formatText, VERSION } from "../src/reporters.js";
import { RULES } from "../src/rules.js";
import { HEADER } from "./helpers.js";

const SOURCE =
  HEADER +
  `export ledger owner: ZswapCoinPublicKey;
export circuit withdraw(): [] {
  assert(ownPublicKey() == owner, "not owner");
}
`;
const findings = lintSource(SOURCE, "contracts/main.compact");

describe("text reporter", () => {
  it("prints the file, severity, rule, location, code frame and summary", () => {
    const out = formatText(findings, 1, { color: false });
    assert.match(out, /^contracts\/main\.compact$/m);
    assert.match(out, /CRITICAL\s+MS001 own-public-key-auth\s+contracts\/main\.compact:5:10/);
    assert.match(out, /5 │ {3}assert\(ownPublicKey\(\) == owner/);
    assert.match(out, /│ {10}\^{14}\n/); // caret under ownPublicKey()
    assert.match(out, /docs\/rules\/MS001\.md/);
    assert.match(out, /1 finding in 1 file \(1 critical\)/);
  });

  it("has no ANSI codes when color is off", () => {
    assert.doesNotMatch(formatText(findings, 1, { color: false }), /\x1b\[/);
  });

  it("can hide code frames and links", () => {
    const out = formatText(findings, 1, { color: false, codeFrame: false, links: false });
    assert.doesNotMatch(out, /│/);
    assert.doesNotMatch(out, /https:/);
  });

  it("reports a clean run", () => {
    assert.match(formatText([], 3, { color: false }), /No findings in 3 files\./);
  });
});

describe("JSON reporter", () => {
  it("produces parseable JSON with tool, version and complete findings", () => {
    const data = JSON.parse(formatJson(findings));
    assert.equal(data.tool, "midnight-shield");
    assert.equal(data.version, VERSION);
    const f = data.findings[0];
    for (const key of ["ruleId", "ruleName", "severity", "message", "file", "line", "col", "docUrl", "snippet"]) {
      assert.ok(key in f, `missing ${key}`);
    }
  });
});

describe("SARIF reporter", () => {
  const sarif = JSON.parse(formatSarif(findings));
  const run = sarif.runs[0];

  it("declares SARIF 2.1.0 with a schema", () => {
    assert.equal(sarif.version, "2.1.0");
    assert.match(sarif.$schema, /sarif-2\.1\.0/);
  });

  it("lists every rule with a description, help link and security severity", () => {
    const ids = run.tool.driver.rules.map((r: { id: string }) => r.id);
    assert.deepEqual(ids, RULES.map((r) => r.id));
    for (const r of run.tool.driver.rules) {
      assert.ok(r.shortDescription.text.length > 0);
      assert.match(r.helpUri, /^https:\/\//);
      assert.ok(Number(r.properties["security-severity"]) >= 0);
    }
  });

  it("emits results that reference declared rules, valid levels and 1-based locations", () => {
    const declared = new Set(run.tool.driver.rules.map((r: { id: string }) => r.id));
    assert.equal(run.results.length, findings.length);
    for (const res of run.results) {
      assert.ok(declared.has(res.ruleId));
      assert.ok(["error", "warning", "note", "none"].includes(res.level));
      const region = res.locations[0].physicalLocation.region;
      assert.ok(region.startLine >= 1 && region.startColumn >= 1);
      assert.equal(res.locations[0].physicalLocation.artifactLocation.uri, "contracts/main.compact");
    }
  });
});
