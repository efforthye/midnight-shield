import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { RULES } from "../src/rules.js";

const CLI = resolve("dist/src/cli.js");

function run(args: string[], cwd = process.cwd()) {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

function tempDir(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), "midnight-shield-"));
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
  return dir;
}

describe("CLI", () => {
  it("exits 1 when a finding reaches --fail-on (default high)", () => {
    const r = run(["examples/vulnerable.compact"]);
    assert.equal(r.code, 1);
    assert.match(r.stdout, /MS001/);
  });

  it("exits 0 on a clean file", () => {
    const r = run(["examples/safe.compact"]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /No findings/);
  });

  it("exits 0 with --fail-on none", () => {
    assert.equal(run(["examples/vulnerable.compact", "--fail-on", "none"]).code, 0);
  });

  it("respects --disable and --min-severity", () => {
    const r = run(["examples/vulnerable.compact", "--format", "json", "--disable", "MS001", "--min-severity", "high", "--fail-on", "none"]);
    const ids = JSON.parse(r.stdout).findings.map((f: { ruleId: string }) => f.ruleId);
    assert.ok(!ids.includes("MS001"));
    assert.ok(!ids.includes("MS005")); // low, hidden
    assert.ok(ids.includes("MS003"));
  });

  it("writes SARIF to a file with --output", () => {
    const dir = tempDir();
    const out = join(dir, "r.sarif");
    run(["examples/vulnerable.compact", "--format", "sarif", "--output", out, "--fail-on", "none"]);
    assert.equal(JSON.parse(readFileSync(out, "utf8")).version, "2.1.0");
  });

  it("creates a config with --init and loads it automatically", () => {
    const dir = tempDir({ "a.compact": "import CompactStandardLibrary;\nexport ledger x: Field;\n" });
    assert.equal(run(["--init"], dir).code, 0);
    assert.ok(existsSync(join(dir, "midnight-shield.config.json")));
    assert.equal(run(["--init"], dir).code, 2); // refuses to overwrite

    writeFileSync(join(dir, "midnight-shield.config.json"), JSON.stringify({ disable: ["MS006"] }));
    const r = run(["."], dir);
    assert.doesNotMatch(r.stdout, /MS006/);
  });

  it("exits 2 on an invalid config, option or path", () => {
    const dir = tempDir({ "midnight-shield.config.json": '{"failOn":"sometimes"}' });
    assert.equal(run(["."], dir).code, 2);
    assert.equal(run(["--format", "xml"]).code, 2);
    assert.equal(run(["--no-such-flag"]).code, 2);
    assert.equal(run(["does/not/exist"]).code, 2);
  });

  it("lists every rule and prints the package version", () => {
    const rules = run(["--list-rules"]).stdout;
    for (const r of RULES) assert.match(rules, new RegExp(r.id));
    const pkg = JSON.parse(readFileSync("package.json", "utf8"));
    assert.equal(run(["--version"]).stdout.trim(), pkg.version);
  });

  it("explains a rule from its documentation", () => {
    const r = run(["explain", "ms001"]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /# MS001 own-public-key-auth/);
    assert.equal(run(["explain", "MS999"]).code, 2);
  });

  it("prints the disclosure map as text and JSON", () => {
    assert.match(run(["examples/vulnerable.compact", "--print", "disclosures"]).stdout, /backupKey/);
    const json = JSON.parse(run(["examples/vulnerable.compact", "--print", "disclosures", "--format", "json"]).stdout);
    assert.ok(json.disclosures.some((d: { protection: string }) => d.protection === "raw"));
  });

  it("writes a baseline, then only reports new findings", () => {
    const dir = tempDir({ "c.compact": readFileSync("examples/vulnerable.compact", "utf8") });
    assert.equal(run(["c.compact", "--write-baseline", "b.json"], dir).code, 0);
    const clean = run(["c.compact", "--baseline", "b.json"], dir);
    assert.equal(clean.code, 0);
    assert.match(clean.stdout, /No findings/);
    assert.match(run(["c.compact", "--baseline", "b.json", "--show-suppressed"], dir).stdout, /Suppressed \(31\)/);
  });

  it("saves snapshots and diffs them, failing only on new findings", () => {
    const safe = readFileSync("examples/safe.compact", "utf8");
    const broken = safe.replace(/(export circuit transferOwnership[^{]*\{\n)\s*assert\([^\n]*\n/, "$1");
    const dir = tempDir({ "c.compact": safe });
    assert.equal(run(["snapshot", "c.compact", "-o", "base.json"], dir).code, 0);
    writeFileSync(join(dir, "c.compact"), broken);
    assert.equal(run(["snapshot", "c.compact", "-o", "head.json"], dir).code, 0);
    const text = run(["diff", "base.json", "head.json"], dir);
    assert.equal(text.code, 0);
    assert.match(text.stdout, /New findings \(1\)\n  \+ HIGH MS011/);
    assert.equal(run(["diff", "base.json", "head.json", "--fail-on", "high"], dir).code, 1);
    assert.equal(run(["diff", "head.json", "base.json", "--fail-on", "high"], dir).code, 0);
    assert.equal(run(["diff", "base.json"], dir).code, 2);
  });

  it("writes a status badge next to the report", () => {
    const dir = tempDir({ "c.compact": readFileSync("examples/vulnerable.compact", "utf8") });
    run(["c.compact", "--badge", "badge.json", "--fail-on", "none"], dir);
    const badge = JSON.parse(readFileSync(join(dir, "badge.json"), "utf8"));
    assert.equal(badge.label, "midnight shield");
    assert.equal(badge.color, "red");
  });

  it("writes a Markdown report", () => {
    assert.match(run(["examples/vulnerable.compact", "--format", "markdown", "--fail-on", "none"]).stdout, /^# Midnight Shield report/);
  });

  it("filters by confidence", () => {
    const r = run(["examples/vulnerable.compact", "--format", "json", "--min-confidence", "high", "--fail-on", "none"]);
    assert.ok(JSON.parse(r.stdout).findings.every((f: { confidence: string }) => f.confidence === "high"));
  });

  it("fixes a missing pragma with --fix, and --fix-dry-run changes nothing", () => {
    const src = "import CompactStandardLibrary;\nexport ledger x: Field;\n";
    const dir = tempDir({ "a.compact": src });
    assert.match(run(["a.compact", "--fix-dry-run"], dir).stdout, /would fix a\.compact \(MS006\)/);
    assert.equal(readFileSync(join(dir, "a.compact"), "utf8"), src);
    run(["a.compact", "--fix"], dir);
    assert.match(readFileSync(join(dir, "a.compact"), "utf8"), /^pragma language_version/);
  });

  it("loads plugins and can skip TypeScript files", () => {
    const dir = tempDir({ "a.compact": "pragma language_version >= 0.28.0;\nexport ledger c: Counter;\nexport circuit d(): [] { c.decrement(1); }\n", "app.ts": "console.log(seed);" });
    const plugin = resolve("examples/plugins/no-counter-decrement.mjs");
    const r = run([".", "--plugin", plugin, "--format", "json", "--fail-on", "none"], dir);
    const ids = JSON.parse(r.stdout).findings.map((f: { ruleId: string }) => f.ruleId);
    assert.ok(ids.includes("ACME001"));
    assert.ok(ids.includes("MS102"));
    const noSdk = JSON.parse(run([".", "--no-sdk", "--format", "json", "--fail-on", "none"], dir).stdout);
    assert.ok(!noSdk.findings.some((f: { ruleId: string }) => f.ruleId === "MS102"));
    assert.equal(run([".", "--plugin", "missing.mjs"], dir).code, 2);
  });
});
