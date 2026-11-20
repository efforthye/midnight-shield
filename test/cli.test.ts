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
});
