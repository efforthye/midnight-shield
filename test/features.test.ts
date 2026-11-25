import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { applyEdits, pragmaFix } from "../src/fixes.js";
import { createBaseline, lintSource, mapDisclosures } from "../src/linter.js";
import { lintFiles, readBaseline } from "../src/node.js";
import { validateRule, PluginError } from "../src/plugins.js";
import { loadPlugins } from "../src/plugin-loader.js";
import { formatMarkdown, formatSarif, formatText, formatDisclosures } from "../src/reporters.js";
import { lintSdkSource } from "../src/sdk.js";
import { HEADER } from "./helpers.js";

const VULNERABLE = readFileSync("examples/vulnerable.compact", "utf8");

describe("confidence", () => {
  it("every finding carries a confidence, and --min-confidence filters by it", () => {
    const all = lintSource(VULNERABLE, "v.compact");
    assert.ok(all.every((f) => ["high", "medium", "low"].includes(f.confidence)));
    const high = lintSource(VULNERABLE, "v.compact", { minConfidence: "high" });
    assert.ok(high.length > 0 && high.length < all.length);
    assert.ok(high.every((f) => f.confidence === "high"));
    assert.ok(!high.some((f) => f.ruleId === "MS007")); // name-based, low confidence
  });
});

describe("baseline", () => {
  it("fingerprints stay the same when code moves to other lines", () => {
    const a = lintSource(VULNERABLE, "v.compact");
    const b = lintSource("\n\n// moved down\n" + VULNERABLE, "v.compact");
    assert.deepEqual(
      a.map((f) => f.fingerprint),
      b.map((f) => f.fingerprint),
    );
    assert.notDeepEqual(
      a.map((f) => f.line),
      b.map((f) => f.line),
    );
  });

  it("accepted findings are hidden, new ones are reported", () => {
    const before = lintSource(VULNERABLE, "v.compact");
    const baseline = new Set(createBaseline(before).findings.map((f) => f.fingerprint));
    const changed = VULNERABLE + "\nexport ledger leaked2: Bytes<32>;\nexport circuit leakAgain(): [] {\n  leaked2 = disclose(secretKey());\n}\n";
    const after = lintSource(changed, "v.compact", { baseline });
    assert.deepEqual(after.map((f) => f.ruleId), ["MS007"]);
    const withSuppressed = lintSource(changed, "v.compact", { baseline, includeSuppressed: true });
    assert.equal(withSuppressed.filter((f) => f.suppressed === "baseline").length, before.length);
  });

  it("round-trips through a file", () => {
    const dir = mkdtempSync(join(tmpdir(), "ms-baseline-"));
    const file = join(dir, "baseline.json");
    writeFileSync(file, JSON.stringify(createBaseline(lintSource(VULNERABLE, "v.compact"))));
    assert.ok(readBaseline(file).size > 0);
    writeFileSync(file, "{}");
    assert.throws(() => readBaseline(file), /not a Midnight Shield baseline/);
  });
});

describe("suppressed findings", () => {
  const src = `${HEADER}
    export ledger pk: Bytes<32>;
    witness sk(): Bytes<32>;
    export circuit register(): [] {
      // shield-disable-next-line MS005
      pk = disclose(persistentHash<Bytes<32>>(sk()));
    }`;

  it("can be included and are marked", () => {
    const f = lintSource(src, "s.compact", { includeSuppressed: true }).filter((x) => x.ruleId === "MS005");
    assert.equal(f.length, 1);
    assert.equal(f[0].suppressed, "inline");
  });

  it("show in a separate section of the text report and as SARIF suppressions", () => {
    const all = lintSource(src, "s.compact", { includeSuppressed: true });
    assert.match(formatText(all, 1, { color: false }), /Suppressed \(1\)/);
    const sarif = JSON.parse(formatSarif(all));
    const res = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === "MS005");
    assert.deepEqual(res.suppressions, [{ kind: "inSource" }]);
  });
});

describe("disclosure map", () => {
  const entries = mapDisclosures(VULNERABLE, "v.compact");

  it("lists every point where private data becomes public, with its protection", () => {
    const leak = entries.find((d) => d.circuit === "backupKey");
    assert.ok(leak);
    assert.equal(leak.protection, "raw");
    assert.deepEqual(leak.sources, ["witness:secretKey"]);
    assert.ok(leak.findings.includes("MS007"));

    const vote = entries.find((d) => d.circuit === "castVote");
    assert.equal(vote?.protection, "hash");
    assert.equal(vote?.secretBits, 8);

    const commit = entries.find((d) => d.circuit === "commitAmount");
    assert.equal(commit?.protection, "commit");
  });

  it("includes return values of exported circuits", () => {
    const src = `${HEADER}
      witness balance(): Uint<64>;
      export circuit peek(): Uint<64> { return disclose(balance()); }`;
    const vias = mapDisclosures(src).map((d) => d.via);
    assert.ok(vias.includes("disclose"));
    assert.ok(vias.includes("return"));
  });

  it("renders as a table", () => {
    const out = formatDisclosures(entries, { color: false });
    assert.match(out, /backupKey/);
    assert.match(out, /RAW/);
    assert.match(out, /disclosure points/);
  });
});

describe("markdown report", () => {
  it("has a summary, a findings table and details", () => {
    const md = formatMarkdown(lintSource(VULNERABLE, "v.compact"), 1, { date: "2026-11-20" });
    assert.match(md, /^# Midnight Shield report/);
    assert.match(md, /\| 🟣 critical \| 2 \|/);
    assert.match(md, /### 1\. MS001 own-public-key-auth/);
    assert.match(md, /```compact/);
  });
});

describe("autofix", () => {
  it("inserts a pragma after the license header, once", () => {
    const src = "// SPDX-License-Identifier: MIT\n// header\n\nimport CompactStandardLibrary;\nexport ledger x: Field;\n";
    const findings = lintSource(src);
    const ms006 = findings.find((f) => f.ruleId === "MS006");
    assert.ok(ms006?.fix);
    const fixed = applyEdits(src, [ms006.fix]);
    assert.equal(fixed.split("\n")[2], "pragma language_version >= 0.28.0;");
    assert.ok(!lintSource(fixed).some((f) => f.ruleId === "MS006"));
  });

  it("keeps Windows line endings", () => {
    const src = "import CompactStandardLibrary;\r\nexport ledger x: Field;\r\n";
    const fixed = applyEdits(src, [pragmaFix(src)]);
    assert.ok(fixed.startsWith("pragma language_version >= 0.28.0;\r\nimport"));
  });

  it("offers fixes only for rules where a fix cannot change contract behavior", () => {
    const withFix = lintSource(VULNERABLE).filter((f) => f.fix);
    assert.deepEqual(withFix, []);
  });
});

describe("custom rules (plugins)", () => {
  it("loads a plugin and reports its findings next to built-in ones", async () => {
    const plugins = await loadPlugins(["examples/plugins/no-counter-decrement.mjs"]);
    assert.equal(plugins[0].id, "ACME001");
    const src = `${HEADER}
      export ledger c: Counter;
      export circuit down(): [] { c.decrement(1); }`;
    const f = lintSource(src, "p.compact", { plugins });
    assert.ok(f.some((x) => x.ruleId === "ACME001" && x.line === 5));
    assert.match(formatSarif(f, plugins), /ACME001/);
  });

  it("validates rule definitions", () => {
    const ok = { id: "ACME002", name: "x", severity: "low", summary: "x", check() {} };
    assert.equal(validateRule(ok, "p").confidence, "medium");
    assert.throws(() => validateRule({ ...ok, id: "MS999" }, "p"), PluginError);
    assert.throws(() => validateRule({ ...ok, id: "bad" }, "p"), PluginError);
    assert.throws(() => validateRule({ ...ok, severity: "huge" }, "p"), PluginError);
    assert.throws(() => validateRule({ ...ok, check: 1 }, "p"), PluginError);
  });

  it("reports a crashing rule with its ID", () => {
    const boom = validateRule({ id: "ACME003", name: "boom", severity: "low", summary: "x", check() { throw new Error("oops"); } }, "p");
    assert.throws(() => lintSource(HEADER, "a.compact", { plugins: [boom] }), /ACME003 crashed.*oops/);
  });
});

describe("TypeScript/SDK checks", () => {
  it("flags remote proof servers but not local ones or other remote services", () => {
    const ids = (src: string) => lintSdkSource(src).map((f) => f.ruleId);
    assert.deepEqual(ids(`const p = httpClientProofProvider("https://prover.example.com");`), ["MS101"]);
    assert.deepEqual(ids(`const cfg = { proofServer: 'https://prover.example.com' };`), ["MS101"]);
    assert.deepEqual(ids(`const u = "http://10.0.0.5:6300";`), ["MS101"]);
    assert.deepEqual(ids(`const cfg = { proofServer: 'http://127.0.0.1:6300', indexer: 'https://indexer.example.com' };`), []);
    assert.deepEqual(ids(`const p = httpClientProofProvider("http://localhost:6300");`), []);
    assert.deepEqual(ids(`const cfg = { proofServer: local, faucet: 'https://faucet.example.com/' };`), []);
  });

  it("flags secrets passed directly to log calls", () => {
    const ids = (src: string) => lintSdkSource(src).map((f) => f.ruleId);
    assert.deepEqual(ids("console.log(seed);"), ["MS102"]);
    assert.deepEqual(ids("logger.info(`key: ${secretKey}`);"), ["MS102"]);
    assert.deepEqual(ids("console.log(publicKeyOf(seed));"), []);
    assert.deepEqual(ids("console.log(`seed has ${seed.length} bytes`);"), []);
    assert.deepEqual(ids("logger.info(`built from ${secret.kind}`);"), []);
    assert.deepEqual(ids("console.log(`Installing compiler ${pin}`);"), []);
  });

  it("skips test files", () => {
    const dir = mkdtempSync(join(tmpdir(), "ms-sdk-"));
    writeFileSync(join(dir, "app.test.ts"), "console.log(seed);");
    writeFileSync(join(dir, "app.ts"), "console.log(seed);");
    const f = lintFiles([dir]);
    assert.equal(f.length, 1);
    assert.match(f[0].file, /app\.ts$/);
  });
});
