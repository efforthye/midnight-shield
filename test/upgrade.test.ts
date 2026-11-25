import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { compareContracts, formatUpgradeMarkdown, formatUpgradeText } from "../src/upgrade.js";
import { HEADER } from "./helpers.js";

const kinds = (a: string, b: string) => compareContracts(HEADER + a, HEADER + b).map((c) => `${c.severity}:${c.kind}:${c.subject}`);

describe("upgrade check", () => {
  it("reports nothing for the same contract", () => {
    const src = `export ledger a: Uint<64>;\nexport circuit f(x: Uint<64>): [] { a = disclose(x); }`;
    assert.deepEqual(kinds(src, src), []);
  });

  it("a field added at the end needs new state; one inserted in the middle shifts the rest", () => {
    assert.deepEqual(kinds(`export ledger a: Uint<64>;`, `export ledger a: Uint<64>;\nexport ledger b: Boolean;`), ["high:field-added:b"]);
    const mid = compareContracts(HEADER + `export ledger a: Uint<64>;\nexport ledger c: Field;`, HEADER + `export ledger a: Uint<64>;\nexport ledger b: Boolean;\nexport ledger c: Field;`);
    assert.deepEqual(mid.map((c) => `${c.severity}:${c.kind}:${c.subject}`), ["critical:field-moved:b"]);
    assert.match(mid[0].message, /moves one position \(c\)/);
  });

  it("removed, reordered and retyped fields are critical; a rename in place is not", () => {
    assert.deepEqual(kinds(`export ledger a: Uint<64>;\nexport ledger b: Field;`, `export ledger b: Field;`), ["critical:field-removed:a"]);
    assert.deepEqual(kinds(`export ledger a: Field;\nexport ledger b: Field;`, `export ledger b: Field;\nexport ledger a: Field;`).sort(), ["critical:field-moved:a", "critical:field-moved:b"]);
    assert.deepEqual(kinds(`export ledger a: Uint<64>;`, `export ledger a: Uint<128>;`), ["critical:field-type-changed:a"]);
    assert.deepEqual(kinds(`export ledger a: Uint<64>;`, `export ledger total: Uint<64>;`), ["low:field-renamed:total"]);
  });

  it("enum members reordered under stored values are critical; appended ones are not", () => {
    const v1 = `enum P { open, closed }\nexport ledger p: P;`;
    assert.deepEqual(kinds(v1, `enum P { draft, open, closed }\nexport ledger p: P;`), ["critical:type-changed:P"]);
    assert.deepEqual(kinds(v1, `enum P { open, closed, archived }\nexport ledger p: P;`), ["low:type-changed:P"]);
  });

  it("circuit and witness interface changes, and guards that got weaker", () => {
    const owner = `export ledger ownerId: Bytes<32>;\nexport ledger fee: Uint<64>;\nwitness sk(): Bytes<32>;\ncircuit me(): Bytes<32> { return persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:"), sk()]); }\n`;
    const v1 = owner + `export circuit setFee(f: Uint<64>): [] { assert(me() == ownerId, "no"); fee = disclose(f); }\nexport circuit old(): [] {}`;
    const v2 = owner + `witness extra(): Field;\nexport circuit setFee(f: Uint<64>, g: Uint<64>): [] { fee = disclose(f); }\nexport circuit fresh(): [] {}`;
    assert.deepEqual(kinds(v1, v2), ["high:access-weakened:setFee", "medium:circuit-signature-changed:setFee", "medium:circuit-removed:old", "low:witness-changed:extra", "info:circuit-added:fresh"]);
    const files = [{ file: "c.compact", changes: compareContracts(HEADER + v1, HEADER + v2) }];
    assert.match(formatUpgradeText(files, { color: false }), /5 changes: 0 critical, 1 high, 2 medium, 1 low, 1 info\./);
    assert.match(formatUpgradeMarkdown(files), /\| high \| `c.compact` \| access-weakened \| `setFee` \|/);
  });

  it("the CLI pairs folders by path and fails on high by default", () => {
    const dir = mkdtempSync(join(tmpdir(), "ms-upgrade-"));
    for (const [v, body] of [["v1", "export ledger a: Uint<64>;"], ["v2", "export ledger a: Uint<64>;\nexport ledger b: Field;"]]) {
      mkdirSync(join(dir, v));
      writeFileSync(join(dir, v, "c.compact"), HEADER + body);
    }
    const cli = resolve("dist/src/cli.js");
    const r = spawnSync(process.execPath, [cli, "upgrade", "v1", "v2"], { cwd: dir, encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
    assert.equal(r.status, 1);
    assert.match(r.stdout, /HIGH\s+field-added\s+b/);
    const ok = spawnSync(process.execPath, [cli, "upgrade", "v1", "v2", "--fail-on", "critical", "--format", "json"], { cwd: dir, encoding: "utf8" });
    assert.equal(ok.status, 0);
    assert.equal(JSON.parse(ok.stdout).files[0].changes[0].kind, "field-added");
  });
});
