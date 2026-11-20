import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { lintFiles } from "../src/node.js";
import { isScannableFile, lintFileMap, parseRepoUrl, usesMidnightSdk } from "../src/repo.js";

describe("repository scanning (playground)", () => {
  it("reads GitHub repository references in common forms", () => {
    assert.deepEqual(parseRepoUrl("efforthye/midnight-shield"), { owner: "efforthye", repo: "midnight-shield" });
    assert.deepEqual(parseRepoUrl("https://github.com/efforthye/midnight-shield.git"), { owner: "efforthye", repo: "midnight-shield" });
    assert.deepEqual(parseRepoUrl("github.com/a/b/tree/dev/contracts/src/"), { owner: "a", repo: "b", ref: "dev", path: "contracts/src" });
    assert.equal(parseRepoUrl("midnight-shield"), undefined);
    assert.equal(parseRepoUrl("https://github.com/a/b/issues/1"), undefined);
    assert.equal(parseRepoUrl("a/b c"), undefined);
  });

  it("selects contract and DApp sources, skipping dependencies and build output", () => {
    assert.ok(isScannableFile("contract/src/token.compact"));
    assert.ok(isScannableFile("api/src/index.ts"));
    assert.ok(!isScannableFile("api/src/index.ts", false));
    assert.ok(!isScannableFile("node_modules/x/a.compact"));
    assert.ok(!isScannableFile("contract/src/managed/token/contract/index.js"));
    assert.ok(!isScannableFile("api/dist/index.js"));
    assert.ok(!isScannableFile(".github/scripts/a.ts"));
    assert.ok(!isScannableFile("types/a.d.ts"));
    assert.ok(!isScannableFile("README.md"));
    assert.ok(!isScannableFile("api/src/index.test.ts"));
    assert.ok(!isScannableFile("test/helpers.ts"));
  });

  it("keeps DApp code and leaves unrelated TypeScript out", () => {
    assert.ok(usesMidnightSdk('import { WalletBuilder } from "@midnight-ntwrk/wallet";'));
    assert.ok(usesMidnightSdk(readFileSync("examples/dapp/vulnerable.ts", "utf8")));
    assert.ok(usesMidnightSdk(readFileSync("examples/dapp/safe.ts", "utf8")));
    assert.ok(!usesMidnightSdk(readFileSync("src/lexer.ts", "utf8")));
    assert.ok(!usesMidnightSdk(readFileSync("scripts/run-tests.mjs", "utf8")));
  });

  it("resolves imports between files in memory, like the CLI does on disk", () => {
    const files = new Map([
      ["contracts/main.compact", readFileSync("test/fixtures/imports/main.compact", "utf8")],
      ["contracts/lib/Auth.compact", readFileSync("test/fixtures/imports/lib/Auth.compact", "utf8")],
    ]);
    const inMemory = lintFileMap(files).filter((f) => f.file === "contracts/main.compact");
    const onDisk = lintFiles(["test/fixtures/imports/main.compact"]);
    assert.ok(inMemory.length > 0);
    assert.deepEqual(
      inMemory.map((f) => [f.ruleId, f.line]),
      onDisk.map((f) => [f.ruleId, f.line]),
    );
  });

  it("sorts findings by severity, then file and line", () => {
    const files = new Map([
      ["b.compact", readFileSync("examples/vulnerable.compact", "utf8")],
      ["a.ts", readFileSync("examples/dapp/vulnerable.ts", "utf8")],
    ]);
    const order = ["critical", "high", "medium", "low", "info"];
    const out = lintFileMap(files);
    for (let i = 1; i < out.length; i++) assert.ok(order.indexOf(out[i - 1].severity) <= order.indexOf(out[i].severity));
    assert.ok(out.some((f) => f.file === "a.ts") && out.some((f) => f.file === "b.compact"));
  });
});
