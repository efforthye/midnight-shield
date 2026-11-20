// Fuzz tests: the parser and analyzer must never throw, whatever the input.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { lex } from "../src/lexer.js";
import { lintSource } from "../src/linter.js";

/** Small deterministic PRNG so failures are reproducible. */
function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

const SEEDS = ["examples/vulnerable.compact", "examples/safe.compact", "test/fixtures/imports/main.compact"].map((f) => readFileSync(f, "utf8"));

describe("robustness", () => {
  it("survives random token deletions, duplications and swaps", () => {
    const rand = rng(42);
    for (let i = 0; i < 400; i++) {
      const src = SEEDS[i % SEEDS.length];
      const tokens = lex(src).tokens.filter((t) => t.kind !== "eof").map((t) => t.value);
      const edits = 1 + Math.floor(rand() * 6);
      for (let k = 0; k < edits; k++) {
        const j = Math.floor(rand() * tokens.length);
        const op = rand();
        if (op < 0.4) tokens.splice(j, 1);
        else if (op < 0.7) tokens.splice(j, 0, tokens[Math.floor(rand() * tokens.length)]);
        else [tokens[j], tokens[(j + 1) % tokens.length]] = [tokens[(j + 1) % tokens.length], tokens[j]];
      }
      const mutated = tokens.join(" ");
      assert.doesNotThrow(() => lintSource(mutated), `iteration ${i}`);
    }
  });

  it("survives truncation at every position of a real contract", () => {
    const src = SEEDS[0];
    for (let n = 0; n < src.length; n += 7) {
      assert.doesNotThrow(() => lintSource(src.slice(0, n)), `length ${n}`);
    }
  });

  it("survives random bytes", () => {
    const rand = rng(7);
    const alphabet = "abcXYZ019_<>(){}[];:,.=!&|?+-*/\"' \n\tcircuit witness ledger assert disclose";
    for (let i = 0; i < 200; i++) {
      let s = "";
      const len = Math.floor(rand() * 400);
      for (let k = 0; k < len; k++) s += alphabet[Math.floor(rand() * alphabet.length)];
      assert.doesNotThrow(() => lintSource(s), `iteration ${i}`);
    }
  });

  it("handles deeply nested expressions without stack overflow", () => {
    const deep = "(".repeat(500) + "x" + ")".repeat(500);
    assert.doesNotThrow(() => lintSource(`export circuit f(): [] { const a = ${deep}; }`));
  });

  it("analyzes recursive circuits without looping forever", () => {
    const src = `
      circuit a(x: Field): Field { return b(x); }
      circuit b(x: Field): Field { return a(x); }
      export circuit f(x: Field): Field { return a(x); }`;
    assert.doesNotThrow(() => lintSource(src));
  });
});
