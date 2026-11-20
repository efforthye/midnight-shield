import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { lex } from "../src/lexer.js";

const values = (src: string) => lex(src).tokens.map((t) => t.value).filter(Boolean);

describe("lexer", () => {
  it("splits identifiers, numbers, strings and punctuation", () => {
    assert.deepEqual(values('const x = pad(32, "a:b");'), ["const", "x", "=", "pad", "(", "32", ",", '"a:b"', ")", ";"]);
  });

  it("emits `>` one at a time so nested generics close", () => {
    assert.deepEqual(values("Vector<2, Bytes<32>>"), ["Vector", "<", "2", ",", "Bytes", "<", "32", ">", ">"]);
  });

  it("lexes ranges without swallowing the dots into numbers", () => {
    assert.deepEqual(values("0..10"), ["0", "..", "10"]);
  });

  it("keeps hex and underscored numbers whole", () => {
    assert.deepEqual(values("0xff 1_000"), ["0xff", "1_000"]);
  });

  it("collects line and block comments separately with their lines", () => {
    const { tokens, comments } = lex("a // one\n/* two\nthree */ b");
    assert.deepEqual(tokens.map((t) => t.value).filter(Boolean), ["a", "b"]);
    assert.equal(comments.length, 2);
    assert.equal(comments[0].line, 1);
    assert.equal(comments[1].line, 2);
    assert.equal(comments[1].endLine, 3);
  });

  it("tracks line and column of every token", () => {
    const { tokens } = lex("a\n  bb");
    assert.deepEqual([tokens[1].line, tokens[1].col], [2, 3]);
  });

  it("handles escaped quotes in strings", () => {
    assert.deepEqual(values('"a\\"b" c'), ['"a\\"b"', "c"]);
  });

  it("always ends with an eof token, even on empty input", () => {
    const { tokens } = lex("");
    assert.equal(tokens.length, 1);
    assert.equal(tokens[0].kind, "eof");
  });
});
