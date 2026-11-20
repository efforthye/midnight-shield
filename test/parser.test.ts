import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Decl, Expr, Stmt } from "../src/ast.js";
import { parse } from "../src/parser.js";

function circuitBody(src: string): Stmt[] {
  const p = parse(src);
  assert.deepEqual(p.diagnostics, []);
  const c = p.decls.find((d): d is Extract<Decl, { kind: "circuit" }> => d.kind === "circuit");
  assert.ok(c?.body);
  return c.body;
}

function firstExpr(src: string): Expr {
  const body = circuitBody(`circuit f(): [] { ${src} }`);
  const s = body[0];
  if (s.kind === "expr") return s.expr;
  if (s.kind === "const") return s.init;
  throw new Error(`unexpected statement ${s.kind}`);
}

describe("parser: declarations", () => {
  it("reads pragma, ledger, witness, circuit, constructor, struct, enum and type alias", () => {
    const p = parse(`
      pragma language_version >= 0.28.0;
      import CompactStandardLibrary;
      export enum Phase { A, B }
      export struct P { x: Field, y: Uint<8> }
      export new type Key = Bytes<32>;
      export sealed ledger owner: Bytes<32>;
      witness sk(): Bytes<32>;
      constructor(k: Bytes<32>) { owner = disclose(k); }
      export pure circuit id(x: Field): Field { return x; }
    `);
    assert.deepEqual(p.diagnostics, []);
    assert.deepEqual(
      p.decls.map((d) => d.kind),
      ["pragma", "import", "enum", "struct", "typeAlias", "ledger", "witness", "constructor", "circuit"],
    );
    const ledger = p.decls.find((d) => d.kind === "ledger") as Extract<Decl, { kind: "ledger" }>;
    assert.equal(ledger.sealed, true);
    assert.equal(ledger.exported, true);
    const circuit = p.decls.find((d) => d.kind === "circuit") as Extract<Decl, { kind: "circuit" }>;
    assert.equal(circuit.pure, true);
  });

  it("reads path imports with a prefix and selective imports", () => {
    const p = parse(`
      import "../utils/Utils" prefix Utils_;
      import "../Token"<32> prefix T_;
      import { a, b } from "./M" prefix M_;
      include "std";
    `);
    assert.deepEqual(p.diagnostics, []);
    const imports = p.decls.filter((d): d is Extract<Decl, { kind: "import" }> => d.kind === "import");
    assert.deepEqual(
      imports.map((d) => [d.target, d.prefix, d.isPath]),
      [
        ["../utils/Utils", "Utils_", true],
        ["../Token", "T_", true],
        ["./M", "M_", true],
      ],
    );
    assert.equal(p.decls.at(-1)?.kind, "include");
  });

  it("reads declarations nested in a module", () => {
    const p = parse(`module M { export ledger x: Field; export circuit f(): [] {} }`);
    assert.deepEqual(p.diagnostics, []);
    const m = p.decls[0] as Extract<Decl, { kind: "module" }>;
    assert.deepEqual(m.decls.map((d) => d.kind), ["ledger", "circuit"]);
  });
});

describe("parser: expressions", () => {
  it("tells generic calls apart from comparisons", () => {
    const call = firstExpr("persistentHash<Vector<2, Bytes<32>>>(x);");
    assert.equal(call.kind, "call");
    assert.equal(call.kind === "call" && call.typeArgs?.length, 1);

    const cmp = firstExpr("a < b;");
    assert.equal(cmp.kind, "binary");
    assert.equal(cmp.kind === "binary" && cmp.op, "<");
  });

  it("reads `>=` written as two tokens", () => {
    const e = firstExpr("a >= b;");
    assert.equal(e.kind === "binary" && e.op, ">=");
  });

  it("reads default<T> as a value", () => {
    const e = firstExpr("x == default<Bytes<32>> || y;");
    assert.equal(e.kind === "binary" && e.op, "||");
  });

  it("tells lambdas apart from parenthesized conditional branches", () => {
    const lambda = firstExpr("fold((acc, x: Uint<8>): Uint<8> => acc + x, 0, v);");
    assert.equal(lambda.kind === "call" && lambda.args[0].kind, "lambda");

    const cond = firstExpr("const r = c ? (a) : b;");
    assert.equal(cond.kind, "cond");
  });

  it("reads struct literals, including generic ones", () => {
    const e = firstExpr("Either<A, B> { is_left: true, left: x, right: y };");
    assert.equal(e.kind, "struct");
    assert.equal(e.kind === "struct" && e.fields.length, 3);
  });

  it("does not treat `if (x) {` as a struct literal", () => {
    const body = circuitBody("circuit f(): [] { if (Flag) { g(); } }");
    assert.equal(body[0].kind, "if");
  });

  it("reads casts, member access, indexing and ranges", () => {
    assert.equal(firstExpr("(a + b) as Uint<64>;").kind, "cast");
    assert.equal(firstExpr("kernel.self().bytes;").kind, "member");
    assert.equal(firstExpr("rs[0];").kind, "index");
    const body = circuitBody("circuit f(): [] { for (const i of 0..4) { g(i); } }");
    assert.equal(body[0].kind, "for");
  });

  it("locates postfix expressions at their start", () => {
    const e = firstExpr("ownPublicKey().bytes;");
    assert.deepEqual(e.loc, { line: 1, col: 19 });
  });
});

describe("parser: statements", () => {
  it("reads const with destructuring and type annotation", () => {
    const body = circuitBody("circuit f(): [] { const [a, b] = g(); const c: Field = 1; }");
    assert.deepEqual(body.map((s) => s.kind), ["const", "const"]);
    assert.deepEqual(body[0].kind === "const" && body[0].names, ["a", "b"]);
  });

  it("reads assignments with compound operators", () => {
    const body = circuitBody("circuit f(): [] { x = 1; y += 2; z -= 3; }");
    assert.deepEqual(body.map((s) => s.kind === "assign" && s.op), ["=", "+=", "-="]);
  });

  it("reads if / else chains and returns", () => {
    const body = circuitBody("circuit f(): Field { if (a) { return 1; } else if (b) { return 2; } else { return 3; } }");
    assert.equal(body[0].kind, "if");
  });
});

describe("parser: error recovery", () => {
  it("reports a diagnostic and keeps parsing the rest of the file", () => {
    const p = parse(`
      export circuit broken(): [] { const = ; }
      export circuit fine(): [] { g(); }
    `);
    assert.ok(p.diagnostics.length >= 1);
    const names = p.decls.filter((d) => d.kind === "circuit").map((d) => (d as { name: string }).name);
    assert.deepEqual(names, ["broken", "fine"]);
  });

  it("skips unknown top-level syntax without stopping", () => {
    const p = parse(`@@@ weird; export ledger x: Field;`);
    assert.ok(p.diagnostics.length >= 1);
    assert.ok(p.decls.some((d) => d.kind === "ledger"));
  });
});
