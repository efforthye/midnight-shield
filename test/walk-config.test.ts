import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ConfigError, validateConfig } from "../src/config.js";
import { parse } from "../src/parser.js";
import { calleeName, walkProgram } from "../src/walk.js";

describe("AST walker (plugin API)", () => {
  const program = parse(`
    module M {
      export ledger total: Counter;
      witness sk(): Bytes<32>;
      constructor() { total.increment(1); }
      export circuit f(xs: Vector<3, Uint<8>>, p: P): Uint<8> {
        const [a, b] = g();
        let_ = 1;
        if (a > b) { assert(xs[0] == 1, "x"); } else { total.increment(2); }
        for (const i of 0..3) { h(i); }
        const s = P { x: p.x, ...p };
        const v = [-a, !b, (a + b) as Uint<8>, ...xs];
        const c = a ? b : 0;
        const l = fold((acc, x: Uint<8>): Uint<8> => acc + x, 0, xs);
        { return c; }
      }
    }`);

  it("visits every circuit, statement kind and expression kind", () => {
    const circuits: string[] = [];
    const stmts = new Set<string>();
    const exprs = new Set<string>();
    const calls: string[] = [];
    const inAssert: string[] = [];
    walkProgram(program, {
      circuit: (_d, ctx) => circuits.push(`${ctx.circuit}:${ctx.exported}`),
      statement: (s) => stmts.add(s.kind),
      expression: (e, ctx) => {
        exprs.add(e.kind);
        if (ctx.inAssert && e.kind === "index") inAssert.push("index");
      },
      call: (_e, callee) => calls.push(callee),
    });
    assert.deepEqual(circuits, ["constructor:false", "f:true"]);
    for (const k of ["const", "assign", "if", "for", "return", "expr", "block"]) assert.ok(stmts.has(k), k);
    for (const k of ["ident", "number", "string", "call", "member", "index", "vector", "struct", "binary", "unary", "cast", "cond", "lambda", "spread"]) assert.ok(exprs.has(k), k);
    assert.ok(calls.includes("total.increment"));
    assert.ok(calls.includes("assert"));
    assert.deepEqual(inAssert, ["index"]);
  });

  it("names callees, including member calls", () => {
    const p = parse("circuit f(): [] { a.b.c(); }");
    let name = "";
    walkProgram(p, { call: (_e, c) => (name = c) });
    assert.equal(name, "a.b.c");
    assert.equal(calleeName({ kind: "number", value: "1", loc: { line: 1, col: 1 } }), "");
  });
});

describe("config validation", () => {
  it("accepts every documented key", () => {
    const c = validateConfig({ disable: ["MS005", "ACME001"], failOn: "none", minSeverity: "low", minConfidence: "medium", ignore: ["x/**"], baseline: "b.json", plugins: ["p.mjs"], sdk: false, $schema: "s" });
    assert.equal(c.minConfidence, "medium");
    assert.equal(c.sdk, false);
    assert.deepEqual(c.plugins, ["p.mjs"]);
  });

  it("rejects wrong types with a clear message", () => {
    const bad: [unknown, RegExp][] = [
      [[], /JSON object/],
      [{ disable: "MS005" }, /disable/],
      [{ minSeverity: "big" }, /minSeverity/],
      [{ minConfidence: "sure" }, /minConfidence/],
      [{ ignore: [1] }, /ignore/],
      [{ baseline: 1 }, /baseline/],
      [{ plugins: "x" }, /plugins/],
      [{ sdk: "yes" }, /sdk/],
    ];
    for (const [raw, msg] of bad) assert.throws(() => validateConfig(raw), (e: Error) => e instanceof ConfigError && msg.test(e.message));
  });
});
