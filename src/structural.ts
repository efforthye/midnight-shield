// Structural checks on the syntax tree, for bugs that do not need full data
// flow: MS012 (transient hash in state), MS013 (assert on a witness the
// prover chooses) and MS014 (commitment randomness made public).

import type { RawFinding } from "./analyzer.js";
import type { Decl, Expr, Program, Stmt } from "./ast.js";
import { collect, exprs, stmtExprs, stmts, type Ctx } from "./auth-writes.js";

type Body = { name: string; body: Stmt[] };

function bodies(decls: Decl[], out: Body[] = []): Body[] {
  for (const d of decls) {
    if (d.kind === "circuit" && d.body) out.push({ name: d.name, body: d.body });
    else if (d.kind === "constructor") out.push({ name: "constructor", body: d.body });
    else if (d.kind === "module") bodies(d.decls, out);
  }
  return out;
}

function booleanWitnesses(decls: Decl[], out = new Set<string>()): Set<string> {
  for (const d of decls) {
    if (d.kind === "witness" && d.returnType?.name === "Boolean") out.add(d.name);
    else if (d.kind === "module") booleanWitnesses(d.decls, out);
  }
  return out;
}

const callee = (e: Expr): string => (e.kind === "call" && e.callee.kind === "ident" ? e.callee.name : "");
const isCallTo = (e: Expr, names: Set<string>) => e.kind === "call" && e.callee.kind === "ident" && names.has(e.callee.name);

/** Remove wrappers that do not change what a value is: disclose(x), casts, parentheses-free unary !. */
function unwrap(e: Expr): Expr {
  if (e.kind === "call" && callee(e) === "disclose" && e.args[0]) return unwrap(e.args[0]);
  if (e.kind === "cast") return unwrap(e.expr);
  return e;
}

/** Ledger writes in a statement list: assignments to a field, and write/insert/push-like calls on one. */
function* ledgerWrites(body: Stmt[], ctx: Ctx): Generator<{ field: string; value: Expr[]; loc: Stmt["loc"] }> {
  const WRITE = new Set(["write", "insert", "insertDefault", "push", "pushFront", "resetToDefault", "insertCoin"]);
  for (const s of stmts(body)) {
    if (s.kind === "assign" && s.target.kind === "ident" && ctx.ledger.has(s.target.name)) {
      yield { field: s.target.name, value: [s.value], loc: s.loc };
    }
    for (const e of stmtExprs(s)) {
      if (e.kind === "call" && e.callee.kind === "member" && e.callee.object.kind === "ident" && ctx.ledger.has(e.callee.object.name) && WRITE.has(e.callee.property)) {
        yield { field: e.callee.object.name, value: e.args, loc: e.loc };
      }
    }
  }
}

/** Local constants whose value comes from an expression matching `pred` (transitively through other constants). */
function taintedLocals(body: Stmt[], pred: (e: Expr, tainted: Set<string>) => boolean): Set<string> {
  const tainted = new Set<string>();
  for (const s of stmts(body)) {
    if (s.kind === "const" && pred(s.init, tainted)) for (const n of s.names) tainted.add(n);
  }
  return tainted;
}

const TRANSIENT = new Set(["transientHash", "transientCommit"]);

/** MS012: a transientHash/transientCommit result stored in the ledger. */
function transientInState(program: Program, ctx: Ctx): RawFinding[] {
  const out: RawFinding[] = [];
  const usesTransient = (e: Expr, tainted: Set<string>) => {
    for (const x of exprs(e)) {
      if (isCallTo(x, TRANSIENT)) return true;
      if (x.kind === "ident" && tainted.has(x.name)) return true;
    }
    return false;
  };
  for (const b of bodies(program.decls)) {
    const tainted = taintedLocals(b.body, usesTransient);
    for (const w of ledgerWrites(b.body, ctx)) {
      if (!w.value.some((v) => usesTransient(v, tainted))) continue;
      out.push({
        ruleId: "MS012",
        severity: "medium",
        confidence: "high",
        loc: w.loc,
        message: `A transientHash/transientCommit result is stored in the ledger field '${w.field}'. Midnight does not guarantee that transient hashes stay the same across upgrades, so stored values may stop matching after one. Use persistentHash or persistentCommit for anything kept in state; transient ones are for in-circuit consistency checks.`,
      });
    }
  }
  return out;
}

/** MS013: assert(w()) where w is a Boolean witness. The prover chooses the witness value, so the check proves nothing. */
function witnessControlledAssert(program: Program): RawFinding[] {
  const bools = booleanWitnesses(program.decls);
  if (!bools.size) return [];
  const out: RawFinding[] = [];
  for (const b of bodies(program.decls)) {
    const fromWitness = taintedLocals(b.body, (e) => isCallTo(unwrap(e), bools));
    const isWitnessBool = (e: Expr): string | undefined => {
      const x = unwrap(e);
      if (isCallTo(x, bools)) return callee(x);
      if (x.kind === "ident" && fromWitness.has(x.name)) return x.name;
      if (x.kind === "unary" && x.op === "!") return isWitnessBool(x.arg);
      if (x.kind === "binary" && (x.op === "==" || x.op === "!=")) {
        const lit = (y: Expr) => y.kind === "ident" && (y.name === "true" || y.name === "false");
        if (lit(x.right)) return isWitnessBool(x.left);
        if (lit(x.left)) return isWitnessBool(x.right);
      }
      if (x.kind === "binary" && (x.op === "&&" || x.op === "||")) {
        // only when every part is prover-chosen
        const l = isWitnessBool(x.left);
        const r = isWitnessBool(x.right);
        return l && r ? l : undefined;
      }
      return undefined;
    };
    for (const s of stmts(b.body)) {
      for (const e of stmtExprs(s)) {
        if (callee(e) !== "assert" || e.kind !== "call" || !e.args[0]) continue;
        const w = isWitnessBool(e.args[0]);
        if (!w) continue;
        out.push({
          ruleId: "MS013",
          severity: "high",
          confidence: "high",
          loc: e.loc,
          message: `This assert only checks '${w}', a value the prover supplies through a witness. The prover can return whatever passes, so the assert does not enforce anything. Check it against something the contract trusts instead: a value stored in the ledger, a hash of a secret, or a Merkle proof.`,
        });
      }
    }
  }
  return out;
}

const COMMIT = new Set(["persistentCommit", "transientCommit"]);

/** MS014: the randomness of a commitment is also made public, which lets anyone open the commitment. */
function randomnessDisclosed(program: Program, ctx: Ctx): RawFinding[] {
  const out: RawFinding[] = [];
  // witnesses used as commitment randomness anywhere in the file
  const randWitnesses = new Set<string>();
  for (const b of bodies(program.decls)) {
    const fromWitness = new Map<string, string>();
    for (const s of stmts(b.body)) {
      if (s.kind === "const" && s.names.length === 1) {
        const x = unwrap(s.init);
        if (x.kind === "call" && x.callee.kind === "ident" && ctx.witnesses.has(x.callee.name)) fromWitness.set(s.names[0], x.callee.name);
      }
      for (const e of stmtExprs(s)) {
        if (!isCallTo(e, COMMIT) || e.kind !== "call" || e.args.length < 2) continue;
        const r = unwrap(e.args[e.args.length - 1]);
        if (r.kind === "call" && r.callee.kind === "ident" && ctx.witnesses.has(r.callee.name)) randWitnesses.add(r.callee.name);
        if (r.kind === "ident" && fromWitness.has(r.name)) randWitnesses.add(fromWitness.get(r.name)!);
      }
    }
  }
  if (!randWitnesses.size) return out;
  for (const b of bodies(program.decls)) {
    // a circuit that checks a commitment in an assert is opening it on purpose (commit-reveal)
    const opens = [...stmts(b.body)].some((s) =>
      [...stmtExprs(s)].some((e) => callee(e) === "assert" && e.kind === "call" && !!e.args[0] && [...exprs(e.args[0])].some((x) => isCallTo(x, COMMIT))),
    );
    if (opens) continue;
    const locals = new Map<string, string>();
    for (const s of stmts(b.body)) {
      if (s.kind === "const" && s.names.length === 1) {
        const x = unwrap(s.init);
        if (x.kind === "call" && x.callee.kind === "ident" && randWitnesses.has(x.callee.name)) locals.set(s.names[0], x.callee.name);
      }
      for (const e of stmtExprs(s)) {
        if (callee(e) !== "disclose" || e.kind !== "call" || !e.args[0]) continue;
        const x = unwrap(e.args[0]);
        const w = x.kind === "call" && x.callee.kind === "ident" && randWitnesses.has(x.callee.name) ? x.callee.name : x.kind === "ident" ? locals.get(x.name) : undefined;
        if (!w) continue;
        out.push({
          ruleId: "MS014",
          severity: "high",
          confidence: "medium",
          loc: e.loc,
          message: `'${w}()' is the randomness of a commitment, and here it is made public as is. With the randomness, anyone can open the commitment by trying candidate values, so it no longer hides anything. Keep commitment randomness private; reveal it only when you deliberately open the commitment.`,
        });
      }
    }
  }
  return out;
}

export function checkStructural(program: Program): RawFinding[] {
  const ctx: Ctx = { ledger: new Set(), witnesses: new Set(), circuits: new Map(), enums: new Set() };
  collect(program.decls, ctx);
  return [...transientInState(program, ctx), ...witnessControlledAssert(program), ...randomnessDisclosed(program, ctx)];
}
