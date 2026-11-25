// Structural checks on the syntax tree, for bugs that do not need full data
// flow: MS012 (transient hash in state), MS013 (assert on a witness the
// prover chooses) and MS014 (commitment randomness made public).

import type { RawFinding } from "./analyzer.js";
import { isSecretName } from "./analyzer.js";
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
  // helper circuits that only pass a Boolean witness through: circuit check(): Boolean { return isAdmin(); }
  const helpers = (ds: Decl[]) => {
    for (const d of ds) {
      if (d.kind === "module") helpers(d.decls);
      if (d.kind !== "circuit" || d.returnType?.name !== "Boolean" || !d.body || d.body.length !== 1) continue;
      const r = d.body[0];
      if (r.kind === "return" && r.value && isCallTo(unwrap(r.value), bools)) bools.add(d.name);
    }
  };
  helpers(program.decls);
  if (!bools.size) return [];
  const out: RawFinding[] = [];
  const allWitnesses = new Set<string>();
  const ledgerFields = new Set<string>();
  const gather = (ds: Decl[]) => {
    for (const d of ds) {
      if (d.kind === "module") gather(d.decls);
      if (d.kind === "witness") allWitnesses.add(d.name);
      if (d.kind === "ledger") ledgerFields.add(d.name);
    }
  };
  gather(program.decls);
  // helper circuits that hash: circuit adminKey(sk) { return persistentHash(…) }
  const hashers = new Set(HASHING);
  for (const b of bodies(program.decls)) if ([...stmts(b.body)].some((st) => [...stmtExprs(st)].some((e) => isCallTo(e, HASHING)))) hashers.add(b.name);
  // assert(persistentHash(secret) == attesterCommit): the caller has proved who it is, so a Boolean
  // witness checked afterwards is that party's own statement (the attester saying delivery happened)
  const authenticatesIn = (body: Stmt[]) => {
    const secretLocals = taintedLocals(body, (e) => [...exprs(e)].some((x) => isCallTo(x, allWitnesses)));
    return (e: Expr): boolean => {
      const x = unwrap(e);
      if (x.kind !== "binary" || x.op !== "==") return false;
      const proves = (side: Expr) =>
        [...exprs(side)].some((y) => isCallTo(y, hashers)) && [...exprs(side)].some((y) => isCallTo(y, allWitnesses) || (y.kind === "ident" && secretLocals.has(y.name)));
      // the other side must be stored state: a parameter is chosen by the same prover
      const stored = (side: Expr) => {
        const y = unwrap(side);
        return y.kind === "ident" && ledgerFields.has(y.name);
      };
      return (proves(x.left) && stored(x.right)) || (proves(x.right) && stored(x.left));
    };
  };
  // helpers like requireAdmin() whose first-level body makes that check
  const authHelpers = new Set<string>();
  for (const b of bodies(program.decls)) {
    const auth = authenticatesIn(b.body);
    if (b.body.some((st) => st.kind !== "if" && st.kind !== "for" && [...stmtExprs(st)].some((e) => callee(e) === "assert" && e.kind === "call" && !!e.args[0] && auth(e.args[0])))) authHelpers.add(b.name);
  }
  for (const b of bodies(program.decls)) {
    const fromWitness = taintedLocals(b.body, (e) => isCallTo(unwrap(e), bools));
    const authenticates = authenticatesIn(b.body);
    let authenticated = false;
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
      // if (disclose(isAdmin())) { … }: the same check written as a branch
      if (s.kind === "if") {
        const w = isWitnessBool(s.test);
        // (kept after a caller check too: the branch is still the prover's choice, see core-ms013-if-after-check)
        if (w) {
          out.push({
            ruleId: "MS013",
            severity: "high",
            confidence: "high",
            loc: s.loc,
            message: `This if decides on '${w}', a value the prover supplies through a witness. The prover can return whatever takes the branch it wants, so the condition controls nothing. Decide on something the contract trusts instead: a value stored in the ledger, a hash of a secret, or a Merkle proof.`,
          });
        }
      }
      const unconditional = b.body.includes(s) && s.kind !== "if" && s.kind !== "for";
      if (unconditional && [...stmtExprs(s)].some((e) => e.kind === "call" && isCallTo(e, authHelpers))) authenticated = true;
      for (const e of stmtExprs(s)) {
        if (callee(e) !== "assert" || e.kind !== "call" || !e.args[0]) continue;
        // only an unconditional check counts: one inside an if may not run
        if (unconditional && authenticates(e.args[0])) authenticated = true;
        const w = isWitnessBool(e.args[0]);
        if (!w || authenticated) continue;
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
const HASHING = new Set(["persistentCommit", "transientCommit", "persistentHash", "transientHash"]);

/** disclose() calls that sit inside a hash or commitment argument: their value is not made public as is. */
function hashedDiscloses(es: Expr[]): Set<Expr> {
  const out = new Set<Expr>();
  for (const e of es) {
    if (!isCallTo(e, HASHING) || e.kind !== "call") continue;
    for (const a of e.args) for (const x of exprs(a)) if (callee(x) === "disclose") out.add(x);
  }
  return out;
}

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
  // a secret key used as randomness is MS023, and disclosing it is MS007
  for (const w of [...randWitnesses]) if (isSecretName(w) && !/rand|salt|nonce|blind|entropy/i.test(w)) randWitnesses.delete(w);
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
      const inside = hashedDiscloses([...stmtExprs(s)]);
      for (const e of stmtExprs(s)) {
        if (callee(e) !== "disclose" || e.kind !== "call" || !e.args[0] || inside.has(e)) continue;
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

/** MS014 (parameters): a circuit parameter is the randomness of a commitment and is also disclosed in the same circuit. */
function paramRandomnessDisclosed(program: Program): RawFinding[] {
  const out: RawFinding[] = [];
  const circuits: Extract<Decl, { kind: "circuit" }>[] = [];
  const walkC = (ds: Decl[]) => ds.forEach((d) => (d.kind === "circuit" && d.body ? circuits.push(d) : d.kind === "module" ? walkC(d.decls) : undefined));
  walkC(program.decls);
  const witnessTypes = new Map<string, string>();
  const walkW = (ds: Decl[]) => ds.forEach((d) => (d.kind === "witness" ? witnessTypes.set(d.name, d.returnType?.text ?? "") : d.kind === "module" ? walkW(d.decls) : undefined));
  walkW(program.decls);
  for (const c of circuits) {
    const params = new Set(c.params.map((p) => p.name));
    const rand = new Set<string>();
    const all = [...stmts(c.body!)].flatMap((s) => [...stmtExprs(s)]);
    // persistentCommit(ownerSecret(), key): the committed value is 32 secret bytes from a witness, so
    // knowing the randomness does not let anyone guess it; the commitment works as a keyed binding
    const keyedBinding = (e: Extract<Expr, { kind: "call" }>) => {
      const v = unwrap(e.args[0]);
      return v.kind === "call" && v.callee.kind === "ident" && isSecretName(v.callee.name) && /^Bytes<\s*32\s*>$/.test((witnessTypes.get(v.callee.name) ?? "").replace(/\s/g, ""));
    };
    const keyedOnly = new Set<string>();
    const notKeyed = new Set<string>();
    for (const e of all) {
      if (!isCallTo(e, COMMIT) || e.kind !== "call" || e.args.length < 2) continue;
      const r = unwrap(e.args[e.args.length - 1]);
      if (r.kind === "ident" && params.has(r.name)) {
        rand.add(r.name);
        (keyedBinding(e) ? keyedOnly : notKeyed).add(r.name);
      }
    }
    for (const r of keyedOnly) if (!notKeyed.has(r)) rand.delete(r);
    if (!rand.size) continue;
    // disclose(p) on its own, not the commitment that contains p
    if (all.some((e) => callee(e) === "assert" && e.kind === "call" && !!e.args[0] && [...exprs(e.args[0])].some((x) => isCallTo(x, COMMIT)))) continue;
    const inside = hashedDiscloses(all);
    for (const e of all) {
      if (callee(e) !== "disclose" || e.kind !== "call" || !e.args[0] || inside.has(e)) continue;
      const x = unwrap(e.args[0]);
      if (x.kind !== "ident" || !rand.has(x.name)) continue;
      out.push({
        ruleId: "MS014",
        severity: "high",
        confidence: "medium",
        loc: e.loc,
        message: `'${x.name}' is the randomness of a commitment in '${c.name}', and here it is made public as well. With the randomness, anyone can open the commitment by trying candidate values. Keep commitment randomness private (a witness is the usual source).`,
      });
    }
  }
  return out;
}

export function checkStructural(program: Program): RawFinding[] {
  const ctx: Ctx = { ledger: new Set(), witnesses: new Set(), circuits: new Map(), enums: new Set() };
  collect(program.decls, ctx);
  return [...transientInState(program, ctx), ...witnessControlledAssert(program), ...randomnessDisclosed(program, ctx), ...paramRandomnessDisclosed(program)];
}
