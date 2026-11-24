// More structural checks on Compact contracts:
//   MS015 unused-witness             a witness that nothing calls
//   MS016 unused-circuit             a non-exported circuit that nothing calls
//   MS017 tautological-assert        an assert that can never fail
//   MS018 nullifier-not-checked      a nullifier inserted without a membership check
//   MS019 unguarded-token-send       an exported circuit sends tokens and checks nothing
//   MS020 unguarded-mint             an exported circuit mints tokens and checks nothing
//   MS021 nullifier-matches-leaf     nullifier and Merkle leaf built from the same tag and inputs
//   MS022 shadowed-ledger-field      a parameter or local hides a ledger field of the same name
//   MS023 secret-key-as-randomness   a long-term secret key used as commitment randomness

import type { RawFinding } from "./analyzer.js";
import { isSecretName } from "./analyzer.js";
import type { Decl, Expr, Loc, Program, Stmt } from "./ast.js";
import { collect, exprs, reach, stmtExprs, stmts, type Ctx } from "./auth-writes.js";

type Circuit = Extract<Decl, { kind: "circuit" }>;

function walk(decls: Decl[], f: (d: Decl) => void): void {
  for (const d of decls) {
    f(d);
    if (d.kind === "module") walk(d.decls, f);
  }
}

function bodyOf(d: Decl): Stmt[] {
  if (d.kind === "circuit") return d.body ?? [];
  if (d.kind === "constructor") return d.body;
  return [];
}

function* allExprs(program: Program): Generator<Expr> {
  const out: Expr[] = [];
  walk(program.decls, (d) => {
    for (const s of stmts(bodyOf(d))) for (const e of stmtExprs(s)) out.push(e);
  });
  yield* out;
}

const calleeName = (e: Expr): string =>
  e.kind === "call" ? (e.callee.kind === "ident" ? e.callee.name : e.callee.kind === "member" ? e.callee.property : "") : "";

/** Called names, including names passed as values (map(helper, v), fold(helper, …)). */
function usedNames(program: Program): Set<string> {
  const used = new Set<string>();
  for (const e of allExprs(program)) {
    if (e.kind === "ident") used.add(e.name);
    if (e.kind === "call" && e.callee.kind === "ident") used.add(e.callee.name);
  }
  return used;
}

function unused(program: Program): RawFinding[] {
  // a file that includes others, or is included, shares declarations we cannot see
  if (program.decls.some((d) => d.kind === "include")) return [];
  const used = usedNames(program);
  const out: RawFinding[] = [];
  walk(program.decls, (d) => {
    if (d.kind === "witness" && !used.has(d.name)) {
      out.push({
        ruleId: "MS015",
        severity: "info",
        confidence: "high",
        loc: d.loc,
        message: `Witness '${d.name}' is declared but never used. Remove it, or check whether a circuit was meant to call it (a missing check is a common cause).`,
      });
    }
    if (d.kind === "circuit" && !d.exported && d.body && !used.has(d.name)) {
      out.push({
        ruleId: "MS016",
        severity: "info",
        confidence: "high",
        loc: d.loc,
        message: `Circuit '${d.name}' is not exported and never called, so it is dead code. Remove it, or check whether another circuit was meant to call it.`,
      });
    }
  });
  return out;
}

function sameExpr(a: Expr, b: Expr): boolean {
  return JSON.stringify(a, (k, v) => (k === "loc" ? undefined : v)) === JSON.stringify(b, (k, v) => (k === "loc" ? undefined : v));
}

const unwrapDisclose = (e: Expr): Expr => (e.kind === "call" && e.callee.kind === "ident" && e.callee.name === "disclose" && e.args[0] ? unwrapDisclose(e.args[0]) : e);

function tautology(e: Expr): string | undefined {
  const x = unwrapDisclose(e);
  if (x.kind === "ident" && x.name === "true") return "it is the constant true";
  if (x.kind === "binary") {
    if (["==", "<=", ">="].includes(x.op) && sameExpr(x.left, x.right)) return "both sides are the same expression";
    const zero = (y: Expr) => y.kind === "number" && Number(y.value) === 0;
    if (x.op === ">=" && zero(x.right)) return "unsigned values are never below 0";
    if (x.op === "<=" && zero(x.left)) return "unsigned values are never below 0";
    if (x.op === "||") return tautology(x.left) ?? tautology(x.right);
  }
  return undefined;
}

function tautologicalAsserts(program: Program): RawFinding[] {
  const out: RawFinding[] = [];
  for (const e of allExprs(program)) {
    if (e.kind !== "call" || calleeName(e) !== "assert" || e.callee.kind !== "ident" || !e.args[0]) continue;
    const why = tautology(e.args[0]);
    if (!why) continue;
    out.push({
      ruleId: "MS017",
      severity: "medium",
      confidence: "high",
      loc: e.loc,
      message: `This assert can never fail (${why}), so it checks nothing. It is probably a typo for a real check, for example comparing with a ledger value or a parameter.`,
    });
  }
  return out;
}

const NULLIFIER_SET = /(nullif|spent|used|claimed|voted|consumed|redeemed)/i;

/** Ledger Set fields with a nullifier-like name. */
function nullifierSets(program: Program): Set<string> {
  const out = new Set<string>();
  walk(program.decls, (d) => {
    if (d.kind === "ledger" && d.type.name === "Set" && NULLIFIER_SET.test(d.name)) out.add(d.name);
  });
  return out;
}

/** Calls of a given shape reachable from a circuit through helpers in the same file. */
function reachableCalls(c: Circuit, ctx: Ctx, pred: (e: Expr) => boolean, seen = new Set<string>()): Extract<Expr, { kind: "call" }>[] {
  if (seen.has(c.name)) return [];
  seen.add(c.name);
  const out: Extract<Expr, { kind: "call" }>[] = [];
  for (const s of stmts(c.body ?? [])) {
    for (const e of stmtExprs(s)) {
      if (e.kind !== "call") continue;
      if (pred(e)) out.push(e);
      if (e.callee.kind === "ident" && ctx.circuits.has(e.callee.name)) out.push(...reachableCalls(ctx.circuits.get(e.callee.name)!, ctx, pred, seen));
    }
  }
  return out;
}

const onLedger = (e: Expr, sets: Set<string>, method: string) =>
  e.kind === "call" && e.callee.kind === "member" && e.callee.property === method && e.callee.object.kind === "ident" && sets.has(e.callee.object.name);

function nullifierNotChecked(program: Program, ctx: Ctx): RawFinding[] {
  const out: RawFinding[] = [];
  // the other half: assert(!set.member(n)) with no insert, so the check passes every time
  const allSets = new Set<string>();
  // only nullifier-like names: a deny-list check (assert(!blacklist.member(id))) is not meant to record anything
  walk(program.decls, (d) => {
    if (d.kind === "ledger" && d.type.name === "Set" && NULLIFIER_SET.test(d.name)) allSets.add(d.name);
  });
  for (const c of ctx.circuits.values()) {
    if (!c.exported || !c.body || !allSets.size) continue;
    const negChecks: { set: string; loc: Loc }[] = [];
    for (const e of reachableCalls(c, ctx, (x) => x.kind === "call" && x.callee.kind === "ident" && x.callee.name === "assert")) {
      const cond = e.args[0] ? unwrapDisclose(e.args[0]) : undefined;
      if (cond?.kind !== "unary" || cond.op !== "!") continue;
      const m = unwrapDisclose(cond.arg);
      if (onLedger(m, allSets, "member")) negChecks.push({ set: ((m as Extract<Expr, { kind: "call" }>).callee as Extract<Expr, { kind: "member" }>).object.kind === "ident" ? (((m as Extract<Expr, { kind: "call" }>).callee as Extract<Expr, { kind: "member" }>).object as { name: string }).name : "", loc: e.loc });
    }
    if (!negChecks.length) continue;
    const inserted = new Set(reachableCalls(c, ctx, (e) => onLedger(e, allSets, "insert")).map((e) => ((e.callee as Extract<Expr, { kind: "member" }>).object as { name: string }).name));
    for (const n of negChecks) {
      if (inserted.has(n.set)) continue;
      out.push({
        ruleId: "MS018",
        severity: "high",
        confidence: "medium",
        loc: n.loc,
        message: `'${c.name}' checks that the value is not in '${n.set}' but never adds it, so the check passes every time and the same nullifier can be used again (a double spend or a second vote). Add ${n.set}.insert(…) after the check.`,
      });
    }
  }
  // by role, whatever the name: a Set that receives values derived from the caller's secret,
  // which no circuit ever checks. Without a check it cannot stop anything from happening twice.
  const allSetNames = new Set<string>();
  walk(program.decls, (d) => {
    if (d.kind === "ledger" && d.type.name === "Set" && !NULLIFIER_SET.test(d.name)) allSetNames.add(d.name);
  });
  const checkedAnywhere = new Set<string>();
  for (const e of allExprs(program)) {
    if (e.kind === "call" && e.callee.kind === "member" && e.callee.property === "member" && e.callee.object.kind === "ident") checkedAnywhere.add(e.callee.object.name);
  }
  const unchecked = new Set([...allSetNames].filter((n) => !checkedAnywhere.has(n)));
  if (unchecked.size) {
    for (const c of ctx.circuits.values()) {
      if (!c.exported || !c.body) continue;
      for (const ins of reachableCalls(c, ctx, (e) => onLedger(e, unchecked, "insert"))) {
        const set = ((ins.callee as Extract<Expr, { kind: "member" }>).object as { name: string }).name;
        const v = ins.args[0];
        const secretDerived = v && [...exprs(v)].some((x) => x.kind === "call" && x.callee.kind === "ident" && /Hash$/.test(x.callee.name)) && [...exprs(v)].some((x) => x.kind === "call" && x.callee.kind === "ident" && ctx.witnesses.has(x.callee.name));
        if (!secretDerived) continue;
        out.push({
          ruleId: "MS018",
          severity: "medium",
          confidence: "low",
          loc: ins.loc,
          message: `'${c.name}' adds a hash of the caller's secret to '${set}', and no circuit ever checks membership in '${set}'. If it is meant to stop the same caller from acting twice (a nullifier), it does not: add assert(!${set}.member(…), "already used") before the insert.`,
        });
      }
    }
  }
  const sets = nullifierSets(program);
  if (!sets.size) return out;
  const reported = new Set<string>();
  for (const c of ctx.circuits.values()) {
    if (!c.exported || !c.body) continue;
    const inserts = reachableCalls(c, ctx, (e) => onLedger(e, sets, "insert"));
    if (!inserts.length) continue;
    const checked = new Set(
      reachableCalls(c, ctx, (e) => onLedger(e, sets, "member")).map((e) => ((e.callee as Extract<Expr, { kind: "member" }>).object as { name: string }).name),
    );
    for (const ins of inserts) {
      const set = ((ins.callee as Extract<Expr, { kind: "member" }>).object as { name: string }).name;
      const key = `${ins.loc.line}:${ins.loc.col}`;
      if (checked.has(set) || reported.has(key)) continue;
      reported.add(key);
      out.push({
        ruleId: "MS018",
        severity: "high",
        confidence: "medium",
        loc: ins.loc,
        message: `'${c.name}' adds to '${set}' without first checking that the value is not already in it. Inserting into a Set twice does not fail, so the same nullifier can be used again (a double spend or a second vote). Add assert(!${set}.member(…), "already used") before the insert.`,
      });
    }
  }
  return out;
}

/**
 * Whether a circuit (or a helper it calls) has a check that could identify the
 * caller: an assert that involves a witness, a ledger value or ownPublicKey(),
 * or a call into code we cannot see. An assert on parameters and constants only
 * (assert(amount <= 100)) limits how much, not who.
 */
function checksSomething(c: Circuit, ctx: Ctx, seen = new Set<string>()): boolean {
  if (seen.has(c.name)) return false;
  seen.add(c.name);
  for (const s of stmts(c.body ?? [])) {
    for (const e of stmtExprs(s)) {
      if (e.kind !== "call") continue;
      if (e.callee.kind === "ident" && e.callee.name === "assert" && e.args[0]) {
        for (const x of exprs(e.args[0])) {
          if (x.kind === "ident" && ctx.ledger.has(x.name)) return true;
          if (x.kind === "call" && x.callee.kind === "ident" && (ctx.witnesses.has(x.callee.name) || x.callee.name === "ownPublicKey" || (ctx.circuits.has(x.callee.name) && x.callee.name !== c.name))) return true;
          if (x.kind === "call" && x.callee.kind === "member" && x.callee.object.kind === "ident" && ctx.ledger.has(x.callee.object.name)) return true;
        }
      } else if (e.callee.kind === "ident" && ctx.circuits.has(e.callee.name)) {
        if (checksSomething(ctx.circuits.get(e.callee.name)!, ctx, seen)) return true;
      } else if (e.callee.kind === "ident" && !ctx.witnesses.has(e.callee.name) && !KNOWN_SAFE.has(e.callee.name) && !SEND.has(e.callee.name) && !MINT.has(e.callee.name)) {
        return true; // imported or unknown: may check the caller
      }
    }
  }
  return false;
}

const KNOWN_SAFE = new Set(["disclose", "pad", "persistentHash", "persistentCommit", "transientHash", "transientCommit", "default", "left", "right", "some", "none", "receiveShielded", "receiveUnshielded", "receive"]);

const SEND = new Set(["send", "sendImmediate", "sendShielded", "sendImmediateShielded", "sendUnshielded"]);
const MINT = new Set(["mintToken", "mintShieldedToken", "mintUnshieldedToken"]);

function unguardedTokenOps(ctx: Ctx): RawFinding[] {
  const out: RawFinding[] = [];
  for (const c of ctx.circuits.values()) {
    // `_name` is the convention for an unchecked building block that a wrapper circuit guards
    if (!c.exported || !c.body || c.name.startsWith("_")) continue;
    if (reach(c, ctx, new Set()).guarded && checksSomething(c, ctx)) continue;
    const isOp = (names: Set<string>) => (e: Expr) => e.kind === "call" && e.callee.kind === "ident" && names.has(e.callee.name);
    for (const e of reachableCalls(c, ctx, isOp(SEND))) {
      out.push({
        ruleId: "MS019",
        severity: "high",
        confidence: "medium",
        loc: e.loc,
        message: `'${c.name}' sends tokens with ${calleeName(e)}() but checks nothing: no assert, and no call that could check the caller. Anyone can call it and move the contract's funds. Check who is calling (and the amount) before sending.`,
      });
    }
    for (const e of reachableCalls(c, ctx, isOp(MINT))) {
      out.push({
        ruleId: "MS020",
        severity: "high",
        confidence: "medium",
        loc: e.loc,
        message: `'${c.name}' mints tokens with ${calleeName(e)}() but checks nothing: no assert, and no call that could check the caller. Anyone can mint any amount. If this is not a deliberate faucet, restrict who can mint and how much.`,
      });
    }
  }
  return out;
}

/** The constant domain tags in an expression: pad(32, "tag"). */
function tags(e: Expr): string[] {
  const out: string[] = [];
  for (const x of exprs(e)) {
    if (x.kind === "call" && calleeName(x) === "pad" && x.args[1]?.kind === "string") out.push(x.args[1].value);
  }
  return out;
}

/** Hash inputs without the tags, for comparing what two hashes are built from. */
function hashInputs(e: Expr): string {
  const parts: string[] = [];
  for (const x of exprs(e)) {
    if (x.kind === "call" && x.callee.kind === "ident" && x.callee.name !== "pad" && x.callee.name !== "disclose" && !/Hash|Commit/.test(x.callee.name)) parts.push(`${x.callee.name}()`);
    else if (x.kind === "ident" && !["pad", "disclose"].includes(x.name)) parts.push(x.name);
  }
  return [...new Set(parts)].sort().join(",");
}

function nullifierMatchesLeaf(program: Program, ctx: Ctx): RawFinding[] {
  const types = new Map<string, string>();
  walk(program.decls, (d) => {
    if (d.kind === "ledger") types.set(d.name, d.type.name);
  });
  const isTree = (n: string) => /MerkleTree$/.test(types.get(n) ?? "");
  const isSet = (n: string) => types.get(n) === "Set";
  type Use = { field: string; tag: string; inputs: string; loc: Loc; at: Loc };
  const uses: Use[] = [];
  walk(program.decls, (d) => {
    const body = bodyOf(d);
    const locals = new Map<string, Expr>();
    for (const s of stmts(body)) {
      if (s.kind === "const" && s.names.length === 1) locals.set(s.names[0], s.init);
      for (const e of stmtExprs(s)) {
        if (e.kind !== "call" || e.callee.kind !== "member" || e.callee.object.kind !== "ident" || e.callee.property !== "insert" || !e.args[0]) continue;
        const field = e.callee.object.name;
        if (!isTree(field) && !isSet(field)) continue;
        let v = unwrapDisclose(e.args[0]);
        if (v.kind === "ident" && locals.has(v.name)) v = unwrapDisclose(locals.get(v.name)!);
        for (const tag of tags(v)) uses.push({ field, tag, inputs: hashInputs(v), loc: e.loc, at: v.loc });
      }
    }
  });
  const out: RawFinding[] = [];
  for (const n of uses.filter((u) => isSet(u.field))) {
    const leaf = uses.find((u) => isTree(u.field) && u.tag === n.tag && u.inputs === n.inputs);
    if (!leaf) continue;
    out.push({
      ruleId: "MS021",
      severity: "high",
      confidence: "medium",
      loc: n.at,
      message: `The value added to '${n.field}' is built from the same tag ("${n.tag}") and inputs as the leaf added to '${leaf.field}' on line ${leaf.loc.line}, so the nullifier equals the member's leaf. Anyone can match the two and see which member acted, which breaks the anonymity the Merkle tree gives. Use a different tag for nullifiers.`,
    });
  }
  return out;
}

function shadowedLedger(program: Program, ctx: Ctx): RawFinding[] {
  const out: RawFinding[] = [];
  const flag = (name: string, loc: Loc, what: string) =>
    out.push({
      ruleId: "MS022",
      severity: "low",
      confidence: "high",
      loc,
      message: `The ${what} '${name}' has the same name as a ledger field, so inside this circuit '${name}' no longer refers to the ledger: a read meant for the ledger silently uses the local value instead. Rename it.`,
    });
  walk(program.decls, (d) => {
    if (d.kind !== "circuit" && d.kind !== "constructor") return;
    for (const p of d.params) if (ctx.ledger.has(p.name)) flag(p.name, p.loc, "parameter");
    for (const s of stmts(bodyOf(d))) if (s.kind === "const") for (const n of s.names) if (ctx.ledger.has(n)) flag(n, s.loc, "local constant");
  });
  return out;
}

const COMMIT = new Set(["persistentCommit", "transientCommit"]);

function secretKeyAsRandomness(program: Program, ctx: Ctx): RawFinding[] {
  const out: RawFinding[] = [];
  for (const e of allExprs(program)) {
    if (e.kind !== "call" || e.callee.kind !== "ident" || !COMMIT.has(e.callee.name) || e.args.length < 2) continue;
    const r = unwrapDisclose(e.args[e.args.length - 1]);
    const w = r.kind === "call" && r.callee.kind === "ident" && ctx.witnesses.has(r.callee.name) ? r.callee.name : undefined;
    if (!w || !isSecretName(w) || /rand|salt|nonce|blind|entropy/i.test(w)) continue;
    out.push({
      ruleId: "MS023",
      severity: "high",
      confidence: "medium",
      loc: r.loc,
      message: `'${w}()' looks like a long-term secret key and is used as the randomness of a commitment. Opening the commitment would reveal the key, and committing to the same value twice gives the same commitment, which links the user's actions. Use fresh randomness for each commitment.`,
    });
  }
  return out;
}


// ---- checks mapped from other ecosystems' analyzers (Slither, Circomspect) ----

/** MS024: an if or a conditional on a constant (Slither boolean-cst, Circomspect constant branch). */
function constantCondition(program: Program): RawFinding[] {
  const out: RawFinding[] = [];
  const isConst = (e: Expr) => {
    const x = unwrapDisclose(e);
    return x.kind === "ident" && (x.name === "true" || x.name === "false");
  };
  walk(program.decls, (d) => {
    // assert(false) directly in a circuit body (inside a branch it is a deliberate rejection)
    for (const s of bodyOf(d)) {
      const e = s.kind === "expr" ? s.expr : undefined;
      if (e?.kind === "call" && e.callee.kind === "ident" && e.callee.name === "assert" && e.args[0]) {
        const c = unwrapDisclose(e.args[0]);
        if (c.kind === "ident" && c.name === "false") {
          out.push({ ruleId: "MS024", severity: "medium", confidence: "high", loc: e.loc, message: "assert(false) always fails, so every call of this circuit is rejected. If the circuit should be disabled, remove it; otherwise write the real condition." });
        }
      }
    }
    for (const s of stmts(bodyOf(d))) {
      if (s.kind === "if" && isConst(s.test)) {
        out.push({ ruleId: "MS024", severity: "medium", confidence: "high", loc: s.loc, message: "This if always takes the same branch, because its condition is a constant. One branch is dead code; this is often a leftover from debugging that turned a check off." });
      }
    }
  });
  return out;
}

/** Ledger fields an expression reads. */
function readsOf(e: Expr, ledger: Set<string>): Set<string> {
  const out = new Set<string>();
  for (const x of exprs(e)) if (x.kind === "ident" && ledger.has(x.name)) out.add(x.name);
  return out;
}

/** MS025: a ledger field written twice in a row with no read in between (Slither write-after-write). */
function writeAfterWrite(program: Program, ctx: Ctx): RawFinding[] {
  const out: RawFinding[] = [];
  walk(program.decls, (d) => {
    const body = bodyOf(d);
    const pending = new Map<string, Loc>();
    for (const s of body) {
      // only straight-line top-level statements; anything else ends the sequence
      if (s.kind === "assign" && s.target.kind === "ident" && ctx.ledger.has(s.target.name) && s.op === "=") {
        for (const r of readsOf(s.value, ctx.ledger)) pending.delete(r);
        const prev = pending.get(s.target.name);
        if (prev) {
          out.push({ ruleId: "MS025", severity: "medium", confidence: "high", loc: s.loc, message: `'${s.target.name}' is written on line ${prev.line} and written again here before anything reads it, so the first write has no effect. One of the two is probably meant for a different field.` });
        }
        pending.set(s.target.name, s.loc);
      } else if (s.kind === "const" || s.kind === "expr") {
        for (const e of stmtExprs(s)) for (const r of readsOf(e, ctx.ledger)) pending.delete(r);
        for (const e of stmtExprs(s)) if (e.kind === "call" && e.callee.kind === "ident" && ctx.circuits.has(e.callee.name)) pending.clear();
      } else pending.clear();
    }
  });
  return out;
}

// standard-library circuits that are not keywords (disclose, pad, assert, default, map, fold and slice are keywords and cannot be redeclared)
const STDLIB_NAMES = new Set(["persistentHash", "persistentCommit", "transientHash", "transientCommit", "ownPublicKey", "merkleTreePathRoot", "merkleTreePathRootNoLeafHash", "some", "none", "left", "right", "degradeToTransient", "upgradeFromTransient", "tokenType", "nativeToken"]);

/** MS026: a declaration hides a standard-library name (Slither shadowing-builtin). */
function shadowedBuiltin(program: Program): RawFinding[] {
  const out: RawFinding[] = [];
  const flag = (name: string, loc: Loc) =>
    out.push({ ruleId: "MS026", severity: "low", confidence: "high", loc, message: `'${name}' hides the standard-library ${name}, so calls in this scope use this value or circuit instead. A reader (or an AI agent) will assume the standard one. Rename it.` });
  walk(program.decls, (d) => {
    if ((d.kind === "circuit" || d.kind === "witness") && STDLIB_NAMES.has(d.name)) flag(d.name, d.loc);
    if (d.kind === "circuit" || d.kind === "constructor") {
      for (const p of d.params) if (STDLIB_NAMES.has(p.name)) flag(p.name, p.loc);
      for (const s of stmts(bodyOf(d))) if (s.kind === "const") for (const n of s.names) if (STDLIB_NAMES.has(n)) flag(n, s.loc);
    }
  });
  return out;
}

/** MS027: a Boolean check whose result is thrown away (Slither unused-return / unchecked-transfer). */
function ignoredCheck(program: Program, ctx: Ctx): RawFinding[] {
  const out: RawFinding[] = [];
    // only helpers named as checks: a Boolean result like _grantRole's "was it new" is informational
  const boolCircuits = new Set(
    [...ctx.circuits.values()].filter((c) => c.returnType?.name === "Boolean" && /^_?(is|has|check|verify|can|valid|contains|was|owns)/i.test(c.name)).map((c) => c.name),
  );
  const BOOL_METHODS = new Set(["member", "checkRoot", "isEmpty", "lessThan", "isSome", "isNone"]);
  walk(program.decls, (d) => {
    for (const s of stmts(bodyOf(d))) {
      if (s.kind !== "expr") continue;
      const e = unwrapDisclose(s.expr);
      if (e.kind !== "call") continue;
      let what: string | undefined;
      if (e.callee.kind === "ident" && boolCircuits.has(e.callee.name)) what = `${e.callee.name}()`;
      if (e.callee.kind === "ident" && ["blockTimeLessThan", "blockTimeGreaterThan", "blockTimeGte", "blockTimeLt", "unshieldedBalanceGte", "unshieldedBalanceLt", "unshieldedBalanceLte", "unshieldedBalanceGt"].includes(e.callee.name)) what = `${e.callee.name}()`;
      if (e.callee.kind === "member" && BOOL_METHODS.has(e.callee.property) && e.callee.object.kind === "ident" && ctx.ledger.has(e.callee.object.name)) what = `${e.callee.object.name}.${e.callee.property}()`;
      if (!what) continue;
      out.push({ ruleId: "MS027", severity: "high", confidence: "high", loc: s.loc, message: `${what} returns a Boolean, and the result is thrown away, so nothing is enforced. Wrap it in assert(…, "…") if it is meant as a check.` });
    }
  });
  return out;
}

const RECEIVE = new Set(["receive", "receiveShielded", "receiveUnshielded"]);

/** MS028: the contract receives tokens but nothing can send them out (Slither locked-ether). */
function lockedTokens(program: Program): RawFinding[] {
  let receive: Expr | undefined;
  let sends = false;
  let opaque = false;
  for (const e of allExprs(program)) {
    if (e.kind !== "call" || e.callee.kind !== "ident") continue;
    if (RECEIVE.has(e.callee.name)) receive ??= e;
    if (SEND.has(e.callee.name)) sends = true;
  }
  walk(program.decls, (d) => {
    if (d.kind === "import" && !/CompactStandardLibrary/.test(d.target)) opaque = true;
    if (d.kind === "include") opaque = true;
  });
  if (!receive || sends || opaque) return [];
  return [{ ruleId: "MS028", severity: "medium", confidence: "medium", loc: receive.loc, message: "The contract receives tokens, but no circuit in it sends tokens out. Anything deposited stays locked in the contract for good. Add a withdrawal circuit (with a caller check), or make sure this is intended." }];
}

/** MS029: a statement that does nothing (Slither redundant-statements, Circomspect side-effect-free assignment). */
function noEffect(program: Program): RawFinding[] {
  const out: RawFinding[] = [];
  walk(program.decls, (d) => {
    for (const s of stmts(bodyOf(d))) {
      if (s.kind !== "expr") continue;
      const e = unwrapDisclose(s.expr);
      if (e.kind === "ident" || e.kind === "member" || (e.kind === "binary" && ["==", "!=", "&&", "||"].includes(e.op))) {
        out.push({ ruleId: "MS029", severity: "low", confidence: "high", loc: s.loc, message: "This statement computes a value and does nothing with it. It is probably an unfinished assignment or a check that is missing its assert(…)." });
      }
    }
  });
  return out;
}

/** MS031: arithmetic on a Field ledger value, which wraps around silently (Circomspect field-arithmetic). */
function fieldArithmetic(program: Program): RawFinding[] {
  const fields = new Set<string>();
  walk(program.decls, (d) => {
    if (d.kind === "ledger" && d.type.name === "Field") fields.add(d.name);
  });
  if (!fields.size) return [];
  const out: RawFinding[] = [];
  walk(program.decls, (d) => {
    for (const s of stmts(bodyOf(d))) {
      if (s.kind !== "assign" || s.target.kind !== "ident" || !fields.has(s.target.name)) continue;
      const arith = s.op === "+=" || s.op === "-=" || [...exprs(s.value)].some((x) => x.kind === "binary" && ["+", "-", "*"].includes(x.op));
      if (!arith) continue;
      out.push({ ruleId: "MS031", severity: "high", confidence: "medium", loc: s.loc, message: `'${s.target.name}' is a Field, and Field arithmetic wraps around modulo a large prime instead of failing. Subtracting more than the balance gives a huge positive number. Store amounts as Uint<…>, whose arithmetic is checked.` });
    }
  });
  return out;
}

/** MS032: a local constant that is never used (Circomspect unused variable). */
function unusedLocals(program: Program): RawFinding[] {
  const out: RawFinding[] = [];
  walk(program.decls, (d) => {
    const body = bodyOf(d);
    const used = new Set<string>();
    for (const s of stmts(body)) for (const e of stmtExprs(s)) if (e.kind === "ident") used.add(e.name);
    // names used as assignment targets of a struct field etc. count too
    for (const s of stmts(body)) {
      if (s.kind !== "const") continue;
      for (const n of s.names) {
        if (n === "_" || n.startsWith("_") || used.has(n)) continue;
        out.push({ ruleId: "MS032", severity: "info", confidence: "high", loc: s.loc, message: `The local constant '${n}' is computed but never used. Often a check was meant to use it (assert(${n} == …)); otherwise remove it.` });
      }
    }
  });
  return out;
}


/**
 * MS034: state that anyone can set is trusted by another circuit. An exported
 * circuit with no caller check writes a ledger field from a parameter or a
 * witness, and another circuit relies on that field in an assert or in the
 * amount or recipient of a token transfer (the oracle-price pattern).
 */
const HASHING_FNS = new Set(["persistentHash", "transientHash"]);

function untrustedStateDependency(program: Program, ctx: Ctx): RawFinding[] {
  const out: RawFinding[] = [];
  const params = (c: Circuit) => new Set(c.params.map((p) => p.name));
  const callerControlled = (e: Expr, ps: Set<string>) =>
    [...exprs(e)].some((x) => (x.kind === "ident" && ps.has(x.name)) || (x.kind === "call" && x.callee.kind === "ident" && ctx.witnesses.has(x.callee.name)));
  // fields written from caller-controlled values in unchecked exported circuits; a module's
  // `export circuit` is exported to the importing contract, which decides what it exposes
  const inModule = new Set<string>();
  for (const d of program.decls) if (d.kind === "module") walk(d.decls, (x) => x.kind === "circuit" && inModule.add(x.name));
  const open = new Map<string, { circuit: string; loc: Loc }>();
  for (const c of ctx.circuits.values()) {
    if (!c.exported || !c.body || c.name.startsWith("_") || inModule.has(c.name) || checksSomething(c, ctx)) continue;
    const ps = params(c);
    for (const s of stmts(c.body)) {
      if (s.kind === "assign" && s.target.kind === "ident" && ctx.ledger.has(s.target.name) && callerControlled(s.value, ps) && !open.has(s.target.name)) {
        open.set(s.target.name, { circuit: c.name, loc: s.loc });
      }
      for (const e of stmtExprs(s)) {
        if (e.kind === "call" && e.callee.kind === "member" && e.callee.property === "write" && e.callee.object.kind === "ident" && ctx.ledger.has(e.callee.object.name) && e.args[0] && callerControlled(e.args[0], ps) && !open.has(e.callee.object.name)) {
          open.set(e.callee.object.name, { circuit: c.name, loc: e.loc });
        }
      }
    }
  }
  if (!open.size) return out;
  const reads = (e: Expr, f: string) => [...exprs(e)].some((x) => (x.kind === "ident" && x.name === f) || (x.kind === "call" && x.callee.kind === "member" && x.callee.object.kind === "ident" && x.callee.object.name === f));
  const TRANSFER = new Set([...SEND, ...MINT]);
  for (const [field, w] of open) {
    let use: { circuit: string; how: string } | undefined;
    for (const c of ctx.circuits.values()) {
      if (c.name === w.circuit || !c.body) continue;
      // a parameter or local with the same name hides the ledger field (MS022)
      if (c.params.some((p) => p.name === field) || [...stmts(c.body)].some((s) => s.kind === "const" && s.names.includes(field))) continue;
      for (const s of stmts(c.body)) {
        for (const e of stmtExprs(s)) {
          if (e.kind !== "call" || e.callee.kind !== "ident") continue;
          // an assert that recomputes a hash or commitment from the caller's secret and compares it
          // with the stored value checks the caller against it (commit-reveal); it does not trust it
          const opens = (x: Expr) => [...exprs(x)].some((y) => y.kind === "call" && y.callee.kind === "ident" && (COMMIT.has(y.callee.name) || HASHING_FNS.has(y.callee.name) || ctx.witnesses.has(y.callee.name)));
          if (e.callee.name === "assert" && e.args[0] && reads(e.args[0], field) && !opens(e.args[0])) use ??= { circuit: c.name, how: "a check" };
          if (TRANSFER.has(e.callee.name) && e.args.some((a) => reads(a, field))) use ??= { circuit: c.name, how: `a token ${MINT.has(e.callee.name) ? "mint" : "transfer"}` };
        }
      }
    }
    if (!use) continue;
    out.push({
      ruleId: "MS034",
      severity: "high",
      confidence: "medium",
      loc: w.loc,
      message: `'${w.circuit}' lets any caller set '${field}' (no caller check), and '${use.circuit}' relies on '${field}' in ${use.how}. Whoever calls '${w.circuit}' first decides what '${use.circuit}' accepts. Restrict who can write '${field}' (an owner check or a Merkle proof bound to the caller), or verify the value where it is used.`,
    });
  }
  return out;
}

export function checkContract(program: Program): RawFinding[] {
  const ctx: Ctx = { ledger: new Set(), witnesses: new Set(), circuits: new Map(), enums: new Set() };
  collect(program.decls, ctx);
  return [
    ...unused(program),
    ...tautologicalAsserts(program),
    ...nullifierNotChecked(program, ctx),
    ...unguardedTokenOps(ctx),
    ...nullifierMatchesLeaf(program, ctx),
    ...shadowedLedger(program, ctx),
    ...secretKeyAsRandomness(program, ctx),
    ...constantCondition(program),
    ...writeAfterWrite(program, ctx),
    ...shadowedBuiltin(program),
    ...ignoredCheck(program, ctx),
    ...lockedTokens(program),
    ...noEffect(program),
    ...fieldArithmetic(program),
    ...unusedLocals(program),
    ...untrustedStateDependency(program, ctx),
  ];
}
