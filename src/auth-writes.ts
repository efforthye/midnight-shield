// MS011: an exported circuit changes a ledger field that the contract uses for
// authorization (an owner key, an admin set), and nothing in that circuit
// checks the caller. Anyone can then make themselves the owner or an admin.
//
// This is a structural check on the syntax tree. To stay quiet on real code it
// treats a circuit as guarded when it, or any circuit it calls in the same
// file, contains an assert, and when it calls anything it cannot see into
// (an imported module's circuit, for example an `assertOnlyOwner()`).

import type { RawFinding } from "./analyzer.js";
import type { Decl, Expr, Loc, Program, Stmt } from "./ast.js";

type Circuit = Extract<Decl, { kind: "circuit" }>;

/** Built-ins and standard-library functions that never check the caller. */
const BUILTINS = new Set([
  "disclose", "pad", "persistentHash", "persistentCommit", "transientHash", "transientCommit",
  "degradeToTransient", "upgradeFromTransient", "ownPublicKey", "merkleTreePathRoot",
  "merkleTreePathRootNoLeafHash", "default", "some", "none", "left", "right", "ecAdd", "ecMul",
  "ecMulGenerator", "hashToCurve", "nativeToken", "tokenType", "mintToken", "evolveNonce",
  "receive", "send", "sendImmediate", "mergeCoin", "mergeCoinImmediate", "createZswapInput",
  "createZswapOutput", "burnAddress", "blockTimeLessThan", "blockTimeGreaterThan",
  "blockTimeGte", "blockTimeLt", "map", "fold", "slice", "assert",
  "sendShielded", "sendImmediateShielded", "sendUnshielded", "mergeCoin", "mergeCoinImmediate", "evolveNonce", "blockTimeLte", "blockTimeGt", "jubjubSchnorrVerify", "mintShieldedToken", "mintUnshieldedToken", "receiveShielded", "receiveUnshielded",
  "unshieldedBalance", "unshieldedBalanceLt", "unshieldedBalanceGte", "unshieldedBalanceLte", "unshieldedBalanceGt",
  "shieldedBurnAddress", "kernel", "self", "left", "right",
]);

/** Ledger ADT methods that change state. */
const WRITE_METHODS = new Set(["write", "insert", "insertDefault", "remove", "resetToDefault", "insertCoin", "increment", "decrement"]);

export interface Ctx {
  ledger: Set<string>;
  witnesses: Set<string>;
  circuits: Map<string, Circuit>;
  enums: Set<string>;
}

export function collect(decls: Decl[], ctx: Ctx): void {
  for (const d of decls) {
    if (d.kind === "ledger") ctx.ledger.add(d.name);
    else if (d.kind === "witness") ctx.witnesses.add(d.name);
    else if (d.kind === "circuit") ctx.circuits.set(d.name, d);
    else if (d.kind === "enum") ctx.enums.add(d.name);
    else if (d.kind === "module") collect(d.decls, ctx);
  }
}

export function* exprs(e: Expr): Generator<Expr> {
  yield e;
  switch (e.kind) {
    case "call":
      yield* exprs(e.callee);
      for (const a of e.args) yield* exprs(a);
      break;
    case "member":
      yield* exprs(e.object);
      break;
    case "index":
      yield* exprs(e.object);
      yield* exprs(e.index);
      break;
    case "vector":
      for (const x of e.elements) yield* exprs(x);
      break;
    case "struct":
      for (const f of e.fields) yield* exprs(f.value);
      break;
    case "binary":
      yield* exprs(e.left);
      yield* exprs(e.right);
      break;
    case "unary":
    case "spread":
      yield* exprs(e.arg);
      break;
    case "cast":
      yield* exprs(e.expr);
      break;
    case "cond":
      yield* exprs(e.test);
      yield* exprs(e.then);
      yield* exprs(e.else);
      break;
    case "lambda":
      if (Array.isArray(e.body)) for (const s of e.body) yield* stmtExprs(s);
      else yield* exprs(e.body);
      break;
  }
}

export function* stmtExprs(s: Stmt): Generator<Expr> {
  switch (s.kind) {
    case "const":
      yield* exprs(s.init);
      break;
    case "assign":
      yield* exprs(s.target);
      yield* exprs(s.value);
      break;
    case "if":
      yield* exprs(s.test);
      for (const x of s.then) yield* stmtExprs(x);
      for (const x of s.else ?? []) yield* stmtExprs(x);
      break;
    case "for":
      yield* exprs(s.iter);
      for (const x of s.body) yield* stmtExprs(x);
      break;
    case "return":
      if (s.value) yield* exprs(s.value);
      break;
    case "expr":
      yield* exprs(s.expr);
      break;
    case "block":
      for (const x of s.body) yield* stmtExprs(x);
      break;
  }
}

export function* stmts(body: Stmt[]): Generator<Stmt> {
  for (const s of body) {
    yield s;
    if (s.kind === "if") {
      yield* stmts(s.then);
      if (s.else) yield* stmts(s.else);
    } else if (s.kind === "for") yield* stmts(s.body);
    else if (s.kind === "block") yield* stmts(s.body);
  }
}

/** The ledger field an expression reads: `owner`, `owner.read()`. */
function ledgerRef(e: Expr, ctx: Ctx): string | undefined {
  if (e.kind === "ident" && ctx.ledger.has(e.name)) return e.name;
  if (e.kind === "call" && e.callee.kind === "member" && e.callee.property === "read" && e.callee.object.kind === "ident" && ctx.ledger.has(e.callee.object.name)) {
    return e.callee.object.name;
  }
  return undefined;
}

/** Calls that only move or read data, so a value built from them does not identify anyone. */
const PASS_THROUGH = new Set(["disclose", "read", "lookup", "member", "size", "isEmpty", "length"]);

/**
 * A value that identifies a caller: computed by a call such as a hash of a
 * witness, a public-key derivation or ownPublicKey(). A plain parameter or a
 * ledger read is data, not an identity (`scores.member(disclose(id))` is an
 * existence check, not an allow-list).
 */
function identityLike(e: Expr): boolean {
  for (const x of exprs(e)) {
    if (x.kind !== "call") continue;
    // a commitment being opened (commit-reveal) is about data, not about who is calling
    if (x.callee.kind === "ident" && (x.callee.name === "persistentCommit" || x.callee.name === "transientCommit")) return false;
    const name = x.callee.kind === "ident" ? x.callee.name : x.callee.kind === "member" ? x.callee.property : "";
    if (!PASS_THROUGH.has(name)) return true;
  }
  return false;
}

function callName(e: Extract<Expr, { kind: "call" }>): { name: string; member?: { object: string; method: string } } {
  if (e.callee.kind === "ident") return { name: e.callee.name };
  if (e.callee.kind === "member" && e.callee.object.kind === "ident") {
    return { name: `${e.callee.object.name}.${e.callee.property}`, member: { object: e.callee.object.name, method: e.callee.property } };
  }
  return { name: "" };
}

/** Ledger fields the contract compares against a caller identity inside an assert. */
function authFields(ctx: Ctx): Set<string> {
  const out = new Set<string>();
  for (const c of ctx.circuits.values()) {
    for (const s of stmts(c.body ?? [])) {
      // a comparison in an if decides who gets through just like an assert does
      const conditions: Expr[] = s.kind === "if" ? [s.test] : [];
      for (const e of stmtExprs(s)) if (e.kind === "call" && e.callee.kind === "ident" && e.callee.name === "assert" && e.args[0]) conditions.push(e.args[0]);
      for (const cond of conditions) {
        for (const x of exprs(cond)) {
          if (x.kind === "binary" && (x.op === "==" || x.op === "!=")) {
            const l = ledgerRef(x.left, ctx);
            const r = ledgerRef(x.right, ctx);
            if (l && !r && identityLike(x.right)) out.add(l);
            if (r && !l && identityLike(x.left)) out.add(r);
          }
          // Set/Map membership used as an allow-list: assert(admins.member(caller))
          if (x.kind === "call") {
            const { member } = callName(x);
            if (member && member.method === "member" && ctx.ledger.has(member.object) && x.args[0] && identityLike(x.args[0])) out.add(member.object);
          }
        }
      }
    }
  }
  return out;
}

interface Reach {
  writes: { field: string; loc: Loc }[];
  guarded: boolean;
}

/** Writes to auth fields reachable from a circuit, and whether anything on the way may check the caller. */
export function reach(c: Circuit, ctx: Ctx, fields: Set<string>, seen = new Set<string>()): Reach {
  const result: Reach = { writes: [], guarded: false };
  if (seen.has(c.name)) return result;
  seen.add(c.name);
  for (const s of stmts(c.body ?? [])) {
    if (s.kind === "assign" && s.target.kind === "ident" && fields.has(s.target.name)) result.writes.push({ field: s.target.name, loc: s.loc });
    for (const e of stmtExprs(s)) {
      if (e.kind !== "call") continue;
      const { name, member } = callName(e);
      if (name === "assert") result.guarded = true;
      else if (member && ctx.ledger.has(member.object)) {
        if (WRITE_METHODS.has(member.method) && fields.has(member.object)) result.writes.push({ field: member.object, loc: e.loc });
      } else if (ctx.circuits.has(name)) {
        const sub = reach(ctx.circuits.get(name)!, ctx, fields, seen);
        result.writes.push(...sub.writes);
        if (sub.guarded) result.guarded = true;
      } else if (!BUILTINS.has(name) && !ctx.witnesses.has(name) && !(member && ctx.enums.has(member.object))) {
        // an imported or unknown function: it may check the caller, so stay quiet
        result.guarded = true;
      }
    }
  }
  return result;
}

/** Ledger fields whose names say they decide who is in charge. */
const AUTH_NAME = /^_?(owner|admins?|authority|operator|controller|minter|governor|guardian|manager|superuser|root(Admin)?)(Id|Key|PublicKey|Address|Commitment|Hash|s)?$/i;

export function checkAuthWrites(program: Program): RawFinding[] {
  const ctx: Ctx = { ledger: new Set(), witnesses: new Set(), circuits: new Map(), enums: new Set() };
  collect(program.decls, ctx);
  const checked = authFields(ctx);
  // fields named like an owner or admin count too, with lower confidence: the
  // contract may not compare them anywhere yet (then anyone can set them freely)
  const named = new Set([...ctx.ledger].filter((n) => AUTH_NAME.test(n) && !checked.has(n)));
  const fields = new Set([...checked, ...named]);
  if (!fields.size) return [];
  const out: RawFinding[] = [];
  const reported = new Set<string>();
  for (const c of ctx.circuits.values()) {
    if (!c.exported || !c.body) continue;
    const r = reach(c, ctx, fields);
    if (r.guarded) continue;
    for (const w of r.writes) {
      const key = `${w.loc.line}:${w.loc.col}`;
      if (reported.has(key)) continue;
      reported.add(key);
      const byName = named.has(w.field);
      out.push({
        ruleId: "MS011",
        severity: "high",
        confidence: byName ? "low" : "medium",
        loc: w.loc,
        message: byName
          ? `'${c.name}' changes '${w.field}', which by its name decides who is in charge, and nothing in '${c.name}' checks who is calling. Anyone can call it and set '${w.field}'. Assert that the caller is the current ${w.field.replace(/^_/, "")} (prove knowledge of a secret whose hash is stored) before changing it.`
          : `'${c.name}' changes '${w.field}', which the contract uses to authorize callers, but nothing in '${c.name}' checks who is calling. Anyone can call it and take over '${w.field}'. Assert that the caller is the current owner (prove knowledge of the secret behind '${w.field}') before changing it.`,
      });
    }
  }
  return out;
}
