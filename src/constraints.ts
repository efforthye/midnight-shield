// Witness constraint report: for every exported circuit, each value the prover
// chooses (witness results and the circuit's own parameters), where it ends up
// (ledger fields, token amounts and recipients, return values), and what in the
// circuit constrains it. This is the Compact counterpart of the under-constrained
// analyses of Circomspect and Picus: a proof is only as strong as the checks that
// tie prover-chosen values to something the prover does not choose.
//
// MS037 (self-satisfiable-check) is built on it: an assert whose every input is
// chosen by the prover, with nothing trusted in it (no ledger state, no constant,
// no hash), can always be made to pass by picking the values to fit.

import type { RawFinding } from "./analyzer.js";
import type { Decl, Expr, Program, Stmt } from "./ast.js";
import { collect, exprs, stmtExprs, type Ctx } from "./auth-writes.js";
import { TOKEN_OPS } from "./access.js";

type Circuit = Extract<Decl, { kind: "circuit" }>;

/** A name bound in scope: a local constant, or a helper's parameter bound to the argument expression. */
interface Binding {
  expr: Expr;
  env: Env;
}
type Env = Map<string, Binding>;

/** What an expression is built from, after following locals, helper parameters and helper return values. */
interface Leaves {
  witnesses: Set<string>;
  params: Set<string>;
  ledger: Set<string>;
  constant: boolean;
  hashed: boolean;
  ownKey: boolean;
  /** a comparison (==, <, …) somewhere in it, also inside helper circuits */
  relational: boolean;
  /** a ledger set or Merkle tree membership check somewhere in it */
  membership: boolean;
  /** inputs that appear outside any hash (the rest only appear hashed) */
  open: Set<string>;
  /** inputs whose value itself is used, not as a key into a ledger map or set */
  value: Set<string>;
}

const HASHES = new Set(["keccak256", "sha256", "secp256k1EcdsaVerify", "secp256k1EcdsaVerifyLowS", "secp256k1EcdsaRecover", "secp256k1EthereumAddress", "schnorrVerify", "ecdsaVerify", "persistentHash", "persistentCommit", "transientHash", "transientCommit", "ecMul", "ecMulGenerator", "hashToCurve", "jubjubSchnorrVerify", "merkleTreePathRoot", "merkleTreePathRootNoLeafHash"]);
const LEDGER_READS = new Set(["read", "lookup", "member", "size", "isEmpty", "checkRoot", "isHistoricRoot", "head", "length", "first", "root", "history", "isFull"]);
const RELATIONAL = new Set(["==", "!=", "<", "<=", ">", ">="]);

export type Constraint =
  | "tied to ledger" // compared with ledger state
  | "hash or signature" // checked through a hash or a signature: knowing the preimage or key is the point
  | "bounded by constant" // compared with a constant
  | "membership" // checked against a ledger set or Merkle tree
  | "coin value" // passed to receive(), so the chain checks it
  | "only other prover values"; // every value in the check is chosen by the prover (MS037)

export interface InputReport {
  /** `secretKey()` for a witness, `amount` for a parameter */
  name: string;
  kind: "witness" | "parameter";
  /** where the value ends up; "(hashed)" when it only gets there inside a hash or commitment */
  reaches: string[];
  /** every place it reaches, it reaches only hashed: a secret, which needs no constraint */
  hashedOnly: boolean;
  constraints: { kind: Constraint; line: number }[];
}

export interface CircuitConstraints {
  name: string;
  line: number;
  module: boolean;
  inputs: InputReport[];
  /** asserts that only compare prover-chosen values with each other */
  selfSatisfiable: { line: number; col: number; inputs: string[] }[];
  /** nullifier checks whose value the prover can vary: witnesses tied to nothing else (MS038) */
  freeNullifiers: { line: number; col: number; set: string; inputs: string[] }[];
}

interface Check {
  line: number;
  col: number;
  leaves: Leaves;
  relational: boolean;
  membership: boolean;
  isIf: boolean;
  /** the two sides of each `==` in the condition (split at &&) */
  equalities: [Leaves, Leaves][];
  message?: string;
  /** `!set.member(x)`: the set and what x is built from */
  notMember?: { set: string; leaves: Leaves };
}

interface Sink {
  label: string;
  leaves: Leaves;
}

const empty = (): Leaves => ({ witnesses: new Set(), params: new Set(), ledger: new Set(), constant: false, hashed: false, ownKey: false, relational: false, membership: false, open: new Set(), value: new Set() });
const calleeIdent = (e: Expr): string => (e.kind === "call" && e.callee.kind === "ident" ? e.callee.name : "");

const ARITH = new Set(["+", "-", "*", "/", "%", "<", "<=", ">", ">="]);

/** How the contract treats a witness, from everywhere it is used: the facts rules read instead of guessing from names. */
export interface WitnessRole {
  /** used in arithmetic or an ordering comparison: an amount, a score, a time */
  quantity: boolean;
  /** used inside a hash, commitment or signature: key material */
  hashed: boolean;
  /** published (to the ledger, a transfer or a return value) outside any hash */
  publishedRaw: boolean;
  /** used as the key of a ledger map or set entry: an identifier for an account or record */
  keyed: boolean;
}

class ConstraintScanner {
  /** how many hash calls we are inside while collecting leaves */
  private hashDepth = 0;
  /** how many ledger lookups we are inside: a key picks an entry, its value is not used */
  private keyDepth = 0;
  /** witnesses seen as operands of arithmetic or ordering, and seen inside hashes */
  readonly quantity = new Set<string>();
  readonly hashedSeen = new Set<string>();
  readonly keyedSeen = new Set<string>();
  private budget = 0;
  /** ledger sets or maps that only record that a value was used (nullifier sets) */
  readonly usedMarks = new Set<string>();
  /** set.insert(x) / tree.insert(x): one value added to a set or tree */
  readonly singleInserts: { field: string; leaves: Leaves }[] = [];

  constructor(
    private ctx: Ctx,
    private roots: Set<string>,
  ) {}

  /** The ledger field an expression's member chain starts from. */
  private rootField(e: Expr): string | undefined {
    if (e.kind === "ident") return this.ctx.ledger.has(e.name) ? e.name : undefined;
    if (e.kind === "member" || e.kind === "index") return this.rootField(e.object);
    if (e.kind === "call") return this.rootField(e.callee);
    return undefined;
  }

  leaves(e: Expr, env: Env, out = empty(), depth = 0): Leaves {
    // deep enough for a leaf built through several helpers and locals (MerkleTreePath { leaf: leafOf(org, commitOf(sk)) })
    // and a budget per top-level call: shared locals and helpers are walked once per use, which can blow up
    if (depth === 0) this.budget = 20000;
    if (depth > 48 || --this.budget < 0) return out;
    switch (e.kind) {
      case "number":
      case "string":
        out.constant = true;
        break;
      case "ident": {
        const b = env.get(e.name);
        if (b) this.leaves(b.expr, b.env, out, depth + 1);
        else if (this.ctx.ledger.has(e.name)) out.ledger.add(e.name);
        else if (this.roots.has(e.name)) {
          out.params.add(e.name);
          if (!this.hashDepth) out.open.add(e.name);
          if (!this.hashDepth && !this.keyDepth) out.value.add(e.name);
        }
        else out.constant = true; // an enum member or a module-level constant
        break;
      }
      case "call": {
        const name = calleeIdent(e);
        if (e.callee.kind === "member") {
          const f = this.rootField(e.callee.object);
          if (f && LEDGER_READS.has(e.callee.property)) {
            out.ledger.add(f);
            if (e.callee.property === "member" || e.callee.property === "checkRoot" || e.callee.property === "isHistoricRoot") out.membership = true;
            this.keyDepth++;
            for (const a of e.args) this.leaves(a, env, out, depth + 1);
            this.keyDepth--;
            break;
          }
          this.leaves(e.callee.object, env, out, depth + 1);
          for (const a of e.args) this.leaves(a, env, out, depth + 1);
          break;
        }
        if (this.ctx.witnesses.has(name)) {
          out.witnesses.add(`${name}()`);
          if (!this.hashDepth) out.open.add(`${name}()`);
          else this.hashedSeen.add(`${name}()`);
          if (!this.hashDepth && !this.keyDepth) out.value.add(`${name}()`);
          if (this.keyDepth && !this.hashDepth) this.keyedSeen.add(`${name}()`);
          break;
        }
        if (name === "ownPublicKey") {
          out.ownKey = true;
          break;
        }
        if (name === "pad") {
          out.constant = true;
          break;
        }
        const hash = HASHES.has(name);
        if (hash) out.hashed = true;
        const helper = this.ctx.circuits.get(name);
        if (helper?.body) {
          const inner = this.bindParams(helper, e.args, env);
          for (const r of returns(helper.body, inner)) this.leaves(r.expr, r.env, out, depth + 1);
          break;
        }
        if (hash) this.hashDepth++;
        for (const a of e.args) this.leaves(a, env, out, depth + 1);
        if (hash) this.hashDepth--;
        break;
      }
      default:
        if (e.kind === "binary" && RELATIONAL.has(e.op)) out.relational = true;
        if (e.kind === "binary" && ARITH.has(e.op) && !this.hashDepth) {
          for (const side of [e.left, e.right]) for (const w of this.leaves(side, env, empty(), depth + 1).value) if (w.endsWith("()")) this.quantity.add(w);
        }
        for (const x of children(e)) this.leaves(x, env, out, depth + 1);
    }
    return out;
  }

  bindParams(helper: Circuit, args: Expr[], env: Env): Env {
    const inner: Env = new Map();
    helper.params.forEach((p, i) => {
      if (args[i]) inner.set(p.name, { expr: args[i], env });
    });
    return inner;
  }

  scan(body: Stmt[], env: Env, out: { checks: Check[]; sinks: Sink[]; coins: Leaves[] }, stack: string[], exported: boolean): void {
    const local: Env = new Map(env);
    for (const s of body) {
      if (s.kind === "const" && s.names.length === 1) local.set(s.names[0], { expr: s.init, env: new Map(local) });
      if (s.kind === "if") {
        out.checks.push(this.check(s.test, local, s.loc.line, true));
        this.scan(s.then, local, out, stack, exported);
        if (s.else) this.scan(s.else, local, out, stack, exported);
      } else if (s.kind === "for") this.scan(s.body, local, out, stack, exported);
      else if (s.kind === "block") this.scan(s.body, local, out, stack, exported);
      if (s.kind === "assign") {
        const f = this.rootField(s.target);
        if (f) out.sinks.push({ label: f, leaves: this.leaves(s.value, local) });
      }
      if (s.kind === "return" && s.value && exported && stack.length === 1) out.sinks.push({ label: "return value", leaves: this.leaves(s.value, local) });
      for (const e of shallowExprs(s)) {
        if (e.kind !== "call") continue;
        const name = calleeIdent(e);
        if (name === "assert" && e.args[0]) {
          out.checks.push({ ...this.check(e.args[0], local, e.loc.line, false, e.loc.col), message: e.args[1]?.kind === "string" ? e.args[1].value : "" });
          continue;
        }
        if (TOKEN_OPS.has(name)) {
          if (name.startsWith("receive")) {
            for (const a of e.args) out.coins.push(this.leaves(a, local));
            continue;
          }
          e.args.forEach((a, i) => out.sinks.push({ label: `${name} ${i === 1 ? "amount" : i === 2 ? "recipient" : "argument"}`, leaves: this.leaves(a, local) }));
          continue;
        }
        if (e.callee.kind === "member") {
          const f = this.rootField(e.callee.object);
          if (f && !LEDGER_READS.has(e.callee.property)) {
            // the first argument of insert/remove on a map or set picks the entry
            if (["insert", "remove", "insertDefault"].includes(e.callee.property) && e.args[0]) for (const w of this.leaves(e.args[0], local).open) if (w.endsWith("()")) this.keyedSeen.add(w);
            // set.insert(n) or flags.insert(n, true): a record that n was used, with nothing else stored
            if (e.callee.property === "insert" && e.args.length === 1) this.singleInserts.push({ field: f, leaves: this.leaves(e.args[0], local) });
            if (e.callee.property === "insert" && (e.args.length === 1 || (e.args.length === 2 && this.leaves(e.args[1], local).constant && !unknowns(this.leaves(e.args[1], local)).length && !this.leaves(e.args[1], local).ledger.size))) this.usedMarks.add(f);
            out.sinks.push({ label: f, leaves: e.args.map((a) => this.leaves(a, local)).reduce(merge, empty()) });
          }
          continue;
        }
        const helper = this.ctx.circuits.get(name);
        if (helper?.body && !stack.includes(name)) this.scan(helper.body, this.bindParams(helper, e.args, local), out, [...stack, name], exported);
      }
    }
  }

  private check(cond: Expr, env: Env, line: number, isIf: boolean, col = 1): Check {
    const leaves = this.leaves(cond, env);
    const strip = (e: Expr): Expr => (e.kind === "call" && calleeIdent(e) === "disclose" && e.args[0] ? strip(e.args[0]) : e);
    const equalities: [Leaves, Leaves][] = [];
    const parts = (e: Expr): Expr[] => {
      const x = strip(e);
      return x.kind === "binary" && x.op === "&&" ? [...parts(x.left), ...parts(x.right)] : [x];
    };
    let notMember: Check["notMember"];
    for (const p of parts(cond)) {
      if (p.kind === "binary" && p.op === "==") equalities.push([this.leaves(p.left, env), this.leaves(p.right, env)]);
      // !set.member(x), or set.member(x) == false
      const neg = p.kind === "unary" && p.op === "!" ? strip(p.arg) : p.kind === "binary" && p.op === "==" && p.right.kind === "ident" && p.right.name === "false" ? strip(p.left) : undefined;
      if (neg && neg.kind === "call" && neg.callee.kind === "member" && neg.callee.property === "member" && neg.args[0]) {
        const set = this.rootField(neg.callee.object);
        if (set) notMember = { set, leaves: this.leaves(neg.args[0], env) };
      }
    }
    return { line, col, leaves, relational: leaves.relational, membership: leaves.membership, isIf, equalities, notMember };
  }
}

function merge(a: Leaves, b: Leaves): Leaves {
  return {
    witnesses: new Set([...a.witnesses, ...b.witnesses]),
    params: new Set([...a.params, ...b.params]),
    ledger: new Set([...a.ledger, ...b.ledger]),
    constant: a.constant || b.constant,
    hashed: a.hashed || b.hashed,
    ownKey: a.ownKey || b.ownKey,
    relational: a.relational || b.relational,
    membership: a.membership || b.membership,
    open: new Set([...a.open, ...b.open]),
    value: new Set([...a.value, ...b.value]),
  };
}

/** Direct sub-expressions of an expression. */
function children(e: Expr): Expr[] {
  switch (e.kind) {
    case "member":
      return [e.object];
    case "index":
      return [e.object, e.index];
    case "vector":
      return e.elements;
    case "struct":
      return e.fields.map((f) => f.value);
    case "binary":
      return [e.left, e.right];
    case "unary":
    case "spread":
      return [e.arg];
    case "cast":
      return [e.expr];
    case "cond":
      return [e.test, e.then, e.else];
    default:
      return [];
  }
}

/** The expressions of one statement, without the statements nested in it (those are scanned with their own scope). */
function* shallowExprs(s: Stmt): Generator<Expr> {
  if (s.kind === "if") {
    yield* exprs(s.test);
    return;
  }
  if (s.kind === "for") {
    yield* exprs(s.iter);
    return;
  }
  if (s.kind === "block") return;
  yield* stmtExprs(s);
}

/** A helper's return values, with its locals in scope. */
function returns(body: Stmt[], env: Env): Binding[] {
  const out: Binding[] = [];
  const local: Env = new Map(env);
  const walk = (ss: Stmt[]) => {
    for (const s of ss) {
      if (s.kind === "const" && s.names.length === 1) local.set(s.names[0], { expr: s.init, env: new Map(local) });
      if (s.kind === "return" && s.value) out.push({ expr: s.value, env: new Map(local) });
      if (s.kind === "if") {
        walk(s.then);
        if (s.else) walk(s.else);
      }
      if (s.kind === "block") walk(s.body);
    }
  };
  walk(body);
  return out;
}

function moduleCircuits(program: Program): Set<string> {
  const out = new Set<string>();
  const walk = (decls: Decl[], inModule: boolean) => {
    for (const d of decls) {
      if (d.kind === "module") walk(d.decls, true);
      else if (d.kind === "circuit" && inModule) out.add(d.name);
    }
  };
  walk(program.decls, false);
  return out;
}

const unknowns = (l: Leaves) => [...l.witnesses, ...l.params];

/** The role of every witness, from how all exported circuits use it. */
export function witnessRoles(program: Program): Map<string, WitnessRole> {
  const roles = new Map<string, WitnessRole>();
  for (const c of constraintMap(program, roles)) void c;
  return roles;
}

export function constraintMap(program: Program, roles?: Map<string, WitnessRole>): CircuitConstraints[] {
  const ctx: Ctx = { ledger: new Set(), witnesses: new Set(), circuits: new Map(), enums: new Set() };
  collect(program.decls, ctx);
  const inModule = moduleCircuits(program);
  const out: CircuitConstraints[] = [];
  for (const c of ctx.circuits.values()) {
    if (!c.exported || !c.body) continue;
    const scanner = new ConstraintScanner(ctx, new Set(c.params.map((p) => p.name)));
    const found = { checks: [] as Check[], sinks: [] as Sink[], coins: [] as Leaves[] };
    scanner.scan(c.body, new Map(), found, [c.name], true);
    if (roles) {
      const role = (w: string) => {
        const name = w.slice(0, -2);
        const r = roles.get(name) ?? { quantity: false, hashed: false, publishedRaw: false, keyed: false };
        roles.set(name, r);
        return r;
      };
      for (const w of scanner.quantity) role(w).quantity = true;
      for (const w of scanner.hashedSeen) role(w).hashed = true;
      for (const w of scanner.keyedSeen) role(w).keyed = true;
      for (const sk of found.sinks) for (const w of sk.leaves.open) if (w.endsWith("()")) role(w).publishedRaw = true;
    }

    const names = new Set<string>(c.params.map((p) => p.name));
    for (const x of [...found.checks.map((k) => k.leaves), ...found.sinks.map((k) => k.leaves)]) for (const w of x.witnesses) names.add(w);

    const constraintsOf = (n: string): InputReport["constraints"] => {
      const list: InputReport["constraints"] = [];
      for (const k of found.checks) {
        if (!unknowns(k.leaves).includes(n)) continue;
        const kind: Constraint = k.membership
          ? "membership"
          : k.leaves.ledger.size
            ? "tied to ledger"
            : k.leaves.hashed
              ? "hash or signature"
              : k.leaves.constant
                ? "bounded by constant"
                : "only other prover values";
        list.push({ kind, line: k.line });
      }
      if (found.coins.some((l) => unknowns(l).includes(n))) list.push({ kind: "coin value", line: c.loc.line });
      return list;
    };

    const inputs: InputReport[] = [];
    for (const n of names) {
      const sinks = found.sinks.filter((s) => unknowns(s.leaves).includes(n));
      const reaches = [...new Set(sinks.map((s) => (s.leaves.open.has(n) ? s.label : `${s.label} (hashed)`)))];
      const hashedOnly = sinks.length > 0 && sinks.every((s) => !s.leaves.open.has(n));
      inputs.push({ name: n, kind: n.endsWith("()") ? "witness" : "parameter", reaches, hashedOnly, constraints: constraintsOf(n) });
    }

    // MS037: a relational check made only of prover-chosen values, none of which is tied to anything else
    const anchored = new Set(inputs.filter((i) => i.constraints.some((k) => k.kind !== "only other prover values")).map((i) => i.name));
    const selfSatisfiable: CircuitConstraints["selfSatisfiable"] = [];
    const effects = found.sinks.some((s) => s.label !== "return value");
    for (const k of found.checks) {
      if (k.isIf || !k.relational || k.membership || k.leaves.ledger.size || k.leaves.constant || k.leaves.hashed || k.leaves.ownKey) continue;
      const u = unknowns(k.leaves);
      if (!k.leaves.witnesses.size || u.length < 2 || u.some((n) => anchored.has(n)) || !effects) continue;
      selfSatisfiable.push({ line: k.line, col: k.col, inputs: u });
    }
    // MS038: a nullifier (assert(!used.member(n)); used.insert(n)) built from a witness that nothing pins down.
    // A value is pinned when a membership check covers it, or an equality ties it to the ledger or a
    // constant, or to values that are themselves pinned (path.leaf == key(sk) with the path in the tree).
    const freeNullifiers: CircuitConstraints["freeNullifiers"] = [];
    const candidates: { nk: Check; free: string[]; sound: boolean }[] = [];
    for (const nk of found.checks) {
      if (!nk.notMember || nk.isIf || !found.sinks.some((sk) => sk.label === nk.notMember!.set)) continue;
      // signing up a new account is open to every new secret on purpose ("user already registered")
      if (/regist|enrol|sign_?up|onboard|join|create_?account|open_?account/i.test(c.name) || /already (registered|enrolled|exists|signed up|joined)/i.test(nk.message ?? "")) continue;
      // an action paid for with a coin (a bet, a deposit) may be repeated by anyone willing to pay again
      if (found.coins.length) continue;
      // the nullifier has to guard something besides itself
      if (!found.sinks.some((sk) => sk.label !== nk.notMember!.set && sk.label !== "return value")) continue;
      const others = found.checks.filter((k) => k !== nk && !k.isIf);
      const pinned = new Set<string>();
      for (const k of others) if (k.membership) for (const n of unknowns(k.leaves)) pinned.add(n);
      for (let changed = true; changed; ) {
        changed = false;
        for (const k of others) {
          for (const [a, b] of k.equalities) {
            for (const [x, y] of [[a, b], [b, a]] as const) {
              const ux = unknowns(x);
              if ((ux.length === 0 && (x.ledger.size || x.constant)) || (ux.length > 0 && ux.every((n) => pinned.has(n)))) {
                for (const n of unknowns(y)) if (!pinned.has(n)) {
                  pinned.add(n);
                  changed = true;
                }
              }
            }
          }
        }
      }
      // the nullifier's inputs, and the values tied to them by an equality (publicNullifier == hash(sk, root))
      const linked = new Set(unknowns(nk.notMember.leaves));
      for (let changed = true; changed; ) {
        changed = false;
        for (const k of others) for (const [a, b] of k.equalities) {
          const ua = unknowns(a), ub = unknowns(b);
          if (ua.some((n) => linked.has(n)) || ub.some((n) => linked.has(n))) for (const n of [...ua, ...ub]) if (!linked.has(n)) {
            linked.add(n);
            changed = true;
          }
        }
      }
      const free = [...linked].filter((n) => n.endsWith("()") && !pinned.has(n));
      // a nullifier that mixes a pinned secret with a free request id (requestNullifier(sk, rid)) is a
      // per-request token on purpose; only one where nothing at all is pinned lets anyone start over
      const linkedWitnesses = [...linked].filter((n) => n.endsWith("()"));
      const nothingPinned = !linkedWitnesses.some((n) => pinned.has(n));
      // flags only checks on a set that just records use; a key registry (the same value also added
      // to another set or tree, registerKey(): one entry per new key) is open to new values on purpose
      const mine = unknowns(nk.notMember.leaves);
      const registry = scanner.singleInserts.some((x) => x.field !== nk.notMember!.set && mine.length > 0 && mine.every((n) => unknowns(x.leaves).includes(n)));
      candidates.push({ nk, free: scanner.usedMarks.has(nk.notMember.set) && !registry && nothingPinned ? free : [], sound: linkedWitnesses.length > 0 && linkedWitnesses.every((n) => pinned.has(n)) });
    }
    // another once-only check in the same circuit whose value is pinned (a payroll row claimed once)
    // already stops the repeat
    if (!candidates.some((x) => x.sound)) for (const { nk, free } of candidates) if (free.length) freeNullifiers.push({ line: nk.line, col: nk.col, set: nk.notMember!.set, inputs: free });
    out.push({ name: c.name, line: c.loc.line, module: inModule.has(c.name), inputs, selfSatisfiable, freeNullifiers });
  }
  return out;
}

export function checkFreeNullifiers(program: Program): RawFinding[] {
  const out: RawFinding[] = [];
  const seen = new Set<number>();
  for (const c of constraintMap(program)) {
    if (c.module) continue;
    for (const f of c.freeNullifiers) {
      if (seen.has(f.line)) continue;
      seen.add(f.line);
      const list = f.inputs.map((n) => `'${n}'`).join(", ");
      out.push({
        ruleId: "MS038",
        severity: "high",
        confidence: "medium",
        loc: { line: f.line, col: f.col },
        message: `In '${c.name}', the nullifier checked against '${f.set}' is built from ${list}, and nothing else in the circuit pins ${f.inputs.length > 1 ? "them" : "it"} down: no membership proof covers ${f.inputs.length > 1 ? "them" : "it"}, and no equality ties ${f.inputs.length > 1 ? "them" : "it"} to the ledger. The prover can return a new value and get a new nullifier every time, so the "once only" check does not hold (the bug class behind double spends in Aztec 2.0 and StealthDrop). Derive the nullifier from a secret that a membership proof or an owner check already binds, plus fixed context.`,
      });
    }
  }
  return out;
}

export function checkSelfSatisfiable(program: Program): RawFinding[] {
  const out: RawFinding[] = [];
  const seen = new Set<number>();
  for (const c of constraintMap(program)) {
    if (c.module) continue;
    for (const s of c.selfSatisfiable) {
      if (seen.has(s.line)) continue;
      seen.add(s.line);
      const list = s.inputs.map((n) => `'${n}'`).join(", ");
      out.push({
        ruleId: "MS037",
        severity: "high",
        confidence: "medium",
        loc: { line: s.line, col: s.col },
        message: `In '${c.name}', every value in this check (${list}) is chosen by the prover: witness results and the circuit's own parameters, with no ledger state, constant or hash in it. The prover can always pick values that pass, so it constrains nothing. Compare at least one of them with something the prover does not choose: a ledger value (an oracle price, a stored balance), a constant limit, or a value tied to the ledger by another check.`,
      });
    }
  }
  return out;
}
