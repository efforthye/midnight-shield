// Access map: for every exported circuit, who can call it, what it checks,
// which ledger fields it changes and which tokens it moves. This is the Compact
// counterpart of Slither's vars-and-auth printer.
//
// On top of the map, MS035 (inconsistent-guard) looks for a ledger field that
// one circuit protects with a caller check and another circuit changes with no
// caller check at all (Slither's protected-vars idea, without annotations: the
// guarded writer is the annotation).

import { Analyzer, type ImportResolver, type RawFinding } from "./analyzer.js";
import type { Decl, Expr, Program, Stmt } from "./ast.js";
import { collect, exprs, stmtExprs, stmts, type Ctx } from "./auth-writes.js";

type Circuit = Extract<Decl, { kind: "circuit" }>;
type Call = Extract<Expr, { kind: "call" }>;

export type GuardKind =
  | "secret" // a stored value compared with a hash of the caller's secret
  | "allow-list" // membership of a caller identity in a ledger set or map
  | "signature" // a signature checked in the circuit
  | "merkle" // a Merkle membership proof
  | "caller-key" // ownPublicKey() compared with a stored key (MS001)
  | "claimed-id" // a stored id compared with a parameter: the caller just claims to be the owner (MS036)
  | "witness-result" // the result of a witness, decided by the prover (MS013)
  | "imported" // a call into code this file cannot see, such as assertOnlyOwner()
  | "one-time" // assert(!set.member(x)): stops a repeat, not a stranger
  | "state" // a check on ledger state that says nothing about the caller
  | "input"; // a check on parameters and constants only

export interface Guard {
  kind: GuardKind;
  line: number;
  /** the helper circuit the check lives in, when it is not in the circuit itself */
  via?: string;
  /** the ledger fields the check reads */
  fields: string[];
  /** the rule that shows this check can be passed by anyone */
  bypass?: string;
  /** imported function name, for kind "imported" */
  callee?: string;
  /** for kind "claimed-id": the stored field and the parameter it is compared with */
  stored?: string;
  claimed?: string;
}

export type Who = "anyone" | "bypassable" | "restricted" | "imported";

export interface CircuitAccess {
  name: string;
  line: number;
  module: boolean;
  who: Who;
  guards: Guard[];
  writes: { field: string; line: number; col: number; overwrite: boolean }[];
  tokens: { op: string; line: number }[];
}

const CALLER_KINDS = new Set<GuardKind>(["secret", "allow-list", "signature", "merkle", "caller-key", "claimed-id", "witness-result", "imported"]);

/** Imported checks whose names say they are about the contract's state, not the caller. */
const STATE_CHECK = /(initiali[sz]ed|paused|whenNot|notPaused|nonReentrant|deadline|expired|open$|closed$)/i;

/** Names and assert messages that say a check is about who is calling. */
const AUTH_FIELD = /(owner|admin|authority|operator|controller|minter|governor|guardian|manager|issuer|oracle|creator|deployer|organizer|organiser|moderator|treasurer|verifier|signer)/i;
const AUTH_MESSAGE = /(owner|admin|only|authori[sz]|permission|not allowed|forbidden|access|caller|operator|issuer)/i;

/** Built-ins and standard-library functions: calling them checks nothing. */
const STDLIB = new Set([
  "disclose", "pad", "persistentHash", "persistentCommit", "transientHash", "transientCommit",
  "degradeToTransient", "upgradeFromTransient", "ownPublicKey", "merkleTreePathRoot",
  "merkleTreePathRootNoLeafHash", "default", "some", "none", "left", "right", "ecAdd", "ecMul",
  "ecMulGenerator", "hashToCurve", "nativeToken", "tokenType", "evolveNonce", "burnAddress",
  "shieldedBurnAddress", "createZswapInput", "createZswapOutput", "map", "fold", "slice", "assert",
  "mergeCoin", "mergeCoinImmediate", "unshieldedBalance", "unshieldedBalanceLt", "unshieldedBalanceGte",
  "unshieldedBalanceLte", "unshieldedBalanceGt", "blockTimeLessThan", "blockTimeGreaterThan",
  "blockTimeGte", "blockTimeLt", "blockTimeLte", "blockTimeGt", "jubjubSchnorrVerify", "kernel", "self",
]);
export const TOKEN_OPS = new Set([
  "send", "sendImmediate", "sendShielded", "sendImmediateShielded", "sendUnshielded",
  "mintToken", "mintShieldedToken", "mintUnshieldedToken",
  "receive", "receiveShielded", "receiveUnshielded",
]);
const WRITE_METHODS = new Set(["write", "insert", "insertDefault", "remove", "resetToDefault", "insertCoin", "increment", "decrement", "pushFront", "popFront"]);
const OVERWRITE_METHODS = new Set(["write", "resetToDefault"]);
const MERKLE_METHODS = new Set(["checkRoot", "isHistoricRoot"]);

const identName = (e: Expr): string => (e.kind === "call" && e.callee.kind === "ident" ? e.callee.name : "");

/** The ledger field at the root of an expression: `a`, `a.lookup(k)`, `a.lookup(k).read()`. */
function rootField(e: Expr, ctx: Ctx): string | undefined {
  if (e.kind === "ident") return ctx.ledger.has(e.name) ? e.name : undefined;
  if (e.kind === "member") return rootField(e.object, ctx);
  if (e.kind === "index") return rootField(e.object, ctx);
  if (e.kind === "call") return rootField(e.callee, ctx);
  return undefined;
}

const unwrap = (e: Expr): Expr => (e.kind === "call" && identName(e) === "disclose" && e.args[0] ? unwrap(e.args[0]) : e.kind === "cast" ? unwrap(e.expr) : e);

/**
 * Every sub-expression, with local constants replaced by what they were
 * computed from, so `const pk = publicKey(sk()); assert(owner == pk)` reads as
 * a comparison with a hash of a witness.
 */
function* expanded(e: Expr, env: Map<string, Expr>, seen = new Set<string>()): Generator<Expr> {
  for (const x of exprs(e)) {
    yield x;
    if (x.kind === "ident" && env.has(x.name) && !seen.has(x.name)) {
      seen.add(x.name);
      yield* expanded(env.get(x.name)!, env, seen);
    }
  }
}

interface Scan {
  guards: Guard[];
  writes: CircuitAccess["writes"];
  tokens: CircuitAccess["tokens"];
}

/** Finds an imported circuit's own access entry, so its checks can be shown in place of "imported". */
type ImportLookup = (name: string) => CircuitAccess | undefined;

class AccessScanner {
  constructor(
    private ctx: Ctx,
    private bypassLines: Map<number, string>,
    private imported: ImportLookup = () => undefined,
  ) {}

  private fieldsIn(e: Expr, env: Map<string, Expr>): string[] {
    const out = new Set<string>();
    for (const x of expanded(e, env)) {
      const f = rootField(x, this.ctx);
      if (f && x.kind === "ident") out.add(f);
    }
    return [...out];
  }

  /** Whether an expression stands for a caller: ownPublicKey(), or something computed from a witness. */
  private callerSide(e: Expr, env: Map<string, Expr>): "caller-key" | "secret" | undefined {
    // a hash of ownPublicKey() *and* a secret is as strong as the secret: only ownPublicKey() alone is forgeable
    let witness = false;
    let ownKey = false;
    const visit = (x: Expr, seen: Set<string>) => {
      if (x.kind !== "call") return;
      const n = identName(x);
      if (n === "ownPublicKey") ownKey = true;
      if (this.ctx.witnesses.has(n)) witness = true;
      // a helper such as _computeAccountId() that reads the secret itself
      const helper = this.ctx.circuits.get(n);
      if (helper && !seen.has(n)) {
        seen.add(n);
        for (const st of stmts(helper.body ?? [])) for (const y of stmtExprs(st)) visit(y, seen);
      }
    };
    const seen = new Set<string>();
    for (const x of expanded(e, env)) visit(x, seen);
    return witness ? "secret" : ownKey ? "caller-key" : undefined;
  }

  /** Only parameters and constants, passed through disclose() or a cast: a value the caller picks freely. */
  private paramOnly(e: Expr, env: Map<string, Expr>, params: Set<string>): boolean {
    let param = false;
    for (const x of expanded(e, env)) {
      if (x.kind === "call") {
        if (identName(x) !== "disclose") return false;
      } else if (x.kind === "ident") {
        if (params.has(x.name)) param = true;
        else if (x.name !== "disclose" && !env.has(x.name)) return false;
      } else if (x.kind !== "cast" && x.kind !== "number" && x.kind !== "string") return false;
    }
    return param;
  }

  private classify(cond: Expr, env: Map<string, Expr>, line: number, via: string | undefined, params = new Set<string>(), message = ""): Guard {
    const fields = this.fieldsIn(cond, env);
    const g = (kind: GuardKind): Guard => {
      const guard: Guard = { kind, line, fields };
      if (via) guard.via = via;
      const bypass = this.bypassLines.get(line);
      if (bypass && (kind === "merkle" || kind === "witness-result" || kind === "caller-key" || kind === "secret" || kind === "allow-list")) guard.bypass = bypass;
      if (kind === "caller-key") guard.bypass ??= "MS001";
      if (kind === "witness-result") guard.bypass ??= "MS013";
      return guard;
    };
    let merkle = false;
    let signature = false;
    let identity: "caller-key" | "secret" | undefined;
    let allow: "caller-key" | "secret" | undefined;
    for (const x of expanded(cond, env)) {
      if (x.kind === "call" && identName(x) === "jubjubSchnorrVerify") signature = true;
      if (x.kind === "call" && x.callee.kind === "member" && MERKLE_METHODS.has(x.callee.property) && rootField(x.callee.object, this.ctx)) merkle = true;
      if (x.kind === "binary" && (x.op === "==" || x.op === "!=")) {
        // one side stands for the caller (a witness or ownPublicKey()), the other reads the ledger.
        // The caller side may read the ledger too: publicKey(localSecretKey(), sequence)
        const lw = this.callerSide(x.left, env);
        const rw = this.callerSide(x.right, env);
        const who = lw && !rw && this.fieldsIn(x.right, env).length ? lw : rw && !lw && this.fieldsIn(x.left, env).length ? rw : undefined;
        if (who === "caller-key" || (who && !identity)) identity = who;
      }
      if (x.kind === "call" && x.callee.kind === "member" && x.callee.property === "member" && rootField(x.callee.object, this.ctx) && x.args[0]) {
        const who = this.callerSide(x.args[0], env);
        if (who === "caller-key" || (who && !allow)) allow = who;
      }
    }
    // assert(!used.member(n)) limits how often, not who: a nullifier or a "not yet" check
    const top = unwrap(cond);
    if (top.kind === "unary" && top.op === "!") {
      const inner = unwrap(top.arg);
      if (inner.kind === "call" && inner.callee.kind === "member" && inner.callee.property === "member" && rootField(inner.callee.object, this.ctx)) return g("one-time");
    }
    // path.leaf == hash(secret): the half of a Merkle proof that ties the path to the caller
    if ([...expanded(cond, env)].some((x) => x.kind === "member" && x.property === "leaf") && this.callerSide(cond, env)) merkle = true;
    // assert(ownerId == disclose(callerId)): the ledger is public, so anyone can pass the stored id as the parameter
    if (!signature && !merkle && !identity && !allow) {
      for (const x of expanded(cond, env)) {
        if (x.kind !== "binary" || (x.op !== "==" && x.op !== "!=")) continue;
        for (const [stored, claimed] of [[x.left, x.right], [x.right, x.left]] as const) {
          const f = this.fieldsIn(stored, env);
          if (f.length && !this.callerSide(stored, env) && this.paramOnly(claimed, env, params) && (f.some((n) => AUTH_FIELD.test(n)) || AUTH_MESSAGE.test(message))) {
            const guard = g("claimed-id");
            guard.bypass = "MS036";
            guard.stored = f.find((n) => AUTH_FIELD.test(n)) ?? f[0];
            guard.claimed = [...expanded(claimed, env)].find((y): y is Extract<Expr, { kind: "ident" }> => y.kind === "ident" && params.has(y.name))?.name;
            return guard;
          }
        }
      }
    }
    if (signature) return g("signature");
    if (merkle) return g("merkle");
    if (identity === "caller-key" || allow === "caller-key") return g("caller-key");
    if (identity) return g("secret");
    if (allow) return g("allow-list");
    // assert(someWitness(…)) or assert(!someWitness(…)): the prover decides the outcome
    let core = unwrap(cond);
    if (core.kind === "unary" && core.op === "!") core = unwrap(core.arg);
    if (core.kind === "call" && this.ctx.witnesses.has(identName(core))) return g("witness-result");
    if (this.bypassLines.get(line) === "MS013") return g("witness-result");
    return g(fields.length ? "state" : "input");
  }

  scan(c: Circuit, via: string | undefined, seen: Set<string>, out: Scan): void {
    if (seen.has(c.name)) return;
    seen.add(c.name);
    const env = new Map<string, Expr>();
    // parameters of a helper are whatever its caller passed, so only the exported circuit's own count
    const params = new Set(via ? [] : c.params.map((p) => p.name));
    for (const s of stmts(c.body ?? [])) {
      if (s.kind === "const" && s.names.length === 1) env.set(s.names[0], s.init);
      if (s.kind === "if") out.guards.push(this.classify(s.test, env, s.loc.line, via, params));
      if (s.kind === "assign") {
        const f = rootField(s.target, this.ctx);
        // total = total + 1 updates the value; only a write that ignores the old value replaces it
        const readsOld = [...exprs(s.value)].some((x) => rootField(x, this.ctx) === f);
        if (f) out.writes.push({ field: f, line: s.loc.line, col: s.loc.col, overwrite: s.op === "=" && s.target.kind === "ident" && !readsOld });
      }
      for (const e of stmtExprs(s)) {
        if (e.kind !== "call") continue;
        const name = identName(e);
        if (name === "assert" && e.args[0]) {
          out.guards.push(this.classify(e.args[0], env, e.loc.line, via, params, e.args[1]?.kind === "string" ? e.args[1].value : ""));
          continue;
        }
        if (TOKEN_OPS.has(name)) {
          out.tokens.push({ op: name, line: e.loc.line });
          continue;
        }
        if (e.callee.kind === "member" && WRITE_METHODS.has(e.callee.property)) {
          const f = rootField(e.callee.object, this.ctx);
          if (f) out.writes.push({ field: f, line: e.loc.line, col: e.loc.col, overwrite: OVERWRITE_METHODS.has(e.callee.property) && e.callee.object.kind === "ident" });
          continue;
        }
        if (e.callee.kind === "member") continue; // reads, enum members, struct fields
        if (this.ctx.circuits.has(name)) {
          this.scan(this.ctx.circuits.get(name)!, via ?? name, seen, out);
          continue;
        }
        if (name && !STDLIB.has(name) && !this.ctx.witnesses.has(name) && !TOKEN_OPS.has(name)) {
          // called for its effect (a statement), not for a value: it is there to check something
          const returned = s.kind === "return" && s.value === e;
          if ((s.kind === "expr" && s.expr === e) || returned) {
            const target = this.imported(name);
            if (target) {
              // the imported circuit's own checks, seen from the call site; one that checks nothing adds nothing
              for (const g of target.guards) {
                if (!CALLER_KINDS.has(g.kind)) continue;
                out.guards.push({ ...g, line: e.loc.line, via: via ?? name, callee: g.callee ?? name, fields: [] });
              }
              continue;
            }
            // `return Lib_balanceOf(x)` returns a value; only a statement call is there to check something
            if (returned) continue;
            // assertInitialized(), whenNotPaused(): checks on the contract's state, not on the caller
            const guard: Guard = { kind: STATE_CHECK.test(name) ? "state" : "imported", line: e.loc.line, fields: [], callee: name };
            if (via) guard.via = via;
            out.guards.push(guard);
          }
        }
      }
    }
  }
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

function whoCanCall(guards: Guard[]): Who {
  const caller = guards.filter((g) => CALLER_KINDS.has(g.kind));
  if (!caller.length) return "anyone";
  if (caller.some((g) => !g.bypass && g.kind !== "imported")) return "restricted";
  if (caller.some((g) => g.kind === "imported")) return "imported";
  return "bypassable";
}

/**
 * The access map of one file. `raw` are the findings already computed for the
 * file; MS001, MS009 and MS013 on a check's line mark it as one anyone can pass.
 */
export interface AccessImports {
  resolver?: ImportResolver;
  file?: string;
  /** files already on the import chain, to stop cycles */
  seen?: Set<string>;
}

const MAX_IMPORT_DEPTH = 4;

/** Look up `Prefix_name` in the module that `import "…" prefix Prefix_;` brings in. */
function importLookup(program: Program, imports: AccessImports): ImportLookup {
  const { resolver, file } = imports;
  if (!resolver) return () => undefined;
  const seen = imports.seen ?? new Set(file ? [file] : []);
  const cache = new Map<string, CircuitAccess[] | undefined>();
  const decls = program.decls.filter((d): d is Extract<Decl, { kind: "import" }> => d.kind === "import" && d.isPath);
  return (name) => {
    for (const d of decls) {
      if (!name.startsWith(d.prefix)) continue;
      if (!cache.has(d.target)) {
        const resolved = seen.size <= MAX_IMPORT_DEPTH ? resolver(file, d.target) : undefined;
        if (!resolved || seen.has(resolved.file)) cache.set(d.target, undefined);
        else {
          const raw = new Analyzer(resolved.program, resolver, resolved.file).run();
          cache.set(d.target, accessMap(resolved.program, raw, { resolver, file: resolved.file, seen: new Set([...seen, resolved.file]) }, true));
        }
      }
      const hit = cache.get(d.target)?.find((c) => c.name === name.slice(d.prefix.length));
      if (hit) return hit;
    }
    return undefined;
  };
}

export function accessMap(program: Program, raw: RawFinding[] = [], imports: AccessImports = {}, includeHelpers = false): CircuitAccess[] {
  const ctx: Ctx = { ledger: new Set(), witnesses: new Set(), circuits: new Map(), enums: new Set() };
  collect(program.decls, ctx);
  const bypassLines = new Map<number, string>();
  for (const f of raw) if (f.ruleId === "MS001" || f.ruleId === "MS009" || f.ruleId === "MS013") bypassLines.set(f.loc.line, f.ruleId);
  const inModule = moduleCircuits(program);
  const scanner = new AccessScanner(ctx, bypassLines, importLookup(program, imports));
  const out: CircuitAccess[] = [];
  for (const c of ctx.circuits.values()) {
    // inside an imported module, unexported helpers can be called too (assertOnlyOwner is often one)
    if ((!c.exported && !includeHelpers) || !c.body) continue;
    const scan: Scan = { guards: [], writes: [], tokens: [] };
    scanner.scan(c, undefined, new Set(), scan);
    out.push({ name: c.name, line: c.loc.line, module: inModule.has(c.name), who: whoCanCall(scan.guards), ...scan });
  }
  return out;
}

/** Ledger types that hold one value, so a write replaces it for everyone. */
const COLLECTIONS = new Set(["Map", "Set", "List", "MerkleTree", "HistoricMerkleTree", "Counter"]);

const GUARD_LABEL: Record<GuardKind, string> = {
  secret: "checks the caller's secret",
  "allow-list": "checks the caller against an allow-list",
  signature: "verifies a signature",
  merkle: "checks a Merkle membership proof",
  "caller-key": "compares ownPublicKey()",
  "claimed-id": "compares a stored id with a parameter",
  "witness-result": "asserts a witness result",
  imported: "calls an imported check",
  "one-time": "checks the value was not used before",
  state: "checks ledger state",
  input: "checks its inputs",
};

export function guardLabel(g: Guard): string {
  return g.kind === "imported" && g.callee ? `calls ${g.callee}()` : GUARD_LABEL[g.kind];
}

/**
 * MS035: a single-value ledger field that one exported circuit changes only
 * after a caller check, and another exported circuit overwrites with no caller
 * check. Whatever the guarded circuit protects, the other one gives away.
 */
export function checkInconsistentGuards(program: Program, raw: RawFinding[] = [], imports: AccessImports = {}): RawFinding[] {
  const single = new Set<string>();
  const walk = (decls: Decl[]) => {
    for (const d of decls) {
      if (d.kind === "ledger" && !COLLECTIONS.has(d.type.name) && !d.sealed) single.add(d.name);
      else if (d.kind === "module") walk(d.decls);
    }
  };
  walk(program.decls);
  if (!single.size) return [];
  const map = accessMap(program, raw, imports).filter((c) => !c.module && !c.name.startsWith("_"));
  const out: RawFinding[] = [];
  for (const field of single) {
    const guarded = map.filter((c) => c.who !== "anyone" && c.writes.some((w) => w.field === field));
    if (!guarded.length) continue;
    for (const c of map) {
      if (c.who !== "anyone") continue;
      const write = c.writes.find((w) => w.field === field && w.overwrite);
      if (!write) continue;
      // a state transition or a one-time setup: the circuit checks a field it also changes
      // (assert(state == Phase.open); state = Phase.closed, or assert(!initialized); initialized = true)
      const own = new Set(c.writes.map((w) => w.field));
      if (c.guards.some((g) => g.kind === "state" && g.fields.some((f) => own.has(f)))) continue;
      const g = guarded[0];
      const check = g.guards.find((x) => CALLER_KINDS.has(x.kind))!;
      out.push({
        ruleId: "MS035",
        severity: "high",
        confidence: "medium",
        loc: { line: write.line, col: write.col },
        message: `'${g.name}' ${guardLabel(check)} (line ${check.line}) before changing '${field}', but '${c.name}' overwrites '${field}' with no caller check. Anyone can call '${c.name}' and get around the check in '${g.name}'. Add the same check to '${c.name}', or make it a helper that is not exported.`,
      });
    }
  }
  return out;
}

/**
 * MS036: an "owner check" that compares a stored id with a parameter. Ledger
 * state is public, so the caller reads the owner's id and passes it in.
 */
export function checkClaimedIdentity(program: Program, raw: RawFinding[] = [], imports: AccessImports = {}): RawFinding[] {
  const out: RawFinding[] = [];
  const seen = new Set<number>();
  for (const c of accessMap(program, raw, imports)) {
    if (c.module) continue;
    // a query (no state change, no transfer) that compares an argument with the admin answers
    // "is this user the admin?", which is not an access check
    if (!c.writes.length && !c.tokens.some((t) => !t.op.startsWith("receive"))) continue;
    for (const g of c.guards) {
      if (g.kind !== "claimed-id" || seen.has(g.line)) continue;
      seen.add(g.line);
      const p = g.claimed ? `the parameter '${g.claimed}'` : "a parameter";
      out.push({
        ruleId: "MS036",
        severity: "critical",
        confidence: "medium",
        loc: { line: g.line, col: 1 },
        message: `'${c.name}' checks the caller by comparing '${g.stored}' with ${p}. Ledger values are public, so anyone can read '${g.stored}' and pass it as ${g.claimed ? `'${g.claimed}'` : "that parameter"}: the check lets everyone through. Make the caller prove knowledge of a secret instead: store hash(domain, secret) in '${g.stored}' and compare it with the same hash recomputed from a witness.`,
      });
    }
  }
  return out;
}
