// Data-flow analyzer for Compact.
//
// Every expression evaluates to an `Info` that describes where its value comes
// from (witnesses, private parameters, public ledger state, constants) and how
// much secret entropy it carries. Calls to circuits defined in the same file are
// evaluated inline with the caller's argument infos, so flows through helper
// circuits are followed. Rules hook into this walk.

import type { Decl, Expr, Loc, Param, Program, Stmt, TypeRef } from "./ast.js";
import { RULES_BY_ID, type Severity } from "./rules.js";

export interface RawFinding {
  ruleId: string;
  severity: Severity;
  message: string;
  loc: Loc;
}

interface Info {
  /** "w:<witness>", "p:<param>", "l:<ledger>", "ownpk" */
  sources: Set<string>;
  /** witnesses whose raw (not hashed or committed) value flows into this value */
  rawWitness: Set<string>;
  /** built only from literals, pad(), default<>, enum members */
  constant: boolean;
  /** this value is ownPublicKey() itself (possibly wrapped), not a hash of it */
  ownpkDirect: boolean;
  /** estimated secret entropy in bits; public and constant parts count as 0; undefined = unknown */
  bits: number | undefined;
  /** location of a hash of only low-entropy private values that this value derives from */
  lowHash?: Loc;
  lowHashBits?: number;
  type?: TypeRef;
}

const HASH_FNS = new Set(["persistentHash", "transientHash"]);
const COMMIT_FNS = new Set(["persistentCommit", "transientCommit"]);
const WRAPPER_FNS = new Set(["left", "right", "some", "disclose"]);
const LEDGER_READ_METHODS = new Set(["member", "read", "lookup", "size", "isEmpty", "checkRoot", "isFull", "head", "length", "first", "root", "history"]);
const LOW_ENTROPY_BITS = 32;
const STRONG_RANDOMNESS_BITS = 128;
const MAX_INLINE_DEPTH = 4;

function empty(): Info {
  return { sources: new Set(), rawWitness: new Set(), constant: true, ownpkDirect: false, bits: 0 };
}

function unknown(): Info {
  return { sources: new Set(), rawWitness: new Set(), constant: false, ownpkDirect: false, bits: undefined };
}

function union(infos: Info[]): Info {
  const out = empty();
  for (const i of infos) {
    i.sources.forEach((s) => out.sources.add(s));
    i.rawWitness.forEach((s) => out.rawWitness.add(s));
    out.constant = out.constant && i.constant;
    out.ownpkDirect = out.ownpkDirect || i.ownpkDirect;
    out.bits = out.bits === undefined || i.bits === undefined ? undefined : out.bits + i.bits;
    if (!out.lowHash && i.lowHash) {
      out.lowHash = i.lowHash;
      out.lowHashBits = i.lowHashBits;
    }
  }
  return out;
}

function isPrivate(i: Info): boolean {
  for (const s of i.sources) if (s.startsWith("w:") || s.startsWith("p:")) return true;
  return false;
}

interface Scope {
  vars: Map<string, Info>;
}

interface Frame {
  name: string;
  scopes: Scope[];
  silent: boolean;
  depth: number;
  stack: string[];
  returns: Info[];
  /** set when an ownPublicKey() comparison happens while silent (inside an inlined helper) */
  ownpkCompare?: Loc;
  /** randomness expressions used by commitments in this function, for reuse detection */
  commitRand: Map<string, { loc: Loc; value: string }>;
  /** name prefix of the module whose code is running (for imported modules) */
  prefix: string;
  /** when running code from another file: the call site in the analyzed file */
  anchor?: Loc;
}

/** Resolves an `import "path"` or `include "path"` to a parsed program. */
export type ImportResolver = (fromFile: string | undefined, target: string) => { file: string; program: Program } | undefined;

interface CircuitEntry {
  decl: Extract<Decl, { kind: "circuit" }>;
  prefix: string;
  external: boolean;
}

const MAX_IMPORT_DEPTH = 6;

export class Analyzer {
  private ledgers = new Map<string, TypeRef>();
  private witnesses = new Map<string, Extract<Decl, { kind: "witness" }>>();
  private circuits = new Map<string, CircuitEntry>();
  private visitedFiles = new Set<string>();
  private enums = new Map<string, number>();
  private structs = new Map<string, Param[]>();
  private aliases = new Map<string, TypeRef>();

  private findings: RawFinding[] = [];
  private seen = new Set<string>();
  private constrainedWitnesses = new Set<string>();
  private witnessSinks = new Map<string, Loc>();
  private hashSites = new Map<string, { loc: Loc; tagged: boolean; private: boolean }>();

  constructor(
    private program: Program,
    private resolver?: ImportResolver,
    private file?: string,
  ) {
    if (file) this.visitedFiles.add(file);
    this.collect(program.decls, "", false, 0, file);
  }

  /**
   * Register declarations. Imported modules are registered under their import
   * prefix (e.g. `Utils_hash`) so calls from the analyzed file resolve, and
   * marked external: they are followed when called, but not reported on.
   */
  private collect(decls: Decl[], prefix: string, external: boolean, depth: number, file: string | undefined): void {
    const setType = <T>(map: Map<string, T>, name: string, value: T) => {
      map.set(prefix + name, value);
      if (prefix && !map.has(name)) map.set(name, value);
    };
    for (const d of decls) {
      switch (d.kind) {
        case "ledger":
          this.ledgers.set(prefix + d.name, d.type);
          break;
        case "witness":
          this.witnesses.set(prefix + d.name, d);
          break;
        case "circuit":
          this.circuits.set(prefix + d.name, { decl: d, prefix, external });
          break;
        case "enum":
          setType(this.enums, d.name, d.members.length);
          break;
        case "struct":
          setType(this.structs, d.name, d.fields);
          break;
        case "typeAlias":
          setType(this.aliases, d.name, d.type);
          break;
        case "module":
          this.collect(d.decls, prefix, external, depth, file);
          break;
        case "import":
        case "include": {
          if (!this.resolver || depth >= MAX_IMPORT_DEPTH) break;
          if (d.kind === "import" && !d.isPath) break; // standard library or a module in this file
          const target = d.kind === "import" ? d.target : d.path;
          const resolved = this.resolver(file, target);
          if (!resolved || this.visitedFiles.has(resolved.file + "|" + prefix)) break;
          this.visitedFiles.add(resolved.file + "|" + prefix);
          const nextPrefix = d.kind === "import" ? prefix + d.prefix : prefix;
          this.collect(resolved.program.decls, nextPrefix, true, depth + 1, resolved.file);
          break;
        }
      }
    }
  }

  /** Resolve a name used inside code of the module with `frame.prefix`. */
  private resolveName<T>(map: Map<string, T>, name: string, frame: Frame): string | undefined {
    if (frame.prefix && map.has(frame.prefix + name)) return frame.prefix + name;
    return map.has(name) ? name : undefined;
  }

  run(): RawFinding[] {
    for (const d of this.program.diagnostics) {
      this.report("MS000", d.loc, `Could not parse this part of the file (${d.message}); it was skipped.`);
    }
    if (!this.program.decls.some((d) => d.kind === "pragma")) {
      this.report("MS006", { line: 1, col: 1 }, "No `pragma language_version` declared. Pin the Compact language version this contract was written for.");
    }
    this.analyzeDecls(this.program.decls);

    for (const site of this.hashSites.values()) {
      if (site.private && !site.tagged) {
        this.report(
          "MS005",
          site.loc,
          "This hash has no constant domain tag. If the same secret is hashed elsewhere (or in another contract), the outputs can be linked. Add a tag such as pad(32, \"myapp:purpose:\") as the first input.",
        );
      }
    }

    for (const [w, loc] of this.witnessSinks) {
      if (!this.constrainedWitnesses.has(w) && this.isFactualWitness(w)) {
        this.report(
          "MS002",
          loc,
          `Witness '${w}()' reaches public state here, but no assert anywhere constrains its value. The prover controls witness results, so check them (range, membership, or relation to ledger state) before trusting them.`,
        );
      }
    }
    return this.findings;
  }

  /**
   * MS002 targets witnesses that report facts (amounts, flags, states, records).
   * Free-form user input (Bytes, Opaque) and randomness are expected to be
   * unconstrained, so they are skipped to avoid noise.
   */
  private isFactualWitness(name: string): boolean {
    if (/rand|salt|nonce|seed|entropy|blind/i.test(name)) return false;
    const t = this.witnesses.get(name)?.returnType;
    return t !== undefined && this.isFactualType(t, 0);
  }

  private isFactualType(t: TypeRef, depth: number): boolean {
    if (depth > 6) return false;
    if (["Boolean", "Uint", "Field"].includes(t.name)) return true;
    if (this.enums.has(t.name)) return true;
    if (this.aliases.has(t.name)) return this.isFactualType(this.aliases.get(t.name)!, depth + 1);
    if (t.name === "[]") return t.args.some((a) => a.kind === "type" && this.isFactualType(a.type, depth + 1));
    if (this.structs.has(t.name)) return this.structs.get(t.name)!.some((f) => f.type !== undefined && this.isFactualType(f.type, depth + 1));
    return false;
  }

  private analyzeDecls(decls: Decl[]): void {
    for (const d of decls) {
      if (d.kind === "module") this.analyzeDecls(d.decls);
      if (d.kind === "constructor") this.analyzeFunction("constructor", d.params, d.body);
      if (d.kind === "circuit" && d.body) this.analyzeFunction(d.name, d.params, d.body);
    }
  }

  private analyzeFunction(name: string, params: Param[], body: Stmt[]): void {
    const vars = new Map<string, Info>();
    for (const p of params) vars.set(p.name, this.paramInfo(p));
    const frame: Frame = { name, scopes: [{ vars }], silent: false, depth: 0, stack: [name], returns: [], commitRand: new Map(), prefix: "" };
    this.execBlock(body, frame);
  }

  private paramInfo(p: Param): Info {
    return {
      sources: new Set([`p:${p.name}`]),
      rawWitness: new Set(),
      constant: false,
      ownpkDirect: false,
      bits: this.typeBits(p.type),
      type: p.type,
    };
  }

  // ---------- reporting ----------

  private report(ruleId: string, loc: Loc, message: string, severity?: Severity): void {
    const key = `${ruleId}:${loc.line}:${loc.col}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const meta = RULES_BY_ID.get(ruleId)!;
    this.findings.push({ ruleId, severity: severity ?? meta.severity, message, loc });
  }

  // ---------- types ----------

  private typeBits(t: TypeRef | undefined, depth = 0): number | undefined {
    if (!t || depth > 8) return undefined;
    const num = (i: number) => {
      const a = t.args[i];
      return a && a.kind === "number" ? a.value : undefined;
    };
    switch (t.name) {
      case "Boolean":
        return 1;
      case "Field":
        return 254;
      case "Uint": {
        const a = t.args[0];
        if (a?.kind === "number") return a.value;
        if (a?.kind === "range") return Math.max(1, Math.ceil(Math.log2(Math.max(2, a.to - a.from))));
        return undefined;
      }
      case "Bytes": {
        const n = num(0);
        return n === undefined ? undefined : n * 8;
      }
      case "Vector": {
        const n = num(0);
        const inner = t.args[1];
        if (n === undefined || inner?.kind !== "type") return undefined;
        const b = this.typeBits(inner.type, depth + 1);
        return b === undefined ? undefined : n * b;
      }
      case "[]": {
        let sum = 0;
        for (const a of t.args) {
          if (a.kind !== "type") return undefined;
          const b = this.typeBits(a.type, depth + 1);
          if (b === undefined) return undefined;
          sum += b;
        }
        return sum;
      }
      case "ZswapCoinPublicKey":
      case "ContractAddress":
      case "UserAddress":
        return 256;
    }
    if (this.enums.has(t.name)) return Math.max(1, Math.ceil(Math.log2(this.enums.get(t.name)!)));
    if (this.aliases.has(t.name)) return this.typeBits(this.aliases.get(t.name), depth + 1);
    if (this.structs.has(t.name)) {
      let sum = 0;
      for (const f of this.structs.get(t.name)!) {
        const b = this.typeBits(f.type, depth + 1);
        if (b === undefined) return undefined;
        sum += b;
      }
      return sum;
    }
    return undefined;
  }

  // ---------- statements ----------

  private lookup(name: string, frame: Frame): Info | undefined {
    for (let i = frame.scopes.length - 1; i >= 0; i--) {
      const v = frame.scopes[i].vars.get(name);
      if (v) return v;
    }
    return undefined;
  }

  private execBlock(body: Stmt[], frame: Frame): void {
    frame.scopes.push({ vars: new Map() });
    for (const s of body) this.execStmt(s, frame);
    frame.scopes.pop();
  }

  private execStmt(s: Stmt, frame: Frame): void {
    const scope = frame.scopes[frame.scopes.length - 1];
    switch (s.kind) {
      case "const": {
        const info = this.evalExpr(s.init, frame);
        if (s.type) info.type = s.type;
        for (const n of s.names) scope.vars.set(n, info);
        break;
      }
      case "assign": {
        const value = this.evalExpr(s.value, frame);
        this.evalExpr(s.target, frame);
        const root = rootIdent(s.target);
        if (root && !this.lookup(root, frame) && this.resolveName(this.ledgers, root, frame)) this.sink(value, s.loc, frame);
        break;
      }
      case "if": {
        const test = this.evalExpr(s.test, frame);
        this.markConstrained(test);
        this.execBlock(s.then, frame);
        if (s.else) this.execBlock(s.else, frame);
        break;
      }
      case "for": {
        const iter = this.evalExpr(s.iter, frame);
        frame.scopes.push({ vars: new Map([[s.name, { ...iter, sources: new Set(iter.sources), rawWitness: new Set(iter.rawWitness) }]]) });
        for (const st of s.body) this.execStmt(st, frame);
        frame.scopes.pop();
        break;
      }
      case "return": {
        if (s.value) frame.returns.push(this.evalExpr(s.value, frame));
        break;
      }
      case "expr":
        this.evalExpr(s.expr, frame);
        break;
      case "block":
        this.execBlock(s.body, frame);
        break;
    }
  }

  private markConstrained(info: Info): void {
    for (const s of info.sources) if (s.startsWith("w:")) this.constrainedWitnesses.add(s.slice(2));
    for (const w of info.rawWitness) this.constrainedWitnesses.add(w);
  }

  /** A value becomes public here (disclose() or a ledger write). */
  private sink(info: Info, loc: Loc, frame: Frame): void {
    for (const w of info.rawWitness) if (!this.witnessSinks.has(w)) this.witnessSinks.set(w, frame.anchor ?? loc);
    if (info.lowHash && !frame.silent) {
      this.report(
        "MS003",
        info.lowHash,
        `This hash only covers low-entropy private values (about ${info.lowHashBits ?? "?"} bit${info.lowHashBits === 1 ? "" : "s"} of entropy), and it is made public. Anyone can hash every possible input and recover the value. Use persistentCommit(value, randomness) with fresh 32-byte randomness instead.`,
      );
    }
  }

  // ---------- expressions ----------

  private evalExpr(e: Expr, frame: Frame): Info {
    switch (e.kind) {
      case "number":
      case "string":
        return empty();
      case "ident":
        return this.evalIdent(e.name, frame);
      case "member": {
        if (e.object.kind === "ident" && this.enums.has(e.object.name)) return empty();
        const obj = this.evalExpr(e.object, frame);
        return { ...obj, sources: new Set(obj.sources), rawWitness: new Set(obj.rawWitness), type: undefined };
      }
      case "index": {
        const obj = this.evalExpr(e.object, frame);
        const idx = this.evalExpr(e.index, frame);
        const out = union([obj, idx]);
        out.ownpkDirect = obj.ownpkDirect;
        return out;
      }
      case "vector":
        return union(e.elements.map((x) => this.evalExpr(x, frame)));
      case "struct":
        return union(e.fields.map((f) => this.evalExpr(f.value, frame)));
      case "spread":
        return this.evalExpr(e.arg, frame);
      case "unary": {
        const a = this.evalExpr(e.arg, frame);
        return { ...a, ownpkDirect: false };
      }
      case "cast": {
        const a = this.evalExpr(e.expr, frame);
        const tb = this.typeBits(e.type);
        const bits = a.bits === undefined ? tb : tb === undefined ? a.bits : Math.min(a.bits, tb);
        return { ...a, bits, type: e.type };
      }
      case "cond":
        return union([this.evalExpr(e.test, frame), this.evalExpr(e.then, frame), this.evalExpr(e.else, frame)]);
      case "binary": {
        const l = this.evalExpr(e.left, frame);
        const r = this.evalExpr(e.right, frame);
        // Comparing ownPublicKey() to a stored or supplied key is authorization;
        // comparing it to a constant (e.g. the zero key) is only a sanity check.
        if ((e.op === "==" || e.op === "!=") && ((l.ownpkDirect && !r.constant) || (r.ownpkDirect && !l.constant))) {
          this.ownpkCompare(l.ownpkDirect ? e.left.loc : e.right.loc, frame);
        }
        const out = union([l, r]);
        out.ownpkDirect = false;
        if (["==", "!=", "<", "<=", ">", ">=", "&&", "||"].includes(e.op)) out.bits = isPrivate(out) ? 1 : 0;
        return out;
      }
      case "lambda": {
        // Evaluated by the enclosing call (fold/map); standalone it carries no data.
        return unknown();
      }
      case "call":
        return this.evalCall(e, frame);
    }
  }

  private evalIdent(name: string, frame: Frame): Info {
    const local = this.lookup(name, frame);
    if (local) return local;
    if (name === "true" || name === "false" || name === "default") return empty();
    const ledger = this.resolveName(this.ledgers, name, frame);
    if (ledger) {
      return { sources: new Set([`l:${ledger}`]), rawWitness: new Set(), constant: false, ownpkDirect: false, bits: 0, type: this.ledgers.get(ledger) };
    }
    if (this.enums.has(name)) return empty();
    return unknown();
  }

  private ownpkCompare(loc: Loc, frame: Frame): void {
    if (frame.silent) {
      frame.ownpkCompare = frame.ownpkCompare ?? loc;
      return;
    }
    this.report(
      "MS001",
      loc,
      "ownPublicKey() is used to authorize the caller. It is supplied by the prover, so anyone can supply the stored key and pass this check. Prove knowledge of a secret instead: store hash(domain, secret) on the ledger and recompute it from a witness.",
    );
  }

  private evalCall(e: Extract<Expr, { kind: "call" }>, frame: Frame): Info {
    const callee = e.callee;

    // method call: x.method(args)
    if (callee.kind === "member") {
      const obj = this.evalExpr(callee.object, frame);
      const args = e.args.map((a) => this.evalExpr(a, frame));
      const root = rootIdent(callee.object);
      const isLedger = root !== undefined && !this.lookup(root, frame) && this.resolveName(this.ledgers, root, frame) !== undefined;
      if (isLedger) {
        if (callee.property === "member" && args.some((a) => a.ownpkDirect)) this.ownpkCompare(e.loc, frame);
        if (LEDGER_READ_METHODS.has(callee.property)) {
          const out = union([obj, ...args]);
          out.rawWitness = new Set();
          out.bits = callee.property === "member" ? (args.some(isPrivate) ? 1 : 0) : 0;
          out.ownpkDirect = false;
          return out;
        }
        // ledger write: insert, increment, write, push, ...
        for (const a of args) this.sink(a, e.loc, frame);
        return empty();
      }
      const out = union([obj, ...args]);
      out.ownpkDirect = false;
      return out;
    }

    const name = callee.kind === "ident" ? callee.name : undefined;

    if (name === "ownPublicKey") {
      return { sources: new Set(["ownpk"]), rawWitness: new Set(), constant: false, ownpkDirect: true, bits: 0 };
    }
    if (name === "pad" || name === "default") return empty();
    if (name === "assert") {
      const infos = e.args.map((a) => this.evalExpr(a, frame));
      if (infos[0]) this.markConstrained(infos[0]);
      return empty();
    }

    // lambdas passed to fold/map: bind their parameters to the data being iterated
    const lambdas = e.args.filter((a): a is Extract<Expr, { kind: "lambda" }> => a.kind === "lambda");
    const plain = e.args.filter((a) => a.kind !== "lambda").map((a) => this.evalExpr(a, frame));
    if (lambdas.length) {
      const data = union(plain);
      const results = lambdas.map((l) => this.evalLambda(l, data, frame));
      return union([...plain, ...results]);
    }

    const witnessName = name ? this.resolveName(this.witnesses, name, frame) : undefined;
    if (witnessName) {
      const w = this.witnesses.get(witnessName)!;
      return {
        sources: new Set([`w:${witnessName}`]),
        rawWitness: new Set([witnessName]),
        constant: false,
        ownpkDirect: false,
        bits: this.typeBits(w.returnType),
        type: w.returnType,
      };
    }

    if (name && HASH_FNS.has(name)) return this.evalHash(e, plain, frame);
    if (name && COMMIT_FNS.has(name)) return this.evalCommit(e, plain, frame);

    if (name === "disclose") {
      const v = plain[0] ?? empty();
      this.sink(v, e.loc, frame);
      // After disclose() the value is public: it carries no secret entropy.
      const sources = new Set([...v.sources].filter((x) => !x.startsWith("w:") && !x.startsWith("p:")));
      sources.add("disclosed");
      return { ...v, sources, bits: 0, lowHash: undefined };
    }

    if (name && WRAPPER_FNS.has(name)) return union(plain);

    const circuitName = name ? this.resolveName(this.circuits, name, frame) : undefined;
    if (circuitName) return this.inlineCircuit(circuitName, plain, e.loc, frame);

    // unknown or standard-library call
    const out = union(plain);
    out.ownpkDirect = false;
    out.bits = out.bits === undefined ? undefined : out.bits;
    return out;
  }

  private evalLambda(l: Extract<Expr, { kind: "lambda" }>, data: Info, frame: Frame): Info {
    const vars = new Map<string, Info>();
    for (const p of l.params) vars.set(p.name, data);
    frame.scopes.push({ vars });
    let result: Info;
    if (Array.isArray(l.body)) {
      const before = frame.returns.length;
      for (const s of l.body) this.execStmt(s, frame);
      result = union(frame.returns.splice(before));
    } else {
      result = this.evalExpr(l.body, frame);
    }
    frame.scopes.pop();
    return result;
  }

  /** Flatten the inputs of a hash: vector literals and struct literals become their elements. */
  private hashInputs(e: Expr): Expr[] {
    if (e.kind === "vector") return e.elements.flatMap((x) => this.hashInputs(x));
    if (e.kind === "struct") return e.fields.flatMap((f) => this.hashInputs(f.value));
    return [e];
  }

  private evalHash(e: Extract<Expr, { kind: "call" }>, argInfos: Info[], frame: Frame): Info {
    const inputs = e.args.flatMap((a) => this.hashInputs(a));
    const infos = inputs.map((x) => this.evalExpr(x, frame));
    const all = union(infos.length ? infos : argInfos);

    // MS005: decided at the end, because a helper circuit may receive its tag
    // as an argument from the caller (seen when the helper is inlined).
    if (!frame.anchor) {
      const key = `${e.loc.line}:${e.loc.col}`;
      const site = this.hashSites.get(key) ?? { loc: e.loc, tagged: false, private: false };
      if (infos.some((i) => i.constant)) site.tagged = true;
      if (isPrivate(all)) site.private = true;
      this.hashSites.set(key, site);
    }

    const out: Info = {
      sources: new Set(all.sources),
      rawWitness: new Set(),
      constant: all.constant,
      ownpkDirect: false,
      bits: all.bits === undefined ? undefined : Math.min(all.bits, 256),
    };

    // MS003 candidate: every input is constant, public, or low-entropy. If a
    // high-entropy secret is mixed in, the result is safe even when an input
    // was itself a low-entropy hash.
    if (isPrivate(all) && all.bits !== undefined && all.bits <= LOW_ENTROPY_BITS) {
      out.lowHash = all.lowHash ?? frame.anchor ?? e.loc;
      out.lowHashBits = all.bits;
    }
    return out;
  }

  private evalCommit(e: Extract<Expr, { kind: "call" }>, argInfos: Info[], frame: Frame): Info {
    const value = argInfos[0] ?? empty();
    const rand = argInfos[1] ?? unknown();
    const randExpr = e.args[1];

    if (!frame.silent && randExpr) {
      if (rand.constant) {
        this.report(
          "MS004",
          e.loc,
          "This commitment uses constant randomness, so it hides nothing: anyone can recompute it for every candidate value. Use fresh random bytes from a witness.",
        );
      } else if (rand.sources.size > 0 && !isPrivate(rand)) {
        this.report(
          "MS004",
          e.loc,
          "This commitment's randomness comes from public ledger state, so anyone can recompute the commitment for every candidate value. Use secret randomness from a witness or private input.",
        );
      } else if (rand.bits !== undefined && rand.bits < STRONG_RANDOMNESS_BITS) {
        this.report(
          "MS004",
          e.loc,
          `This commitment's randomness has only about ${rand.bits} bits of entropy. Use at least 32 random bytes (Bytes<32>).`,
        );
      } else {
        const key = exprText(randExpr);
        const valueKey = exprText(e.args[0]);
        const prev = frame.commitRand.get(key);
        if (prev && prev.value !== valueKey) {
          this.report(
            "MS004",
            e.loc,
            `The same randomness '${key}' is used by another commitment on line ${prev.loc.line}. Reusing randomness lets observers link the two commitments. Derive separate randomness for each (e.g. hash(tag, salt)).`,
            "medium",
          );
        } else if (!prev) {
          frame.commitRand.set(key, { loc: e.loc, value: valueKey });
        }
      }
    }

    // A commitment with good randomness hides the value; its entropy is not reversible.
    return {
      sources: new Set([...value.sources, ...rand.sources]),
      rawWitness: new Set(),
      constant: false,
      ownpkDirect: false,
      bits: undefined,
    };
  }

  private inlineCircuit(name: string, args: Info[], loc: Loc, frame: Frame): Info {
    const entry = this.circuits.get(name)!;
    const c = entry.decl;
    if (!c.body || frame.depth >= MAX_INLINE_DEPTH || frame.stack.includes(name)) {
      const out = union(args);
      out.ownpkDirect = false;
      out.rawWitness = new Set();
      return out;
    }
    const vars = new Map<string, Info>();
    c.params.forEach((p, i) => {
      const a = args[i] ?? unknown();
      vars.set(p.name, { ...a, type: p.type ?? a.type });
    });
    const inner: Frame = {
      name,
      scopes: [{ vars }],
      silent: true,
      depth: frame.depth + 1,
      stack: [...frame.stack, name],
      returns: [],
      commitRand: new Map(),
      prefix: entry.prefix,
      anchor: frame.anchor ?? (entry.external ? loc : undefined),
    };
    for (const s of c.body) this.execStmt(s, inner);
    if (inner.ownpkCompare) {
      if (frame.silent) frame.ownpkCompare = frame.ownpkCompare ?? loc;
      else
        this.report(
          "MS001",
          loc,
          `ownPublicKey() is passed to '${name}()', which compares it to authorize the caller (${inner.anchor ? "in an imported module" : `line ${inner.ownpkCompare.line}`}). It is supplied by the prover, so this check can be bypassed. Prove knowledge of a secret instead.`,
        );
    }
    const ret = inner.returns.length ? union(inner.returns) : empty();
    if (c.returnType) {
      const tb = this.typeBits(c.returnType);
      if (ret.bits !== undefined && tb !== undefined) ret.bits = Math.min(ret.bits, tb);
      ret.type = c.returnType;
    }
    return ret;
  }
}

function rootIdent(e: Expr): string | undefined {
  if (e.kind === "ident") return e.name;
  if (e.kind === "member" || e.kind === "index") return rootIdent(e.object);
  return undefined;
}

export function exprText(e: Expr): string {
  switch (e.kind) {
    case "ident":
      return e.name;
    case "number":
      return e.value;
    case "string":
      return JSON.stringify(e.value);
    case "member":
      return `${exprText(e.object)}.${e.property}`;
    case "index":
      return `${exprText(e.object)}[${exprText(e.index)}]`;
    case "call":
      return `${exprText(e.callee)}(${e.args.map(exprText).join(", ")})`;
    case "vector":
      return `[${e.elements.map(exprText).join(", ")}]`;
    case "struct":
      return `${e.type.name} { ${e.fields.map((f) => `${f.name}: ${exprText(f.value)}`).join(", ")} }`;
    case "binary":
      return `${exprText(e.left)} ${e.op} ${exprText(e.right)}`;
    case "unary":
      return `${e.op}${exprText(e.arg)}`;
    case "cast":
      return `${exprText(e.expr)} as ${e.type.text}`;
    case "cond":
      return `${exprText(e.test)} ? ${exprText(e.then)} : ${exprText(e.else)}`;
    case "spread":
      return `...${exprText(e.arg)}`;
    case "lambda":
      return "(lambda)";
  }
}
