// Data-flow analyzer for Compact.
//
// Every expression evaluates to an `Info` that describes where its value comes
// from (witnesses, private parameters, public ledger state, constants) and how
// much secret entropy it carries. Calls to circuits defined in the same file are
// evaluated inline with the caller's argument infos, so flows through helper
// circuits are followed. Rules hook into this walk.

import type { WitnessRole } from "./constraints.js";
import type { Decl, Expr, Loc, Param, Program, Stmt, TypeRef } from "./ast.js";
import { SUPPORTED_LANGUAGE, RULES_BY_ID, type Confidence, type Severity } from "./rules.js";
import { stmtExprs, stmts } from "./auth-writes.js";

export interface RawFinding {
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  message: string;
  loc: Loc;
  /** the engine's verdict the finding is based on, so it can be checked */
  evidence?: Evidence;
}

/** What the analysis engine concluded: which value, where it goes, which checks it passes through. */
export interface Evidence {
  circuit: string;
  /** the prover-chosen value, or the ledger field for access findings */
  value: string;
  reaches: string[];
  checks: { kind: string; line: number }[];
  verdict: string;
}

export type Protection = "raw" | "hash" | "commit" | "public" | "constant";

/** A point where data becomes public: disclose(), a ledger write, or an exported circuit's return value. */
export interface DisclosureEvent {
  circuit: string;
  loc: Loc;
  via: "disclose" | "ledger write" | "return";
  /** ledger field written, when known */
  target?: string;
  /** private inputs that flow into the public value: "witness:sk", "param:amount" */
  sources: string[];
  protection: Protection;
  /** estimated secret entropy in bits (undefined = unknown or high) */
  secretBits?: number;
}

interface Info {
  /** "w:<witness>", "p:<param>", "l:<ledger>", "ownpk" */
  sources: Set<string>;
  /** witnesses whose raw (not hashed or committed) value flows into this value */
  rawWitness: Set<string>;
  /** secret-named witnesses or parameters ("w:sk", "p:secretKey") whose raw value flows into this value */
  rawSecret?: Set<string>;
  /** built only from literals, pad(), default<>, enum members */
  constant: boolean;
  /** this value is ownPublicKey() itself (possibly wrapped), not a hash of it */
  ownpkDirect: boolean;
  /** estimated secret entropy in bits; public and constant parts count as 0; undefined = unknown */
  bits: number | undefined;
  /** location of a hash of only low-entropy private values that this value derives from */
  lowHash?: Loc;
  lowHashBits?: number;
  /** the value is the output of a hash or commitment of private data */
  protection?: "hash" | "commit";
  /** MS010: a deterministic identifier derived only from secrets (hash site key) */
  identity?: string;
  type?: TypeRef;
}

const HASH_FNS = new Set(["persistentHash", "transientHash"]);
const COMMIT_FNS = new Set(["persistentCommit", "transientCommit"]);
const WRAPPER_FNS = new Set(["left", "right", "some", "disclose"]);
const LEDGER_READ_METHODS = new Set(["member", "read", "lookup", "size", "isEmpty", "checkRoot", "isFull", "head", "length", "first", "root", "history"]);
const LOW_ENTROPY_BITS = 32;
const STRONG_RANDOMNESS_BITS = 128;
const MAX_INLINE_DEPTH = 8;

function empty(): Info {
  return { sources: new Set(), rawWitness: new Set(), constant: true, ownpkDirect: false, bits: 0 };
}

function unknown(): Info {
  return { sources: new Set(), rawWitness: new Set(), constant: false, ownpkDirect: false, bits: undefined };
}

function union(infos: Info[]): Info {
  const out = empty();
  // keep the protection only if every private part shares it
  const privateParts = infos.filter((i) => isPrivate(i));
  const prot = privateParts.length && privateParts.every((i) => i.protection === privateParts[0].protection) ? privateParts[0].protection : undefined;
  for (const i of infos) {
    i.sources.forEach((s) => out.sources.add(s));
    i.rawWitness.forEach((s) => out.rawWitness.add(s));
    if (i.rawSecret?.size) {
      out.rawSecret = out.rawSecret ?? new Set();
      i.rawSecret.forEach((s) => out.rawSecret!.add(s));
    }
    out.constant = out.constant && i.constant;
    out.ownpkDirect = out.ownpkDirect || i.ownpkDirect;
    out.bits = out.bits === undefined || i.bits === undefined ? undefined : out.bits + i.bits;
    if (!out.lowHash && i.lowHash) {
      out.lowHash = i.lowHash;
      out.lowHashBits = i.lowHashBits;
    }
    out.identity = out.identity ?? i.identity;
  }
  out.protection = prot;
  return out;
}

const ABOUT_A_SECRET = new Set(["path", "file", "filename", "dir", "url", "length", "len", "size", "label", "hint", "placeholder", "prefix", "name", "type", "kind"]);
const SECRET_WORDS = new Set(["sk", "secret", "seed", "mnemonic", "password", "passphrase", "privkey"]);

/** Does an identifier look like it names a secret? (`secretKey`, `localSk`, `_secret`, `privateKey`) */
/** Types that can hold key material: bytes, field elements and vectors of them (not numbers, flags or strings). */
function keyLikeType(t: TypeRef | undefined): boolean {
  if (!t) return true;
  return !["Uint", "Boolean", "Opaque"].includes(t.name);
}

const versionKey = (v: string) => v.split(".").slice(0, 2).map((x) => x.padStart(4, "0")).join(".");

/** MS033: a pragma whose version range lies outside the tested range. */
export function languageVersionWarning(pragma: string): string | undefined {
  const versions = [...pragma.matchAll(/(\d+)\s*\.\s*(\d+)(?:\s*\.\s*\d+)?/g)].map((m) => `${m[1]}.${m[2]}`);
  if (!versions.length) return undefined;
  const { min, max } = SUPPORTED_LANGUAGE;
  // `>= 0.29` or an exact `0.29`: every version it allows is newer than the tested range
  const lowest = versions.map(versionKey).sort()[0];
  if (lowest > versionKey(max)) {
    return `This file requires Compact language ${versions[0]} or later, but Midnight Shield is tested with ${min}–${max}. Newer syntax may be misread or skipped, so findings for this file may be incomplete. Check for a newer Midnight Shield release.`;
  }
  const highest = versions.map(versionKey).sort().reverse()[0];
  if (highest < versionKey(min)) {
    return `This file targets Compact language ${versions[versions.length - 1]}, older than the ${min}–${max} range Midnight Shield is tested with. Older syntax may be misread.`;
  }
  return undefined;
}

export function isSecretName(name: string): boolean {
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  // seedPath, SEED_FILE, secretLength: where a secret is, or how big it is, not the secret
  if (words.length > 1 && ABOUT_A_SECRET.has(words[words.length - 1])) return false;
  if (words.some((w) => SECRET_WORDS.has(w))) return true;
  // privateKey, privKey, signingKey, spendingKey
  return words.some((w, i) => ["private", "priv", "signing", "spending"].includes(w) && words[i + 1] === "key");
}

function noSecret(i: Info): Info {
  return { ...i, rawSecret: undefined };
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
  /** the top-level circuit is exported (its return value is public) */
  exported?: boolean;
  scopes: Scope[];
  silent: boolean;
  depth: number;
  stack: string[];
  returns: Info[];
  /** set when an ownPublicKey() comparison happens while silent (inside an inlined helper) */
  ownpkCompare?: Loc;
  /** randomness expressions used by commitments in this function, for reuse detection */
  commitRand: Map<string, { loc: Loc; value: string }>;
  /** locals of this circuit that are made public somewhere in it (disclose(x), a ledger key, a return) */
  published?: Set<string>;
  /** name prefix of the module whose code is running (for imported modules) */
  prefix: string;
  /** when running code from another file: the call site in the analyzed file */
  anchor?: Loc;
  /** MS008 state, shared with inlined helpers of the same top-level circuit */
  nullifier: NullifierState;
}

interface NullifierState {
  /** a Merkle membership proof over private data (anonymous authorization) */
  anonAuth?: Loc;
  /** an assert that a value is NOT yet in a set (the nullifier check) */
  negMember: boolean;
  /** the circuit changes ledger state */
  writes: boolean;
  /** > 0 while the condition of an assert is evaluated */
  inAssert?: number;
  /** MS009: paths whose root check is (part of) an assert */
  gatedPaths?: Set<string>;
  /** MS009: Merkle paths whose root is checked, by variable name */
  checkedPaths: Map<string, Loc>;
  /** MS009: Merkle paths whose `.leaf` is compared in an assert */
  boundPaths: Set<string>;
  /** MS009: variables holding `merkleTreePathRoot(path)`, mapped to the path variable */
  rootVars: Map<string, string>;
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
  /** MS010: identity key -> circuits that publish it (first location per circuit) */
  private identityUses = new Map<string, Map<string, Loc>>();
  /** exported circuits that authorize with anonymous Merkle membership */
  private anonymousCircuits = new Set<string>();

  /** why each secret witness counts as one, for the MS007 message */
  private secretReason = new Map<string, string>();

  constructor(
    private program: Program,
    private resolver?: ImportResolver,
    private file?: string,
    /** how the contract uses each witness, from the constraint engine (constraints.ts) */
    private roles: Map<string, WitnessRole> = new Map(),
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
    for (const d of this.program.decls) {
      if (d.kind !== "pragma" || !/language_version/.test(d.text)) continue;
      const out = languageVersionWarning(d.text);
      if (out) this.report("MS033", d.loc, out);
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

    // MS010 only matters where the contract promises anonymity: in account-style
    // designs a stable identifier (like an address) is linkable by design.
    for (const uses of this.identityUses.values()) {
      if (uses.size < 2) continue;
      if (![...uses.keys()].some((c) => this.anonymousCircuits.has(c))) continue;
      const entries = [...uses.entries()].sort((a, b) => a[1].line - b[1].line || a[1].col - b[1].col);
      const names = entries.map(([c]) => `'${c}'`).join(", ");
      this.report(
        "MS010",
        entries[0][1],
        `The same identifier, derived only from a secret, is published by ${names}. Observers can link these actions to one user. If they should be unlinkable, mix a per-action value (a round, a nonce, or the action name) into the hash.`,
      );
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
    // used as a number somewhere (a score added to a balance): a fact the prover reports
    if (this.roles.get(name)?.quantity) return true;
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
      if (d.kind === "constructor") this.analyzeFunction("constructor", d.params, d.body, false);
      if (d.kind === "circuit" && d.body) this.analyzeFunction(d.name, d.params, d.body, d.exported);
    }
  }

  private analyzeFunction(name: string, params: Param[], body: Stmt[], exported: boolean): void {
    const vars = new Map<string, Info>();
    for (const p of params) vars.set(p.name, this.paramInfo(p));
    const nullifier: NullifierState = { negMember: false, writes: false, checkedPaths: new Map(), boundPaths: new Set(), rootVars: new Map() };
    const frame: Frame = { name, exported, scopes: [{ vars }], silent: false, depth: 0, stack: [name], returns: [], commitRand: new Map(), prefix: "", nullifier };
    frame.published = this.publishedLocals(body, frame);
    this.execBlock(body, frame);

    for (const [path, loc] of nullifier.checkedPaths) {
      // a root check that neither gates an assert nor guards a state change only computes a
      // Boolean (a read-only query like isMember(path)): it authorizes nothing on chain
      if (!nullifier.writes && !nullifier.gatedPaths?.has(path)) continue;
      if (!nullifier.boundPaths.has(path)) {
        const inline = path.endsWith("()");
        this.report(
          "MS009",
          loc,
          inline
            ? `The root of the Merkle path returned by '${path}' is checked, but the path is used inline, so nothing can assert that its leaf belongs to the caller. Merkle paths are public, so anyone can submit another member's path and pass. Store it first and bind it: const p = ${path}; assert(p.leaf == deriveLeaf(secretKey())).`
            : `The root of Merkle path '${path}' is checked, but nothing asserts that '${path}.leaf' belongs to the caller. Merkle paths are public, so anyone can submit another member's path and pass. Add e.g. assert(${path}.leaf == deriveLeaf(secretKey())).`,
        );
      }
    }

    if (exported && nullifier.anonAuth) this.anonymousCircuits.add(name);

    if (exported && nullifier.anonAuth && nullifier.writes && !nullifier.negMember) {
      this.report(
        "MS008",
        nullifier.anonAuth,
        `'${name}' authorizes the caller with an anonymous Merkle membership proof and then changes state, but never checks a nullifier. The same member can repeat this action. If each member should act once, derive a nullifier (hash of a tag and the member's secret), assert it is not in a set, then insert it.`,
      );
    }
  }

  /** Locals that the circuit makes public: `disclose(c)`, `map.insert(c, …)`, `return disclose(c)`. */
  private publishedLocals(body: Stmt[], frame: Frame): Set<string> {
    const locals = new Set<string>();
    for (const s of stmts(body)) if (s.kind === "const") for (const n of s.names) locals.add(n);
    const out = new Set<string>();
    const plain = (a: Expr): string | undefined => {
      const x = a.kind === "call" && a.callee.kind === "ident" && a.callee.name === "disclose" && a.args[0] ? a.args[0] : a;
      return x.kind === "ident" && locals.has(x.name) ? x.name : undefined;
    };
    for (const s of stmts(body)) {
      for (const e of stmtExprs(s)) {
        if (e.kind !== "call") continue;
        if (e.callee.kind === "ident" && e.callee.name === "disclose" && e.args[0]) {
          const n = plain(e.args[0]);
          if (n) out.add(n);
        }
        if (e.callee.kind === "member") {
          const root = rootIdent(e.callee.object);
          if (root && !locals.has(root) && this.resolveName(this.ledgers, root, frame) !== undefined) for (const a of e.args) {
            const n = plain(a);
            if (n) out.add(n);
          }
        }
      }
    }
    return out;
  }

  private paramInfo(p: Param): Info {
    return {
      sources: new Set([`p:${p.name}`]),
      rawWitness: new Set(),
      constant: false,
      ownpkDirect: false,
      bits: this.typeBits(p.type),
      type: p.type,
      rawSecret: isSecretName(p.name) && keyLikeType(p.type) ? new Set([`p:${p.name}`]) : undefined,
    };
  }

  // ---------- reporting ----------

  private report(ruleId: string, loc: Loc, message: string, severity?: Severity, confidence?: Confidence): void {
    const key = `${ruleId}:${loc.line}:${loc.col}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const meta = RULES_BY_ID.get(ruleId)!;
    this.findings.push({ ruleId, severity: severity ?? meta.severity, confidence: confidence ?? meta.confidence, message, loc });
  }

  // ---------- disclosure map ----------

  private disclosures = new Map<string, DisclosureEvent>();

  getDisclosures(): DisclosureEvent[] {
    return [...this.disclosures.values()].sort((a, b) => a.loc.line - b.loc.line || a.loc.col - b.loc.col);
  }

  private recordDisclosure(info: Info, loc: Loc, frame: Frame, via: DisclosureEvent["via"], target?: string): void {
    // A disclosed value written to the ledger was already recorded at disclose().
    if (via === "ledger write" && info.sources.has("disclosed") && !isPrivate(info)) return;
    const at = frame.anchor ?? loc;
    const circuit = frame.stack[0];
    const key = `${circuit}:${at.line}:${at.col}:${via}`;
    const sources = [...info.sources]
      .filter((s) => s.startsWith("w:") || s.startsWith("p:"))
      .map((s) => (s.startsWith("w:") ? `witness:${s.slice(2)}` : `param:${s.slice(2)}`));
    const protection: Protection = !isPrivate(info)
      ? info.constant
        ? "constant"
        : "public"
      : info.protection ?? "raw";
    const prev = this.disclosures.get(key);
    if (prev) {
      for (const src of sources) if (!prev.sources.includes(src)) prev.sources.push(src);
      return;
    }
    this.disclosures.set(key, {
      circuit,
      loc: at,
      via,
      target,
      sources,
      protection,
      secretBits: protection === "raw" || protection === "hash" ? info.bits : undefined,
    });
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
        const path = findPathRootArg(s.init);
        if (path && s.names.length === 1) frame.nullifier.rootVars.set(this.pathKey(s.names[0], frame), path);
        const info = this.evalExpr(s.init, frame);
        if (s.type) info.type = s.type;
        for (const n of s.names) scope.vars.set(n, info);
        break;
      }
      case "assign": {
        const value = this.evalExpr(s.value, frame);
        this.evalExpr(s.target, frame);
        const root = rootIdent(s.target);
        if (root && !this.lookup(root, frame) && this.resolveName(this.ledgers, root, frame)) this.sink(value, s.loc, frame, true, root);
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
        if (s.value) {
          const v = this.evalExpr(s.value, frame);
          frame.returns.push(v);
          if (frame.exported && frame.depth === 0) {
            this.recordDisclosure(v, s.loc, frame, "return");
            if (v.rawSecret?.size) this.sink(v, s.loc, frame, false, undefined, true);
          }
        }
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
  private sink(info: Info, loc: Loc, frame: Frame, isWrite = false, target?: string, reportSecret = true): void {
    if (isWrite) frame.nullifier.writes = true;
    if (info.identity && frame.exported !== false) {
      const uses = this.identityUses.get(info.identity) ?? new Map<string, Loc>();
      const circuit = frame.stack[0];
      if (!uses.has(circuit)) uses.set(circuit, frame.anchor ?? loc);
      this.identityUses.set(info.identity, uses);
    }
    this.recordDisclosure(info, loc, frame, isWrite ? "ledger write" : "disclose", target);
    for (const w of info.rawWitness) if (!this.witnessSinks.has(w)) this.witnessSinks.set(w, frame.anchor ?? loc);
    // a field named as a public key (signingPublicKey, ownerPk) holds a public value under a key-like parameter name
    // …and a field named as a reveal (seatSecretRevealed, revealedVrfSecret) is a deliberate opening at the end of a commit-reveal
    const publicTarget = !!target && /public|(^|[a-z])(Pub|Pk)(Key)?$|^pk$|reveal/i.test(target.split(".")[0]);
    if (reportSecret && info.rawSecret?.size && !publicTarget) {
      const names = [...info.rawSecret].map((s) => (s.startsWith("w:") ? `witness '${s.slice(2)}()'` : `parameter '${s.slice(2)}'`));
      const why = [...info.rawSecret].map((s) => this.secretReason.get(s.slice(2)) ?? "its name says it is a secret")[0];
      this.report(
        "MS007",
        frame.anchor ?? loc,
        `The raw value of ${names.join(" and ")} is made public here. It is treated as a secret because ${why}. Anyone can read it from the ledger or transaction. Publish a domain-separated hash or a commitment of it instead, or keep it private.`,
      );
    }
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
        // a numeric field of a secret record (terms.principal) is an amount, not key material
        const fieldType = obj.type ? this.structs.get(obj.type.name)?.find((f) => f.name === e.property)?.type : undefined;
        const numeric = !!fieldType && (["Uint", "Field", "Boolean"].includes(fieldType.name) || this.enums.has(fieldType.name));
        return { ...obj, sources: new Set(obj.sources), rawWitness: new Set(obj.rawWitness), type: fieldType, ...(numeric ? { rawSecret: undefined } : {}) };
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
        if (["==", "!=", "<", "<=", ">", ">=", "&&", "||"].includes(e.op)) {
          out.bits = isPrivate(out) ? 1 : 0;
          out.rawSecret = undefined; // a comparison reveals one bit, not the secret
          out.identity = undefined;
        }
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
        let rootKey: string | undefined;
        if (callee.property === "checkRoot" && e.args[0] && !frame.anchor) {
          let path = findPathRootArg(e.args[0]);
          const argRoot = e.args[0].kind === "ident" ? e.args[0].name : undefined;
          if (!path && argRoot) path = frame.nullifier.rootVars.get(this.pathKey(argRoot, frame));
          if (path) {
            const key = this.pathKey(path, frame);
            rootKey = key;
            if (!frame.nullifier.checkedPaths.has(key)) frame.nullifier.checkedPaths.set(key, e.loc);
            if (frame.nullifier.inAssert) (frame.nullifier.gatedPaths ??= new Set()).add(key);
          }
        }
        if (LEDGER_READ_METHODS.has(callee.property)) {
          const out = union([obj, ...args]);
          out.rawWitness = new Set();
          out.rawSecret = undefined;
          out.identity = undefined;
          out.bits = callee.property === "member" ? (args.some(isPrivate) ? 1 : 0) : 0;
          out.ownpkDirect = false;
          // const ok = tree.checkRoot(…); assert(ok): the result carries which path it checked
          if (rootKey) out.sources = new Set([...out.sources, `root:${rootKey}`]);
          return out;
        }
        // ledger write: insert, increment, write, push, ...
        // `map.insert(hash(secret, …), value)` without reading the old value is idempotent per
        // caller: repeating it rewrites the same entry, so it needs no nullifier (MS008)
        const keyedOnce =
          callee.property === "insert" &&
          args.length === 2 &&
          this.fromWitness(e.args[0], frame) &&
          !args[0].rawSecret?.size &&
          !e.args.slice(1).some((v) => [...walkExpr(v)].some((x) => x.kind === "call" && x.callee.kind === "member" && rootIdent(x.callee.object) === root));
        const wroteBefore = frame.nullifier.writes;
        for (const a of args) this.sink(a, e.loc, frame, true, `${root}.${callee.property}()`);
        frame.nullifier.writes = keyedOnce ? wroteBefore : true;
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
      frame.nullifier.inAssert = (frame.nullifier.inAssert ?? 0) + 1;
      const infos = e.args.map((a) => this.evalExpr(a, frame));
      frame.nullifier.inAssert--;
      for (const src of infos[0]?.sources ?? []) if (src.startsWith("root:")) (frame.nullifier.gatedPaths ??= new Set()).add(src.slice(5));
      if (infos[0]) this.markConstrained(infos[0]);
      if (e.args[0]) this.scanAuthorization(e.args[0], false, frame);
      return empty();
    }

    // lambdas passed to fold/map: bind their parameters to the data being iterated
    const lambdas = e.args.filter((a): a is Extract<Expr, { kind: "lambda" }> => a.kind === "lambda");
    // disclose(x) passed straight into a hash or commitment: only the result can become
    // public, so x keeps its secrecy for the entropy and randomness checks
    const hashing = !!name && (HASH_FNS.has(name) || COMMIT_FNS.has(name));
    const stripDisclose = (a: Expr): Expr =>
      hashing && a.kind === "call" && a.callee.kind === "ident" && a.callee.name === "disclose" && a.args[0] ? stripDisclose(a.args[0]) : a;
    const plain = e.args.filter((a) => a.kind !== "lambda").map((a) => this.evalExpr(stripDisclose(a), frame));
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
        rawSecret: this.secretWitness(witnessName, w.returnType) ? new Set([`w:${witnessName}`]) : undefined,
        constant: false,
        ownpkDirect: false,
        bits: this.typeBits(w.returnType),
        type: w.returnType,
      };
    }

    if (name && /^merkleTreePathRoot/.test(name)) {
      // the root of a Merkle path: a hash that equals a root already on the ledger
      const out = union(plain);
      out.rawWitness = new Set();
      out.rawSecret = undefined;
      out.identity = undefined;
      out.ownpkDirect = false;
      out.bits = undefined;
      out.protection = "hash";
      return out;
    }
    if (name && HASH_FNS.has(name)) return this.evalHash(e, plain, frame);
    if (name && COMMIT_FNS.has(name)) return this.evalCommit(e, plain, frame);

    if (name === "disclose") {
      const v = plain[0] ?? empty();
      // disclose() only allows a value to become public. A raw secret is reported where it
      // actually does (a ledger write or a return), so disclose(sk) passed into a hash,
      // a commitment or a helper that hashes it is not a leak.
      this.sink(v, e.loc, frame, false, undefined, false);
      // After disclose() the value is public: it carries no secret entropy.
      const sources = new Set([...v.sources].filter((x) => !x.startsWith("w:") && !x.startsWith("p:")));
      sources.add("disclosed");
      // still made from the caller's witness (a key derived from its secret), though now public
      if ([...v.sources].some((x) => x.startsWith("w:"))) sources.add("from-witness");
      return { ...v, sources, bits: 0, lowHash: undefined };
    }

    if (name && WRAPPER_FNS.has(name)) return union(plain);

    const circuitName = name ? this.resolveName(this.circuits, name, frame) : undefined;
    if (circuitName) return this.inlineCircuit(circuitName, plain, e.loc, frame);

    // unknown or standard-library call: the result is derived (e.g. a public key
    // from a secret), so it is no longer the raw secret
    const out = union(plain);
    out.ownpkDirect = false;
    out.rawSecret = undefined;
    out.identity = undefined;
    return out;
  }

  /**
   * A witness that holds a secret: named like one (and typed like key material), or,
   * whatever its name, a Bytes<32> witness the contract hashes into its state or
   * identity (a secret key by role), or a raw Bytes<32> witness with a neutral name
   * that is neither a hash nor an identifier.
   */
  private secretWitness(name: string, type: TypeRef | undefined): boolean {
    const short = name.slice(name.lastIndexOf("_") + 1);
    const role = this.roles.get(name);
    if ((isSecretName(short) || isSecretName(name)) && keyLikeType(type)) {
      this.secretReason.set(name, "its name and type say it is a secret");
      return true;
    }
    if (!type || type.name !== "Bytes" || !/^Bytes<\s*32\s*>$/.test(type.text.replace(/\s/g, ""))) return false;
    // the engine saw it used as a number (added, compared): an amount or a score, not key material
    if (role?.quantity) return false;
    // names that say it is public data, randomness (MS014's subject) or an identifier
    if (/(hash|commit|root|digest|id$|^id|address|addr|pk$|public|nonce|salt|rand|path|leaf|tag|color|domain|nullifier|name|label|title|text|message|memo|ur[il]|data|value|meta|description|content|note|cid|result|score|count|amount|balance|time|date)/i.test(short)) return false;
    if (role?.hashed) {
      this.secretReason.set(name, "the contract also hashes it into an identity or commitment, so it is key material");
      return true;
    }
    // used to pick a map or set entry (balances.insert(user, …)): an account identifier, not key material
    if (role?.keyed) return false;
    this.secretReason.set(name, "it is 32 bytes of private data that is never hashed, compared or used as a number, which is how secret keys are handled");
    return true;
  }

  /** Whether an expression depends on a parameter of the circuit being analysed. */
  private fromParam(e: Expr, frame: Frame): boolean {
    for (const x of walkExpr(e)) {
      if (x.kind !== "ident") continue;
      const info = this.lookup(x.name, frame);
      if (info && [...info.sources].some((s) => s.startsWith("p:"))) return true;
    }
    return false;
  }

  /** Whether an expression depends on a witness value (directly, through locals, or through helper calls). */
  private fromWitness(e: Expr, frame: Frame): boolean {
    for (const x of walkExpr(e)) {
      if (x.kind === "call" && x.callee.kind === "ident" && this.resolveName(this.witnesses, x.callee.name, frame)) return true;
      if (x.kind === "ident") {
        const info = this.lookup(x.name, frame);
        if (info && [...info.sources].some((s) => s.startsWith("w:") || s === "from-witness")) return true;
      }
    }
    return false;
  }

  /** MS008: look for Merkle membership proofs and nullifier checks inside an assert condition. */
  private scanAuthorization(e: Expr, negated: boolean, frame: Frame): void {
    if (e.kind === "unary" && e.op === "!") return this.scanAuthorization(e.arg, !negated, frame);
    if (e.kind === "call" && e.callee.kind === "ident" && e.callee.name === "disclose" && e.args[0]) {
      return this.scanAuthorization(e.args[0], negated, frame);
    }
    if (e.kind === "binary" && (e.op === "==" || e.op === "!=")) {
      // MS009: `path.leaf == ...` binds the Merkle path to a value
      for (const [side, other] of [[e.left, e.right], [e.right, e.left]] as const) {
        if (side.kind === "member" && side.property === "leaf") {
          const root = rootIdent(side.object);
          // only a value derived from a witness secret ties the path to the caller;
          // a parameter or a ledger value can be supplied or read by anyone
          // in a helper circuit analysed on its own, a parameter is whatever the exported caller passes
          // (requireMember(sk) with sk = secretKey()), so a leaf bound to one is left to the caller
          const helperParam = !frame.exported && frame.depth === 0 && this.fromParam(other, frame);
          if (root && (this.fromWitness(other, frame) || helperParam)) frame.nullifier.boundPaths.add(this.pathKey(root, frame));
        }
      }
      return;
    }
    if (e.kind === "binary" && (e.op === "&&" || e.op === "||")) {
      this.scanAuthorization(e.left, negated, frame);
      this.scanAuthorization(e.right, negated, frame);
      return;
    }
    if (e.kind === "call" && e.callee.kind === "member") {
      const root = rootIdent(e.callee.object);
      const isLedger = root !== undefined && !this.lookup(root, frame) && this.resolveName(this.ledgers, root, frame) !== undefined;
      if (!isLedger) return;
      const method = e.callee.property;
      if (method === "member" && negated) frame.nullifier.negMember = true;
      if (method === "checkRoot" && !negated) {
        const args = e.args.map((a) => this.evalExpr(a, frame));
        if (args.some((a) => isPrivate(a) || a.sources.has("disclosed"))) frame.nullifier.anonAuth = frame.nullifier.anonAuth ?? frame.anchor ?? e.loc;
      }
    }
  }

  /** Paths are tracked by name within one top-level circuit; helper frames get their own namespace. */
  private pathKey(name: string, frame: Frame): string {
    return frame.depth === 0 ? name : `${frame.stack.join(">")}:${name}`;
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
      protection: "hash",
    };

    // MS010: deterministic in the secret alone (no fresh randomness)
    const privateInputs = infos.filter((i) => isPrivate(i));
    // a variable public input (a case id, an app id, a round) makes the tag differ per action, so it does not link them
    const varyingPublic = infos.some((i) => !i.constant && !isPrivate(i));
    if (privateInputs.length && !varyingPublic && privateInputs.every((i) => (i.rawSecret?.size ?? 0) > 0 || i.identity)) {
      out.identity = `${frame.prefix}${e.loc.line}:${e.loc.col}`;
    }

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
      } else if (randExpr.kind === "ident" && frame.published?.has(randExpr.name) && !(isPrivate(value) && (value.bits ?? 0) >= 128)) {
        // (a 32-byte secret as the value cannot be guessed, whatever the randomness: a keyed binding)
        // persistentCommit(category, c) where c is also written to the ledger or returned
        this.report(
          "MS004",
          e.loc,
          `This commitment's randomness '${randExpr.name}' is made public in this circuit (written to the ledger, disclosed or returned), so anyone can recompute the commitment for every candidate value of what it hides. Use separate secret randomness from a witness.`,
        );
      } else if (rand.bits !== undefined && rand.bits < STRONG_RANDOMNESS_BITS) {
        this.report(
          "MS004",
          e.loc,
          `This commitment's randomness has only about ${rand.bits} bits of entropy. Use at least 32 random bytes (Bytes<32>).`,
          undefined,
          "medium",
        );
      } else {
        const key = exprText(randExpr);
        const valueKey = exprText(e.args[0]);
        const prev = frame.commitRand.get(key);
        // two calls of a witness (getRandomness(), getRandomness()) are two values: a witness can
        // return fresh bytes on every call. Reuse means the same local or the same stored value.
        const r = randExpr.kind === "call" && randExpr.callee.kind === "ident" && randExpr.callee.name === "disclose" && randExpr.args[0] ? randExpr.args[0] : randExpr;
        const freshEachCall = r.kind === "call" && r.callee.kind === "ident" && !!this.resolveName(this.witnesses, r.callee.name, frame);
        if (prev && prev.value !== valueKey && !freshEachCall) {
          this.report(
            "MS004",
            e.loc,
            `The same randomness '${key}' is used by another commitment on line ${prev.loc.line}. Reusing randomness lets observers link the two commitments. Derive separate randomness for each (e.g. hash(tag, salt)).`,
            "medium",
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
      protection: "commit",
    };
  }

  private inlineCircuit(name: string, args: Info[], loc: Loc, frame: Frame): Info {
    const entry = this.circuits.get(name)!;
    const c = entry.decl;
    if (!c.body || frame.depth >= MAX_INLINE_DEPTH || frame.stack.includes(name)) {
      // Too deep or recursive: treat the result as derived from the arguments.
      const out = union(args);
      out.ownpkDirect = false;
      out.rawWitness = new Set();
      out.rawSecret = undefined;
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
      nullifier: frame.nullifier,
      exported: frame.exported,
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

/** In `merkleTreePathRoot<n, T>(path)` (possibly wrapped in disclose), return `path`'s variable name. */
function findPathRootArg(e: Expr): string | undefined {
  if (e.kind === "call" && e.callee.kind === "ident") {
    if (e.callee.name === "disclose" && e.args[0]) return findPathRootArg(e.args[0]);
    if (/^merkleTreePathRoot/.test(e.callee.name) && e.args[0]) return rootIdent(e.args[0]) ?? inlineCall(e.args[0]);
  }
  return undefined;
}

/** `merkleTreePathRoot(path())`: the path comes straight from a call, so nothing can check its leaf. */
function inlineCall(e: Expr): string | undefined {
  if (e.kind === "call" && e.callee.kind === "ident") return e.callee.name === "disclose" && e.args[0] ? inlineCall(e.args[0]) : `${e.callee.name}()`;
  return undefined;
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

function* walkExpr(e: Expr): Generator<Expr> {
  yield e;
  switch (e.kind) {
    case "call":
      yield* walkExpr(e.callee);
      for (const a of e.args) yield* walkExpr(a);
      break;
    case "member":
      yield* walkExpr(e.object);
      break;
    case "index":
      yield* walkExpr(e.object);
      yield* walkExpr(e.index);
      break;
    case "vector":
      for (const x of e.elements) yield* walkExpr(x);
      break;
    case "struct":
      for (const f of e.fields) yield* walkExpr(f.value);
      break;
    case "binary":
      yield* walkExpr(e.left);
      yield* walkExpr(e.right);
      break;
    case "unary":
    case "spread":
      yield* walkExpr(e.arg);
      break;
    case "cast":
      yield* walkExpr(e.expr);
      break;
    case "cond":
      yield* walkExpr(e.test);
      yield* walkExpr(e.then);
      yield* walkExpr(e.else);
      break;
  }
}
