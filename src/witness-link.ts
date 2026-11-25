// MS121: the contract and the DApp read together. A Compact contract declares
// its witnesses; the DApp implements them in a `witnesses = { … }` object. Only
// with both in view can we tell that `bidSalt` (a name no rule would guess) is
// the randomness of a commitment, and that its implementation returns zeros.

import type { RawFinding } from "./analyzer.js";
import type { Expr, Program } from "./ast.js";
import { collect, exprs, stmtExprs, stmts, type Ctx } from "./auth-writes.js";
import { lex, type Token } from "./lexer.js";

export type WitnessRole = "commitment randomness" | "secret key";

export interface WitnessUse {
  role: WitnessRole;
  file: string;
  line: number;
}

const COMMIT = new Set(["persistentCommit", "transientCommit"]);
const HASH = new Set(["persistentHash", "transientHash"]);

/** What each witness is used for in a contract, by its declared name. */
export function witnessRoles(program: Program, file: string): Map<string, WitnessUse> {
  const ctx: Ctx = { ledger: new Set(), witnesses: new Set(), circuits: new Map(), enums: new Set() };
  collect(program.decls, ctx);
  const out = new Map<string, WitnessUse>();
  const witnessOf = (e: Expr, locals: Map<string, string>): string | undefined => {
    const x = e.kind === "call" && e.callee.kind === "ident" && e.callee.name === "disclose" && e.args[0] ? e.args[0] : e;
    if (x.kind === "call" && x.callee.kind === "ident" && ctx.witnesses.has(x.callee.name)) return x.callee.name;
    if (x.kind === "ident") return locals.get(x.name);
    return undefined;
  };
  for (const c of ctx.circuits.values()) {
    const locals = new Map<string, string>();
    for (const s of stmts(c.body ?? [])) {
      if (s.kind === "const" && s.names.length === 1) {
        const w = witnessOf(s.init, locals);
        if (w) locals.set(s.names[0], w);
      }
      for (const e of stmtExprs(s)) {
        if (e.kind !== "call" || e.callee.kind !== "ident") continue;
        if (COMMIT.has(e.callee.name) && e.args.length >= 2) {
          const w = witnessOf(e.args[e.args.length - 1], locals);
          if (w) out.set(w, { role: "commitment randomness", file, line: e.loc.line });
        }
        if (HASH.has(e.callee.name)) {
          for (const a of e.args) {
            for (const x of exprs(a)) {
              const w = witnessOf(x, locals);
              if (w && !out.has(w) && /Bytes<32>/.test(ctx.witnesses.has(w) ? witnessType(program, w) : "")) out.set(w, { role: "secret key", file, line: e.loc.line });
            }
          }
        }
      }
    }
  }
  return out;
}

function witnessType(program: Program, name: string): string {
  for (const d of program.decls) {
    if (d.kind === "witness" && d.name === name) return d.returnType?.text ?? "";
    if (d.kind === "module") {
      const t = witnessType({ decls: d.decls, diagnostics: [] }, name);
      if (t) return t;
    }
  }
  return "";
}

/** `witnesses = { name: (…) => … }` properties in a DApp file: name, the body tokens, and where it starts. */
export function witnessImplementations(source: string): { name: string; body: Token[]; line: number; col: number }[] {
  const { tokens } = lex(source);
  const out: { name: string; body: Token[]; line: number; col: number }[] = [];
  for (let i = 0; i + 2 < tokens.length; i++) {
    if (tokens[i].kind !== "ident" || !/witnesses$/i.test(tokens[i].value)) continue;
    // deploymentWitnesses, placeholderWitnesses: stand-ins the constructor needs, never run by a circuit
    if (/deploy|placeholder|dummy|stub|noop/i.test(tokens[i].value)) continue;
    let open = -1;
    for (let j = i + 1; j < Math.min(tokens.length, i + 30); j++) {
      if (tokens[j].value === "{") {
        open = j;
        break;
      }
      if (tokens[j].value === ";" || tokens[j].value === "(") break;
    }
    if (open === -1) continue;
    let depth = 0;
    let start = open + 1;
    for (let j = open; j < tokens.length; j++) {
      const v = tokens[j].value;
      if (v === "{" || v === "(" || v === "[") depth++;
      else if (v === "}" || v === ")" || v === "]") depth--;
      if (!((depth === 1 && v === ",") || depth === 0)) continue;
      const prop = tokens.slice(start, j);
      start = j + 1;
      const head = prop[0];
      if (head && (head.kind === "ident" || head.kind === "string")) {
        out.push({ name: head.kind === "string" ? head.value.slice(1, -1) : head.value, body: prop.slice(1), line: head.line, col: head.col });
      }
      if (depth === 0) break;
    }
  }
  return out;
}

/** Why an implementation cannot be secret: zero bytes, a clock, Math.random(), or a constant. */
export function weakImplementation(body: Token[]): string | undefined {
  // only what comes after the arrow: the parameter list names privateState too
  const arrow = body.findIndex((t) => t.value === "=>");
  const value = arrow === -1 ? body : body.slice(arrow + 1);
  const text = value.map((t) => t.value).join(" ");
  // read from stored private state (privateState.secretKey), or made with real randomness
  if (/getRandomValues|randomBytes|randomFill|randomUUID|crypto|privateState\.\w|\.fill|\.set\(/.test(text.replace(/ ?\. ?/g, ".").replace(/ \(/g, "("))) return undefined;
  if (/Math \. random/.test(text)) return "Math.random(), which can be predicted";
  if (/new Uint8Array \( \d+ \)|Buffer \. alloc \(|new Array \( \d+ \)/.test(text)) return "a newly allocated buffer, which is all zeros";
  if (/Date \. now|performance \. now|new Date/.test(text)) return "a clock value, which anyone can guess";
  // a return value made only of literals: [ps, "0xabc…"], [ps, 42n], [ps, fromHex("…")]
  const values = value.filter((t) => t.kind === "string" || t.kind === "number");
  const idents = value.filter((t) => t.kind === "ident" && !["ctx", "context", "privateState", "_", "fromHex", "toBytes", "encode", "Uint8Array", "from", "Buffer", "BigInt", "hexToBytes", "WitnessContext", "Ledger", "PrivateState"].includes(t.value));
  if (values.length && idents.length <= 2) return "a constant written in the code";
  return undefined;
}

export interface LinkedFinding {
  file: string;
  raw: RawFinding;
}

/** Witnesses the contract relies on for secrecy, implemented weakly in the DApp. */
export function linkWitnesses(contracts: { file: string; program: Program }[], dapps: { file: string; source: string }[]): LinkedFinding[] {
  const roles = new Map<string, WitnessUse>();
  for (const c of contracts) for (const [name, use] of witnessRoles(c.program, c.file)) if (!roles.has(name)) roles.set(name, use);
  if (!roles.size) return [];
  const out: LinkedFinding[] = [];
  for (const d of dapps) {
    for (const impl of witnessImplementations(d.source)) {
      const use = roles.get(impl.name);
      if (!use) continue;
      const why = weakImplementation(impl.body);
      if (!why) continue;
      out.push({
        file: d.file,
        raw: {
          ruleId: "MS121",
          severity: "critical",
          confidence: "high",
          loc: { line: impl.line, col: impl.col },
          message: `The contract uses witness '${impl.name}' as ${use.role} (${use.file}:${use.line}), but this implementation returns ${why}. The contract's secrecy rests on this value being random and private, so ${use.role === "secret key" ? "anyone can compute the key and act as the user" : "anyone can open the commitment by trying candidate values"}. Return crypto.getRandomValues(new Uint8Array(32)), and keep it in private state if it must be reused.`,
        },
      });
    }
  }
  return out;
}
