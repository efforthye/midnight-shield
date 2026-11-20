// Generic AST walker, used by custom rules (plugins).

import type { Decl, Expr, Program, Stmt } from "./ast.js";

type CircuitDecl = Extract<Decl, { kind: "circuit" }>;
type ConstructorDecl = Extract<Decl, { kind: "constructor" }>;

export interface WalkContext {
  /** name of the circuit (or "constructor") the node is in */
  circuit: string;
  /** the enclosing circuit is exported */
  exported: boolean;
  /** the node is inside the first argument of an assert(...) */
  inAssert: boolean;
}

export interface Visitor {
  decl?(decl: Decl): void;
  circuit?(decl: CircuitDecl | ConstructorDecl, ctx: WalkContext): void;
  statement?(stmt: Stmt, ctx: WalkContext): void;
  expression?(expr: Expr, ctx: WalkContext): void;
  /** a call expression; `callee` is the called name, e.g. "persistentHash" or "balances.insert" */
  call?(expr: Extract<Expr, { kind: "call" }>, callee: string, ctx: WalkContext): void;
}

export function calleeName(e: Expr): string {
  if (e.kind === "ident") return e.name;
  if (e.kind === "member") return `${calleeName(e.object)}.${e.property}`;
  return "";
}

export function walkProgram(program: Program, visitor: Visitor): void {
  const walkDecls = (decls: Decl[]) => {
    for (const d of decls) {
      visitor.decl?.(d);
      if (d.kind === "module") walkDecls(d.decls);
      if (d.kind === "circuit" && d.body) {
        const ctx: WalkContext = { circuit: d.name, exported: d.exported, inAssert: false };
        visitor.circuit?.(d, ctx);
        walkStmts(d.body, ctx, visitor);
      }
      if (d.kind === "constructor") {
        const ctx: WalkContext = { circuit: "constructor", exported: false, inAssert: false };
        visitor.circuit?.(d, ctx);
        walkStmts(d.body, ctx, visitor);
      }
    }
  };
  walkDecls(program.decls);
}

function walkStmts(stmts: Stmt[], ctx: WalkContext, v: Visitor): void {
  for (const s of stmts) {
    v.statement?.(s, ctx);
    switch (s.kind) {
      case "const":
        walkExpr(s.init, ctx, v);
        break;
      case "assign":
        walkExpr(s.target, ctx, v);
        walkExpr(s.value, ctx, v);
        break;
      case "if":
        walkExpr(s.test, ctx, v);
        walkStmts(s.then, ctx, v);
        if (s.else) walkStmts(s.else, ctx, v);
        break;
      case "for":
        walkExpr(s.iter, ctx, v);
        walkStmts(s.body, ctx, v);
        break;
      case "return":
        if (s.value) walkExpr(s.value, ctx, v);
        break;
      case "expr":
        walkExpr(s.expr, ctx, v);
        break;
      case "block":
        walkStmts(s.body, ctx, v);
        break;
    }
  }
}

function walkExpr(e: Expr, ctx: WalkContext, v: Visitor): void {
  v.expression?.(e, ctx);
  switch (e.kind) {
    case "call": {
      const name = calleeName(e.callee);
      v.call?.(e, name, ctx);
      if (e.callee.kind !== "ident") walkExpr(e.callee, ctx, v);
      e.args.forEach((a, i) => walkExpr(a, name === "assert" && i === 0 ? { ...ctx, inAssert: true } : ctx, v));
      break;
    }
    case "member":
      walkExpr(e.object, ctx, v);
      break;
    case "index":
      walkExpr(e.object, ctx, v);
      walkExpr(e.index, ctx, v);
      break;
    case "vector":
      e.elements.forEach((x) => walkExpr(x, ctx, v));
      break;
    case "struct":
      e.fields.forEach((f) => walkExpr(f.value, ctx, v));
      break;
    case "binary":
      walkExpr(e.left, ctx, v);
      walkExpr(e.right, ctx, v);
      break;
    case "unary":
    case "spread":
      walkExpr(e.arg, ctx, v);
      break;
    case "cast":
      walkExpr(e.expr, ctx, v);
      break;
    case "cond":
      walkExpr(e.test, ctx, v);
      walkExpr(e.then, ctx, v);
      walkExpr(e.else, ctx, v);
      break;
    case "lambda":
      if (Array.isArray(e.body)) walkStmts(e.body, ctx, v);
      else walkExpr(e.body, ctx, v);
      break;
  }
}
