// Recursive-descent parser for Compact.
// It is tolerant: a statement or declaration it cannot parse is skipped and
// reported as a diagnostic, so one unsupported construct never hides findings
// in the rest of the file.

import type { Decl, Expr, Loc, Param, ParseDiagnostic, Program, Stmt, TypeArg, TypeRef } from "./ast.js";
import { lex, type Token } from "./lexer.js";

class ParseError extends Error {
  constructor(
    message: string,
    public loc: Loc,
  ) {
    super(message);
  }
}

const MODIFIERS = new Set(["export", "sealed", "pure"]);

export function parse(source: string): Program {
  const { tokens } = lex(source);
  return new Parser(tokens).parseProgram();
}

class Parser {
  private pos = 0;
  private diagnostics: ParseDiagnostic[] = [];

  constructor(private tokens: Token[]) {}

  // ---------- token helpers ----------

  private peek(offset = 0): Token {
    return this.tokens[Math.min(this.pos + offset, this.tokens.length - 1)];
  }

  private next(): Token {
    const t = this.peek();
    if (t.kind !== "eof") this.pos++;
    return t;
  }

  private is(value: string, offset = 0): boolean {
    const t = this.peek(offset);
    return (t.kind === "punct" || t.kind === "ident") && t.value === value;
  }

  private eat(value: string): boolean {
    if (this.is(value)) {
      this.pos++;
      return true;
    }
    return false;
  }

  private expect(value: string): Token {
    if (!this.is(value)) {
      const t = this.peek();
      throw new ParseError(`expected '${value}' but found '${t.value || "end of file"}'`, this.loc(t));
    }
    return this.next();
  }

  private ident(): string {
    const t = this.peek();
    if (t.kind !== "ident") throw new ParseError(`expected identifier but found '${t.value}'`, this.loc(t));
    this.pos++;
    return t.value;
  }

  private loc(t: Token = this.peek()): Loc {
    return { line: t.line, col: t.col };
  }

  private atEnd(): boolean {
    return this.peek().kind === "eof";
  }

  /** Skip a balanced bracket group starting at the current opening token. */
  private skipBalanced(): void {
    const open = this.next().value;
    const close = open === "{" ? "}" : open === "(" ? ")" : "]";
    let depth = 1;
    while (!this.atEnd() && depth > 0) {
      const t = this.next();
      if (t.value === open) depth++;
      else if (t.value === close) depth--;
    }
  }

  /** Error recovery: skip to the end of the current statement or block. */
  private recover(): void {
    let depth = 0;
    while (!this.atEnd()) {
      const t = this.peek();
      if (t.value === "{" || t.value === "(" || t.value === "[") depth++;
      if (t.value === "}" || t.value === ")" || t.value === "]") {
        if (depth === 0) return;
        depth--;
        if (depth === 0 && t.value === "}") {
          this.pos++;
          return;
        }
      }
      if (t.value === ";" && depth === 0) {
        this.pos++;
        return;
      }
      this.pos++;
    }
  }

  private report(e: unknown): void {
    if (e instanceof ParseError) {
      this.diagnostics.push({ message: e.message, loc: e.loc });
    } else {
      throw e;
    }
  }

  // ---------- program ----------

  parseProgram(): Program {
    const decls = this.parseDecls(false);
    return { decls, diagnostics: this.diagnostics };
  }

  private parseDecls(inModule: boolean): Decl[] {
    const decls: Decl[] = [];
    while (!this.atEnd()) {
      if (inModule && this.is("}")) break;
      const start = this.pos;
      try {
        const d = this.parseDecl();
        if (d) decls.push(d);
      } catch (e) {
        this.report(e);
        if (this.pos === start) this.pos++;
        this.recover();
      }
    }
    return decls;
  }

  private parseDecl(): Decl | undefined {
    const startTok = this.peek();

    if (this.is("pragma")) {
      const parts: string[] = [];
      this.next();
      while (!this.atEnd() && !this.is(";")) parts.push(this.next().value);
      this.eat(";");
      return { kind: "pragma", text: parts.join(" "), loc: this.loc(startTok) };
    }

    if (this.is("include")) {
      this.next();
      const t = this.next();
      this.eat(";");
      return t.kind === "string" ? { kind: "include", path: t.value.slice(1, -1), loc: this.loc(startTok) } : undefined;
    }

    if (this.is("import")) {
      // import Name;  import "path"<args> prefix P_;  import { a, b } from "path" prefix P_;
      this.next();
      if (this.is("{")) {
        this.skipBalanced();
        this.expect("from");
      }
      const t = this.next();
      const isPath = t.kind === "string";
      const target = isPath ? t.value.slice(1, -1) : t.value;
      this.skipTypeParams();
      let prefix = "";
      if (this.eat("prefix")) prefix = this.ident();
      while (!this.atEnd() && !this.is(";")) this.next();
      this.eat(";");
      return { kind: "import", target, isPath, prefix, loc: this.loc(startTok) };
    }

    if (this.is("export") && this.is("{", 1)) {
      this.next();
      this.skipBalanced();
      this.eat(";");
      return undefined;
    }

    if (this.is(";")) {
      this.next();
      return undefined;
    }

    let exported = false;
    let sealed = false;
    let pure = false;
    while (this.peek().kind === "ident" && MODIFIERS.has(this.peek().value)) {
      const m = this.next().value;
      if (m === "export") exported = true;
      if (m === "sealed") sealed = true;
      if (m === "pure") pure = true;
    }

    const kw = this.peek();
    const loc = this.loc(kw);

    switch (kw.value) {
      case "ledger": {
        this.next();
        const name = this.ident();
        this.expect(":");
        const type = this.parseType();
        this.eat(";");
        return { kind: "ledger", name, type, exported, sealed, loc };
      }
      case "witness": {
        this.next();
        const name = this.ident();
        this.skipTypeParams();
        const params = this.parseParams();
        let returnType: TypeRef | undefined;
        if (this.eat(":")) returnType = this.parseType();
        this.eat(";");
        return { kind: "witness", name, params, returnType, loc };
      }
      case "circuit": {
        this.next();
        const name = this.ident();
        this.skipTypeParams();
        const params = this.parseParams();
        let returnType: TypeRef | undefined;
        if (this.eat(":")) returnType = this.parseType();
        let body: Stmt[] | undefined;
        if (this.is("{")) body = this.parseBlock();
        else this.eat(";");
        return { kind: "circuit", name, params, returnType, body, exported, pure, loc };
      }
      case "constructor": {
        this.next();
        const params = this.parseParams();
        const body = this.parseBlock();
        return { kind: "constructor", params, body, loc };
      }
      case "struct": {
        this.next();
        const name = this.ident();
        this.skipTypeParams();
        this.expect("{");
        const fields: Param[] = [];
        while (!this.atEnd() && !this.is("}")) {
          const floc = this.loc();
          const fname = this.ident();
          this.expect(":");
          const type = this.parseType();
          fields.push({ name: fname, type, loc: floc });
          if (!this.eat(",")) this.eat(";");
        }
        this.expect("}");
        this.eat(";");
        return { kind: "struct", name, fields, loc };
      }
      case "enum": {
        this.next();
        const name = this.ident();
        this.expect("{");
        const members: string[] = [];
        while (!this.atEnd() && !this.is("}")) {
          members.push(this.ident());
          this.eat(",");
        }
        this.expect("}");
        this.eat(";");
        return { kind: "enum", name, members, loc };
      }
      case "module": {
        this.next();
        const name = this.ident();
        this.skipTypeParams();
        this.expect("{");
        const decls = this.parseDecls(true);
        this.expect("}");
        return { kind: "module", name, decls, loc };
      }
      case "new":
      case "type": {
        // `new type Name = T;` or `type Name = T;`
        if (kw.value === "new") this.next();
        this.expect("type");
        const name = this.ident();
        this.skipTypeParams();
        this.expect("=");
        const type = this.parseType();
        this.eat(";");
        return { kind: "typeAlias", name, type, loc };
      }
      case "contract": {
        // Cross-contract interface declaration: nothing to analyze.
        this.next();
        this.ident();
        if (this.is("{")) this.skipBalanced();
        this.eat(";");
        return undefined;
      }
      default:
        throw new ParseError(`unexpected '${kw.value || "end of file"}' at top level`, loc);
    }
  }

  private skipTypeParams(): void {
    if (!this.is("<")) return;
    let depth = 0;
    do {
      const t = this.next();
      if (t.value === "<") depth++;
      if (t.value === ">") depth--;
    } while (!this.atEnd() && depth > 0);
  }

  private parseParams(): Param[] {
    this.expect("(");
    const params: Param[] = [];
    while (!this.atEnd() && !this.is(")")) {
      const loc = this.loc();
      if (this.is("[") || this.is("{")) {
        // destructured parameter: keep going without a name
        this.skipBalanced();
        let type: TypeRef | undefined;
        if (this.eat(":")) type = this.parseType();
        params.push({ name: "_", type, loc });
      } else {
        const name = this.ident();
        let type: TypeRef | undefined;
        if (this.eat(":")) type = this.parseType();
        params.push({ name, type, loc });
      }
      if (!this.eat(",")) break;
    }
    this.expect(")");
    return params;
  }

  // ---------- types ----------

  private parseType(): TypeRef {
    const start = this.pos;
    if (this.is("[")) {
      // tuple type: [] or [A, B]
      this.next();
      const args: TypeArg[] = [];
      while (!this.atEnd() && !this.is("]")) {
        args.push({ kind: "type", type: this.parseType() });
        if (!this.eat(",")) break;
      }
      this.expect("]");
      return { name: "[]", args, text: this.textFrom(start) };
    }
    let name = this.ident();
    while (this.is(".") && this.peek(1).kind === "ident") {
      this.next();
      name += "." + this.ident();
    }
    const args: TypeArg[] = [];
    if (this.is("<")) {
      this.next();
      while (!this.atEnd() && !this.is(">")) {
        args.push(this.parseTypeArg());
        if (!this.eat(",")) break;
      }
      this.expect(">");
    }
    return { name, args, text: this.textFrom(start) };
  }

  private parseTypeArg(): TypeArg {
    const t = this.peek();
    if (t.kind === "number") {
      this.next();
      const from = parseNumber(t.value);
      if (this.eat("..")) {
        const to = this.next();
        return { kind: "range", from, to: parseNumber(to.value) };
      }
      return { kind: "number", value: from };
    }
    if (t.kind === "string") {
      this.next();
      return { kind: "string", value: t.value.slice(1, -1) };
    }
    if (this.is("#")) {
      this.next();
      return { kind: "param", name: this.ident() };
    }
    return { kind: "type", type: this.parseType() };
  }

  private textFrom(start: number): string {
    let out = "";
    for (let i = start; i < this.pos; i++) {
      const v = this.tokens[i].value;
      out += v === "," ? ", " : v;
    }
    return out;
  }

  /** Try to parse `<T, U>` generic arguments; backtrack if this is a comparison. */
  private tryTypeArgs(): TypeRef[] | undefined {
    if (!this.is("<")) return undefined;
    const save = this.pos;
    const saveDiag = this.diagnostics.length;
    try {
      this.next();
      const args: TypeRef[] = [];
      while (!this.is(">")) {
        const t = this.peek();
        if (t.kind === "number") {
          this.next();
          if (this.eat("..")) this.next();
          args.push({ name: t.value, args: [], text: t.value });
        } else if (t.kind === "string") {
          this.next();
          args.push({ name: t.value, args: [], text: t.value });
        } else {
          args.push(this.parseType());
        }
        if (!this.eat(",")) break;
      }
      this.expect(">");
      const n = this.peek();
      // After real type arguments comes a call, a struct literal, or an operator /
      // closing token, never the start of another operand.
      const ok = !((n.kind === "ident" && n.value !== "as") || n.kind === "number" || n.kind === "string" || ["[", "!", "-"].includes(n.value));
      if (!ok) throw new ParseError("not type arguments", this.loc());
      return args;
    } catch {
      this.pos = save;
      this.diagnostics.length = saveDiag;
      return undefined;
    }
  }

  // ---------- statements ----------

  private parseBlock(): Stmt[] {
    this.expect("{");
    const body: Stmt[] = [];
    while (!this.atEnd() && !this.is("}")) {
      const start = this.pos;
      try {
        body.push(this.parseStmt());
      } catch (e) {
        this.report(e);
        if (this.pos === start) this.pos++;
        this.recover();
      }
    }
    this.expect("}");
    return body;
  }

  private parseBody(): Stmt[] {
    return this.is("{") ? this.parseBlock() : [this.parseStmt()];
  }

  private parseStmt(): Stmt {
    const loc = this.loc();

    if (this.is("{")) return { kind: "block", body: this.parseBlock(), loc };

    if (this.is("const")) {
      this.next();
      const names: string[] = [];
      if (this.is("[") || this.is("{")) {
        const close = this.is("[") ? "]" : "}";
        this.next();
        while (!this.atEnd() && !this.is(close)) {
          if (this.peek().kind === "ident") names.push(this.next().value);
          else this.next();
        }
        this.expect(close);
      } else {
        names.push(this.ident());
      }
      let type: TypeRef | undefined;
      if (this.eat(":")) type = this.parseType();
      this.expect("=");
      const init = this.parseExpr();
      this.eat(";");
      return { kind: "const", names, type, init, loc };
    }

    if (this.is("if")) {
      this.next();
      this.expect("(");
      const test = this.parseExpr();
      this.expect(")");
      const then = this.parseBody();
      let elseBody: Stmt[] | undefined;
      if (this.eat("else")) elseBody = this.parseBody();
      return { kind: "if", test, then, else: elseBody, loc };
    }

    if (this.is("for")) {
      this.next();
      this.expect("(");
      this.eat("const");
      const name = this.ident();
      this.expect("of");
      const iter = this.parseExpr();
      this.expect(")");
      const body = this.parseBody();
      return { kind: "for", name, iter, body, loc };
    }

    if (this.is("return")) {
      this.next();
      let value: Expr | undefined;
      if (!this.is(";") && !this.is("}")) value = this.parseExpr();
      this.eat(";");
      return { kind: "return", value, loc };
    }

    const expr = this.parseExpr();
    for (const op of ["=", "+=", "-=", "*="]) {
      if (this.is(op)) {
        this.next();
        const value = this.parseExpr();
        this.eat(";");
        return { kind: "assign", target: expr, op, value, loc };
      }
    }
    this.eat(";");
    return { kind: "expr", expr, loc };
  }

  // ---------- expressions ----------

  parseExpr(): Expr {
    return this.parseCond();
  }

  private parseCond(): Expr {
    const test = this.parseBinary(0);
    if (this.is("?")) {
      const loc = this.loc();
      this.next();
      const then = this.parseExpr();
      this.expect(":");
      const elseExpr = this.parseExpr();
      return { kind: "cond", test, then, else: elseExpr, loc };
    }
    return test;
  }

  private static PRECEDENCE: string[][] = [
    ["??"],
    ["||"],
    ["&&"],
    ["==", "!="],
    ["<", "<=", ">", ">="],
    [".."],
    ["+", "-"],
    ["*", "/", "%"],
  ];

  private parseBinary(level: number): Expr {
    if (level >= Parser.PRECEDENCE.length) return this.parseUnary();
    let left = this.parseBinary(level + 1);
    for (;;) {
      const op = this.binaryOp(Parser.PRECEDENCE[level]);
      if (!op) return left;
      const loc = this.loc();
      this.pos += op.length;
      const right = this.parseBinary(level + 1);
      left = { kind: "binary", op: op.op, left, right, loc };
    }
  }

  /** Match a binary operator, joining `>` `=` into `>=` (the lexer never emits `>=`). */
  private binaryOp(ops: string[]): { op: string; length: number } | undefined {
    const t = this.peek();
    if (t.kind !== "punct") return undefined;
    if (t.value === ">" && this.is("=", 1) && !this.is("=", 2) && this.peek(1).offset === t.offset + 1) {
      return ops.includes(">=") ? { op: ">=", length: 2 } : undefined;
    }
    return ops.includes(t.value) ? { op: t.value, length: 1 } : undefined;
  }

  private parseUnary(): Expr {
    if (this.is("!") || this.is("-")) {
      const loc = this.loc();
      const op = this.next().value;
      return { kind: "unary", op, arg: this.parseUnary(), loc };
    }
    if (this.is("...")) {
      const loc = this.loc();
      this.next();
      return { kind: "spread", arg: this.parseUnary(), loc };
    }
    let expr = this.parsePostfix();
    while (this.is("as")) {
      const loc = exprLoc(expr);
      this.next();
      expr = { kind: "cast", expr, type: this.parseType(), loc };
    }
    return expr;
  }

  private parsePostfix(): Expr {
    let expr = this.parsePrimary();
    for (;;) {
      // postfix expressions are located at the start of the whole expression
      const loc = exprLoc(expr);
      if (this.is(".") && this.peek(1).kind === "ident") {
        this.next();
        const property = this.ident();
        expr = { kind: "member", object: expr, property, loc };
        continue;
      }
      if (this.is("[")) {
        this.next();
        const index = this.parseExpr();
        this.expect("]");
        expr = { kind: "index", object: expr, index, loc };
        continue;
      }
      if (this.is("<") && (expr.kind === "ident" || expr.kind === "member")) {
        const typeArgs = this.tryTypeArgs();
        if (typeArgs) {
          if (this.is("(")) {
            expr = { kind: "call", callee: expr, typeArgs, args: this.parseArgs(), loc: exprLoc(expr) };
          } else if (this.is("{") && expr.kind === "ident") {
            const type: TypeRef = { name: expr.name, args: typeArgs.map((t) => ({ kind: "type", type: t })), text: expr.name };
            expr = this.parseStructLiteral(type, exprLoc(expr));
          } else if (expr.kind === "ident") {
            expr = { ...expr, typeArgs };
          }
          continue;
        }
        return expr;
      }
      if (this.is("(")) {
        expr = { kind: "call", callee: expr, args: this.parseArgs(), loc: exprLoc(expr) };
        continue;
      }
      return expr;
    }
  }

  private parseArgs(): Expr[] {
    this.expect("(");
    const args: Expr[] = [];
    while (!this.atEnd() && !this.is(")")) {
      args.push(this.parseExpr());
      if (!this.eat(",")) break;
    }
    this.expect(")");
    return args;
  }

  private parseStructLiteral(type: TypeRef, loc: Loc): Expr {
    this.expect("{");
    const fields: { name: string; value: Expr }[] = [];
    while (!this.atEnd() && !this.is("}")) {
      if (this.is("...")) {
        this.next();
        fields.push({ name: "...", value: this.parseExpr() });
      } else {
        const name = this.ident();
        if (this.eat(":")) fields.push({ name, value: this.parseExpr() });
        else fields.push({ name, value: { kind: "ident", name, loc } });
      }
      if (!this.eat(",")) break;
    }
    this.expect("}");
    return { kind: "struct", type, fields, loc };
  }

  private looksLikeStructLiteral(): boolean {
    // Called with the current token at `{`.
    if (!this.is("{")) return false;
    const a = this.peek(1);
    const b = this.peek(2);
    if (a.value === "}") return true;
    if (a.value === "...") return true;
    return a.kind === "ident" && (b.value === ":" || b.value === "," || b.value === "}");
  }

  private isLambdaAhead(): boolean {
    // Current token is `(`; find its match and look at what follows.
    let depth = 0;
    for (let i = this.pos; i < this.tokens.length; i++) {
      const v = this.tokens[i].value;
      if (v === "(") depth++;
      else if (v === ")") {
        depth--;
        if (depth === 0) {
          const after = this.tokens[i + 1]?.value;
          if (after === "=>") return true;
          if (after !== ":") return false;
          // `(a: T): R => ...` vs. the `(x) :` of a conditional expression:
          // only a lambda has `=>` after the return type.
          let d = 0;
          for (let j = i + 2; j < this.tokens.length; j++) {
            const w = this.tokens[j].value;
            if (w === "<" || w === "[" || w === "(") d++;
            else if (w === ">" || w === "]" || w === ")") {
              if (d === 0) return false;
              d--;
            } else if (d === 0 && w === "=>") return true;
            else if (d === 0 && (w === "," || w === ";" || w === "?" || w === "{")) return false;
          }
          return false;
        }
      }
    }
    return false;
  }

  private parsePrimary(): Expr {
    const t = this.peek();
    const loc = this.loc(t);

    if (t.kind === "number") {
      this.next();
      return { kind: "number", value: t.value, loc };
    }
    if (t.kind === "string") {
      this.next();
      return { kind: "string", value: t.value.slice(1, -1), loc };
    }
    if (this.is("(")) {
      if (this.isLambdaAhead()) return this.parseLambda();
      this.next();
      const inner = this.parseExpr();
      this.expect(")");
      return inner;
    }
    if (this.is("[")) {
      this.next();
      const elements: Expr[] = [];
      while (!this.atEnd() && !this.is("]")) {
        elements.push(this.parseExpr());
        if (!this.eat(",")) break;
      }
      this.expect("]");
      return { kind: "vector", elements, loc };
    }
    // Bytes [0x84, ...pad(10, "x"), 0x58]: a byte-vector literal
    if (t.kind === "ident" && t.value === "Bytes" && this.peek(1).value === "[") {
      this.next();
      return this.parsePrimary();
    }
    if (t.kind === "ident") {
      this.next();
      // single-parameter lambda without parentheses: x => ...
      if (this.is("=>")) {
        this.next();
        return { kind: "lambda", params: [{ name: t.value, loc }], body: this.lambdaBody(), loc };
      }
      if (this.is("{") && /^[A-Z]/.test(t.value) && this.looksLikeStructLiteral()) {
        return this.parseStructLiteral({ name: t.value, args: [], text: t.value }, loc);
      }
      return { kind: "ident", name: t.value, loc };
    }
    throw new ParseError(`unexpected '${t.value || "end of file"}' in expression`, loc);
  }

  private parseLambda(): Expr {
    const loc = this.loc();
    const params = this.parseParams();
    if (this.eat(":")) this.parseType();
    this.expect("=>");
    return { kind: "lambda", params, body: this.lambdaBody(), loc };
  }

  private lambdaBody(): Expr | Stmt[] {
    return this.is("{") ? this.parseBlock() : this.parseExpr();
  }
}

function exprLoc(e: Expr): Loc {
  return e.loc;
}

function parseNumber(raw: string): number {
  const n = Number(raw.replace(/_/g, ""));
  return Number.isFinite(n) ? n : 0;
}
