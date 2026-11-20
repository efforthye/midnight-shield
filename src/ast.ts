// AST for the subset of Compact that Midnight Shield analyzes.

export interface Loc {
  line: number;
  col: number;
}

export interface TypeRef {
  name: string; // e.g. "Bytes", "Uint", "Vector", "[]"
  args: TypeArg[];
  text: string; // source text, for messages
}

export type TypeArg =
  | { kind: "type"; type: TypeRef }
  | { kind: "number"; value: number }
  | { kind: "range"; from: number; to: number }
  | { kind: "string"; value: string }
  | { kind: "param"; name: string };

export type Expr =
  | { kind: "ident"; name: string; typeArgs?: TypeRef[]; loc: Loc }
  | { kind: "number"; value: string; loc: Loc }
  | { kind: "string"; value: string; loc: Loc }
  | { kind: "call"; callee: Expr; typeArgs?: TypeRef[]; args: Expr[]; loc: Loc }
  | { kind: "member"; object: Expr; property: string; loc: Loc }
  | { kind: "index"; object: Expr; index: Expr; loc: Loc }
  | { kind: "vector"; elements: Expr[]; loc: Loc }
  | { kind: "struct"; type: TypeRef; fields: { name: string; value: Expr }[]; loc: Loc }
  | { kind: "binary"; op: string; left: Expr; right: Expr; loc: Loc }
  | { kind: "unary"; op: string; arg: Expr; loc: Loc }
  | { kind: "cast"; expr: Expr; type: TypeRef; loc: Loc }
  | { kind: "cond"; test: Expr; then: Expr; else: Expr; loc: Loc }
  | { kind: "lambda"; params: Param[]; body: Expr | Stmt[]; loc: Loc }
  | { kind: "spread"; arg: Expr; loc: Loc };

export interface Param {
  name: string;
  type?: TypeRef;
  loc: Loc;
}

export type Stmt =
  | { kind: "const"; names: string[]; type?: TypeRef; init: Expr; loc: Loc }
  | { kind: "assign"; target: Expr; op: string; value: Expr; loc: Loc }
  | { kind: "if"; test: Expr; then: Stmt[]; else?: Stmt[]; loc: Loc }
  | { kind: "for"; name: string; iter: Expr; body: Stmt[]; loc: Loc }
  | { kind: "return"; value?: Expr; loc: Loc }
  | { kind: "expr"; expr: Expr; loc: Loc }
  | { kind: "block"; body: Stmt[]; loc: Loc };

export type Decl =
  | { kind: "pragma"; text: string; loc: Loc }
  | { kind: "ledger"; name: string; type: TypeRef; exported: boolean; sealed: boolean; loc: Loc }
  | { kind: "witness"; name: string; params: Param[]; returnType?: TypeRef; loc: Loc }
  | {
      kind: "circuit";
      name: string;
      params: Param[];
      returnType?: TypeRef;
      body?: Stmt[];
      exported: boolean;
      pure: boolean;
      loc: Loc;
    }
  | { kind: "constructor"; params: Param[]; body: Stmt[]; loc: Loc }
  | { kind: "struct"; name: string; fields: Param[]; loc: Loc }
  | { kind: "enum"; name: string; members: string[]; loc: Loc }
  | { kind: "typeAlias"; name: string; type: TypeRef; loc: Loc }
  | { kind: "module"; name: string; decls: Decl[]; loc: Loc };

export interface ParseDiagnostic {
  message: string;
  loc: Loc;
}

export interface Program {
  decls: Decl[];
  diagnostics: ParseDiagnostic[];
}
