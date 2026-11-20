// Tokenizer for the Compact language.
// It keeps line/column for every token and collects comments separately so the
// suppression logic can read `shield-disable` directives.

export type TokenKind = "ident" | "number" | "string" | "punct" | "eof";

export interface Token {
  kind: TokenKind;
  value: string;
  line: number; // 1-based
  col: number; // 1-based
  offset: number;
}

export interface Comment {
  text: string;
  line: number;
  endLine: number;
}

export interface LexResult {
  tokens: Token[];
  comments: Comment[];
}

// Longest first. `>` is always emitted alone so nested generics such as
// `Vector<2, Bytes<32>>` close correctly; the parser joins `>` `=` when needed.
const PUNCTUATORS = [
  "...", "..", "=>", "::", "??", "&&", "||", "<=", "==", "!=", "+=", "-=", "*=",
  "{", "}", "(", ")", "[", "]", "<", ">", ";", ",", ".", ":", "?", "=", "+",
  "-", "*", "/", "%", "!", "#", "&", "|", "^", "@",
];

export function lex(source: string): LexResult {
  const tokens: Token[] = [];
  const comments: Comment[] = [];
  let i = 0;
  let line = 1;
  let col = 1;

  const advance = (n: number) => {
    for (let k = 0; k < n; k++) {
      if (source[i] === "\n") {
        line++;
        col = 1;
      } else {
        col++;
      }
      i++;
    }
  };

  while (i < source.length) {
    const ch = source[i];

    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
      advance(1);
      continue;
    }

    // line comment
    if (ch === "/" && source[i + 1] === "/") {
      const start = i;
      const startLine = line;
      while (i < source.length && source[i] !== "\n") advance(1);
      comments.push({ text: source.slice(start + 2, i), line: startLine, endLine: startLine });
      continue;
    }

    // block comment
    if (ch === "/" && source[i + 1] === "*") {
      const start = i;
      const startLine = line;
      advance(2);
      while (i < source.length && !(source[i] === "*" && source[i + 1] === "/")) advance(1);
      advance(2);
      comments.push({ text: source.slice(start + 2, Math.max(start + 2, i - 2)), line: startLine, endLine: line });
      continue;
    }

    const tokLine = line;
    const tokCol = col;
    const tokOffset = i;

    if (ch === '"' || ch === "'") {
      const quote = ch;
      let j = i + 1;
      while (j < source.length && source[j] !== quote) {
        if (source[j] === "\\") j++;
        j++;
      }
      const raw = source.slice(i, j + 1);
      advance(j + 1 - i);
      tokens.push({ kind: "string", value: raw, line: tokLine, col: tokCol, offset: tokOffset });
      continue;
    }

    if (/[0-9]/.test(ch)) {
      let j = i;
      if (ch === "0" && /[xXbBoO]/.test(source[i + 1] ?? "")) {
        j += 2;
        while (j < source.length && /[0-9a-fA-F_]/.test(source[j])) j++;
      } else {
        // stop before `..` so `0..10` lexes as 0 .. 10
        while (j < source.length && /[0-9_]/.test(source[j])) j++;
      }
      const raw = source.slice(i, j);
      advance(j - i);
      tokens.push({ kind: "number", value: raw, line: tokLine, col: tokCol, offset: tokOffset });
      continue;
    }

    if (/[A-Za-z_$]/.test(ch)) {
      let j = i;
      while (j < source.length && /[A-Za-z0-9_$]/.test(source[j])) j++;
      const raw = source.slice(i, j);
      advance(j - i);
      tokens.push({ kind: "ident", value: raw, line: tokLine, col: tokCol, offset: tokOffset });
      continue;
    }

    const p = PUNCTUATORS.find((op) => source.startsWith(op, i));
    if (p) {
      advance(p.length);
      tokens.push({ kind: "punct", value: p, line: tokLine, col: tokCol, offset: tokOffset });
      continue;
    }

    // Unknown character: emit it so the parser can report a precise error.
    advance(1);
    tokens.push({ kind: "punct", value: ch, line: tokLine, col: tokCol, offset: tokOffset });
  }

  tokens.push({ kind: "eof", value: "", line, col, offset: i });
  return { tokens, comments };
}
