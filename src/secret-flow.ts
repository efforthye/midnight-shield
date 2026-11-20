// Which variables in a DApp file hold a secret, by where the value comes from
// rather than only by its name. `const x = privateState.secretKey` makes `x` a
// secret even though its name says nothing, and so does a value produced by a
// seed or key generator, or copied or re-encoded from another secret.

import { isSecretName } from "./analyzer.js";
import type { Token } from "./lexer.js";

/** Functions whose result is key material. */
const SECRET_SOURCES =
  /^(generateRandomSeed|generateSeed|randomSeed|generateMnemonic|mnemonicToSeed(Sync)?|mnemonicToEntropy|mnemonicToMiniSecret|deriveSecretKey|exportSecretKey|getSecretKey|getPrivateKey|exportPrivateKey|exportSeed|getSeed|fromMnemonic|toSeed|seedFromMnemonic)$/;
/** Functions that only copy or re-encode a value. */
const PASS_THROUGH = /^(toHex|toString|fromHex|from|bytesToHex|hexToBytes|toBase64|fromBase64|btoa|atob|encode|decode|slice|subarray|trim|String|Uint8Array|Buffer|stringify|parse|structuredClone)$/;

let current = new Set<string>();

/** A variable that holds a secret: named like one, or assigned from a secret source in this file. */
export function isSecretValue(name: string): boolean {
  return isSecretName(name) || current.has(name);
}

/** Run `fn` with the secret variables of this file in scope. */
export function withSecretValues<T>(tokens: Token[], fn: () => T): T {
  const previous = current;
  current = secretVariables(tokens);
  try {
    return fn();
  } finally {
    current = previous;
  }
}

export function secretVariables(tokens: Token[]): Set<string> {
  const found = new Set<string>();
  // declarations: `const|let|var name = <rhs>` and `name: alias` in a destructuring
  const decls: { name: string; rhs: Token[] }[] = [];
  for (let i = 1; i + 2 < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind !== "ident" || !["const", "let", "var"].includes(tokens[i - 1].value) || tokens[i + 1].value !== "=") continue;
    const rhs: Token[] = [];
    let depth = 0;
    for (let j = i + 2; j < tokens.length; j++) {
      const v = tokens[j].value;
      if (v === "(" || v === "[" || v === "{") depth++;
      else if (v === ")" || v === "]" || v === "}") depth--;
      if (depth < 0 || (depth === 0 && (v === ";" || v === ","))) break;
      if (tokens[j].line > t.line + 4) break;
      rhs.push(tokens[j]);
    }
    if (rhs.some((x) => x.value === "=>" || x.value === "function")) continue; // a function, not a value
    decls.push({ name: t.value, rhs });
  }
  // const { secretKey: k } = …  →  k
  for (let i = 1; i + 2 < tokens.length; i++) {
    if (tokens[i].kind === "ident" && isSecretName(tokens[i].value) && tokens[i + 1].value === ":" && tokens[i + 2].kind === "ident") {
      let j = i - 1;
      while (j > 0 && tokens[j].value !== "{" && tokens[j].value !== ";" && tokens[j].value !== "(") j--;
      if (tokens[j]?.value === "{" && ["const", "let", "var"].includes(tokens[j - 1]?.value)) found.add(tokens[i + 2].value);
    }
  }
  const sourced = (all: Token[]): boolean => {
    const rhs = all.filter((x) => x.value !== "await");
    // the whole value is a secret property: privateState.secretKey, wallet.keys.seed
    const isPath = rhs.every((x, k) => (k % 2 === 0 ? x.kind === "ident" : x.value === "." || x.value === "?."));
    if (isPath && rhs.length >= 3 && isSecretName(rhs[rhs.length - 1].value)) return true;
    // the whole value is a call to a key or seed generator: generateMnemonic(), wallet.exportSeed()
    let depth = 0;
    for (let k = 0; k < rhs.length; k++) {
      const x = rhs[k];
      if (x.value === "(") depth++;
      else if (x.value === ")") depth--;
      if (depth === 0 && x.kind === "ident" && SECRET_SOURCES.test(x.value) && rhs[k + 1]?.value === "(") {
        // nothing may wrap it: the tokens before are a plain object path
        const before = rhs.slice(0, k);
        if (before.every((y, m) => (m % 2 === 0 ? y.kind === "ident" : y.value === "." || y.value === "?."))) return true;
      }
    }
    // a copy or re-encoding of a known secret: every identifier is either that secret or a pass-through
    const idents = rhs.filter((x, k) => x.kind === "ident" && rhs[k - 1]?.value !== ".");
    const secretIdent = idents.find((x) => found.has(x.value) || isSecretName(x.value));
    return !!secretIdent && idents.every((x) => x === secretIdent || PASS_THROUGH.test(x.value) || x.value === "await" || x.value === "new");
  };
  for (let pass = 0; pass < 3; pass++) {
    for (const d of decls) if (!found.has(d.name) && !isSecretName(d.name) && sourced(d.rhs)) found.add(d.name);
  }
  return found;
}
