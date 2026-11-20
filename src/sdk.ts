// Checks for the TypeScript/JavaScript side of a Midnight DApp: the code that
// talks to the proof server and holds wallet secrets. These are token-level
// heuristics (no type information), so they report medium confidence.

import type { RawFinding } from "./analyzer.js";
import { isSecretName } from "./analyzer.js";
import { lex, type Token } from "./lexer.js";

export const SDK_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];

export function isSdkFile(file: string): boolean {
  return SDK_EXTENSIONS.some((ext) => file.endsWith(ext)) && !file.endsWith(".d.ts");
}

/** Test files use fake secrets and fake remote servers on purpose, so SDK checks skip them. */
export function isTestFile(file: string): boolean {
  const f = file.split("\\").join("/");
  return /(^|\/)(test|tests|__tests__|__mocks__)\//.test(f) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(f);
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal", "proof-server"]);
const LOG_OBJECTS = new Set(["console", "logger", "log"]);
const LOG_METHODS = new Set(["log", "info", "debug", "warn", "error", "trace"]);

function urlHost(literal: string): { host: string; port?: string } | undefined {
  const m = literal.slice(1, -1).match(/^(?:https?|wss?):\/\/(\[[^\]]+\]|[^/:?#]+)(?::(\d+))?/i);
  return m ? { host: m[1].toLowerCase(), port: m[2] } : undefined;
}

/** Identifiers used inside the ${...} parts of a template literal token. */
function templateExpressionTokens(t: Token): Token[] {
  if (!t.value.startsWith("`")) return [];
  const out: Token[] = [];
  const re = /\$\{([^}]*)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(t.value))) {
    for (const inner of lex(m[1]).tokens) if (inner.kind !== "eof") out.push({ ...inner, line: t.line, col: t.col });
  }
  return out;
}

const SAFE_PROPERTIES = new Set(["kind", "type", "length", "size", "name", "id", "label", "source", "constructor", "network", "networkId"]);
const BOUNDARY = new Set([",", ";", "{", "}"]);

export function lintSdkSource(source: string): RawFinding[] {
  const { tokens } = lex(source);
  const out: RawFinding[] = [];
  const loc = (t: Token) => ({ line: t.line, col: t.col });

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];

    // MS101: a proof-server URL that is not local
    if (t.kind === "string" && !t.value.startsWith("`")) {
      const u = urlHost(t.value);
      if (u && !LOCAL_HOSTS.has(u.host)) {
        // the property, variable or call this string belongs to (back to the previous , ; { })
        let mentionsProof = false;
        for (let j = i - 1, depth = 0; j >= 0 && j >= i - 16; j--) {
          const v = tokens[j].value;
          if (v === ")" || v === "]") depth++;
          else if (v === "(" || v === "[") {
            if (depth === 0) {
              // a call like httpClientProofProvider('...')
              if (/proof/i.test(tokens[j - 1]?.value ?? "")) mentionsProof = true;
              continue;
            }
            depth--;
          } else if (depth === 0 && BOUNDARY.has(v)) break;
          if (depth === 0 && (tokens[j].kind === "ident" || tokens[j].kind === "string") && /proof/i.test(v)) mentionsProof = true;
        }
        if (u.port === "6300" || mentionsProof) {
          out.push({
            ruleId: "MS101",
            severity: "critical",
            confidence: "medium",
            loc: loc(t),
            message: `The proof server points to a remote host (${u.host}). The proof server receives every user's private inputs in plain form, so a remote one sees all of them. Run it locally (http://localhost:6300) or on a machine the user controls.`,
          });
        }
      }
    }

    // MS102: a secret passed to a log call
    if (t.kind === "ident" && LOG_OBJECTS.has(t.value) && tokens[i + 1]?.value === "." && LOG_METHODS.has(tokens[i + 2]?.value ?? "") && tokens[i + 3]?.value === "(") {
      // tokens of the call's arguments, with template ${...} expressions expanded
      let depth = 0;
      const inner: Token[] = [];
      for (let j = i + 3; j < tokens.length; j++) {
        const v = tokens[j].value;
        if (v === "(") depth++;
        else if (v === ")" && --depth === 0) break;
        if (j === i + 3) continue;
        if (tokens[j].kind === "string") inner.push(...templateExpressionTokens(tokens[j]));
        else inner.push(tokens[j]);
      }
      // only values passed directly count: `log(secret)` or `${secret}`; a secret passed
      // through another call first (`log(publicKeyOf(secret))`) is a derived value
      const secrets: string[] = [];
      let d = 0;
      for (let k = 0; k < inner.length; k++) {
        const tok = inner[k];
        if (tok.value === "(" || tok.value === "[") d++;
        else if ((tok.value === ")" || tok.value === "]") && d > 0) d--;
        if (d > 0 || tok.kind !== "ident" || !isSecretName(tok.value)) continue;
        const next = inner[k + 1]?.value;
        const after = inner[k + 2]?.value ?? "";
        if (next === "." && SAFE_PROPERTIES.has(after)) continue; // secret.kind, seed.length: metadata only
        if (next === "(") continue; // isSecret(...): a function, not the value
        if (!secrets.includes(tok.value)) secrets.push(tok.value);
      }
      if (secrets.length) {
        out.push({
          ruleId: "MS102",
          severity: "high",
          confidence: "medium",
          loc: loc(t),
          message: `'${secrets.join("', '")}' looks like a secret and is passed to ${t.value}.${tokens[i + 2].value}(). Logs are stored and shared (CI output, crash reports, browser consoles). Remove it or log a non-reversible identifier instead.`,
        });
      }
    }
  }
  out.push(...hardcodedSecrets(tokens), ...browserStorage(tokens));
  return out;
}

/** A string that looks like real key material: 32 random bytes in hex, or a BIP-39 style mnemonic. */
function looksLikeKeyMaterial(literal: string): "hex" | "mnemonic" | undefined {
  const v = literal.slice(1, -1).trim();
  const hex = v.replace(/^0x/i, "");
  // low-entropy values such as 000…001 are well-known development seeds, not leaks
  if (/^[0-9a-fA-F]{64}$/.test(hex) && new Set(hex.toLowerCase()).size >= 8) return "hex";
  const words = v.split(/\s+/);
  if ([12, 15, 18, 21, 24].includes(words.length) && words.every((w) => /^[a-z]{3,8}$/.test(w)) && new Set(words).size >= 8) return "mnemonic";
  return undefined;
}

/** MS103: a seed, secret key or mnemonic written into the source as a literal. */
function hardcodedSecrets(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i + 2 < tokens.length; i++) {
    const name = tokens[i];
    const op = tokens[i + 1];
    const value = tokens[i + 2];
    const isName = name.kind === "ident" || (name.kind === "string" && !name.value.startsWith("`"));
    if (!isName || (op.value !== "=" && op.value !== ":")) continue;
    if (tokens[i + 3]?.value === "=" || value.kind !== "string" || value.value.startsWith("`")) continue;
    const key = name.kind === "string" ? name.value.slice(1, -1) : name.value;
    if (!isSecretName(key)) continue;
    const kind = looksLikeKeyMaterial(value.value);
    if (!kind) continue;
    out.push({
      ruleId: "MS103",
      severity: "critical",
      confidence: "medium",
      loc: { line: value.line, col: value.col },
      message: `'${key}' is set to a ${kind === "hex" ? "32-byte hex key" : "recovery phrase"} written in the source. Anyone who can read the code or the bundle (a public repo, a deployed web app) can use it. Load it from an environment variable or the user's wallet instead, and treat this one as leaked.`,
    });
  }
  return out;
}

const STORAGES = new Set(["localStorage", "sessionStorage"]);

/** MS104: private state or a secret saved to localStorage/sessionStorage, which any script on the page can read. */
function browserStorage(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  const sensitive = (t: Token) => {
    const v = t.kind === "string" ? t.value.slice(1, -1) : t.value;
    return (t.kind === "ident" || t.kind === "string") && (/privatestate/i.test(v.replace(/[-_\s]/g, "")) || isSecretName(v));
  };
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind !== "ident" || !STORAGES.has(t.value)) continue;
    // the tokens that make up this write: setItem(...) arguments, or the `= value` of an assignment
    let parts: Token[] = [];
    if (tokens[i + 1]?.value === "." && tokens[i + 2]?.value === "setItem" && tokens[i + 3]?.value === "(") {
      for (let j = i + 4, depth = 1; j < tokens.length; j++) {
        if (tokens[j].value === "(") depth++;
        else if (tokens[j].value === ")" && --depth === 0) break;
        if (tokens[j].kind === "string") parts.push(tokens[j], ...templateExpressionTokens(tokens[j]));
        else parts.push(tokens[j]);
      }
    } else {
      let j = i + 1;
      if (tokens[j]?.value === "." && tokens[j + 1]?.kind === "ident") j += 2;
      else if (tokens[j]?.value === "[") {
        while (j < tokens.length && tokens[j].value !== "]") parts.push(tokens[j++]);
        j++;
      } else continue;
      if (tokens[j]?.value !== "=" || tokens[j + 1]?.value === "=") continue;
      parts.push(tokens[j - 1]);
      for (let k = j + 1; k < tokens.length && tokens[k].value !== ";" && tokens[k].line === tokens[j].line; k++) parts.push(tokens[k]);
    }
    const hit = parts.find(sensitive);
    if (!hit) continue;
    out.push({
      ruleId: "MS104",
      severity: "high",
      confidence: "medium",
      loc: { line: t.line, col: t.col },
      message: `Private data ('${hit.kind === "string" ? hit.value.slice(1, -1) : hit.value}') is saved to ${t.value}, which stores it unencrypted and lets any script on the page read it (an extension, an injected script, a compromised dependency). Keep private state in the Midnight private state provider, or encrypt it with a key the user controls.`,
    });
  }
  return out;
}
