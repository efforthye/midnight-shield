// Checks for the TypeScript/JavaScript side of a Midnight DApp: the code that
// talks to the proof server and holds wallet secrets. These are token-level
// heuristics (no type information), so they report medium confidence.

import type { RawFinding } from "./analyzer.js";
import { isSecretName } from "./analyzer.js";
import { isSecretValue, withSecretValues } from "./secret-flow.js";
import { lex, type Token } from "./lexer.js";
import { checkSdkMore } from "./sdk-checks.js";

export const SDK_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];

export function isSdkFile(file: string): boolean {
  return SDK_EXTENSIONS.some((ext) => file.endsWith(ext)) && !file.endsWith(".d.ts");
}

/** Test files use fake secrets and fake remote servers on purpose, so SDK checks skip them. */
export function isTestFile(file: string): boolean {
  const f = file.split("\\").join("/");
  // test/…, *.test.ts, and scripts named test-*.js or test_*.js
  return /(^|\/)(test|tests|__tests__|__mocks__)\//.test(f) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(f) || /(^|\/)test[-_][^/]*\.[cm]?[jt]sx?$/.test(f);
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
  return withSecretValues(tokens, () => lintSdkTokens(tokens));
}

function lintSdkTokens(tokens: Token[]): RawFinding[] {
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
      const prefixes: string[] = [];
      let d = 0;
      for (let k = 0; k < inner.length; k++) {
        const tok = inner[k];
        if (tok.value === "(" || tok.value === "[") d++;
        else if ((tok.value === ")" || tok.value === "]") && d > 0) d--;
        if (d > 0 || tok.kind !== "ident" || !isSecretValue(tok.value)) continue;
        const next = inner[k + 1]?.value;
        const after = inner[k + 2]?.value ?? "";
        if (next === "." && SAFE_PROPERTIES.has(after)) continue; // secret.kind, seed.length: metadata only
        if (next === "(") continue; // isSecret(...): a function, not the value
        if (inner[k - 1]?.value === "typeof") continue; // typeof seed: the type, not the value
        if (next === "?" || next === "&&") continue; // process.env.SEED ? 'set' : …: whether it is set, not its value
        // keys.coinPublicKey, wallet.address: a public field of a secret object
        if (next === "." && /public|address|^pk$|pk$/i.test(after)) continue;
        if (/public|address/i.test(tok.value)) continue;
        // seed.slice(0, 8): a short prefix to tell keys apart, not enough to recover the secret
        if (next === "." && /^(slice|substring|substr)$/.test(after) && inner[k + 3]?.value === "(" && inner[k + 4]?.value === "0" && inner[k + 5]?.value === "," && Number(inner[k + 6]?.value) <= 12) {
          if (!prefixes.includes(tok.value)) prefixes.push(tok.value);
          continue;
        }
        if (!secrets.includes(tok.value)) secrets.push(tok.value);
      }
      if (!secrets.length && prefixes.length) {
        out.push({
          ruleId: "MS102",
          severity: "low",
          confidence: "medium",
          loc: loc(t),
          message: `The first characters of '${prefixes.join("', '")}' are passed to ${t.value}.${tokens[i + 2].value}(). A short prefix does not give the secret away, but it does narrow it down and shows up in shared logs. Log a hash of it (or nothing) to tell keys apart.`,
        });
      }
      if (secrets.length) {
        // `console.log("SAVE THIS SEED: …")` in a CLI shows a new seed to its owner on purpose. Still worth a
        // look (terminals get recorded, CI captures stdout), but it is not a logging mistake like logger.info(seed).
        let close = i + 3;
        for (let d = 0; close < tokens.length; close++) {
          if (tokens[close].value === "(") d++;
          else if (tokens[close].value === ")" && --d === 0) break;
        }
        // the call itself, and the console output just before it ("=== New wallet (SAVE THIS) ===")
        // (only text that is itself printed: a "backup" key name elsewhere in the code says nothing)
        const printedLines = new Set(tokens.filter((x, k) => x.value === "console" && tokens[k + 1]?.value === "." && x.line < t.line && x.line >= t.line - 4).map((x) => x.line));
        const text = tokens.filter((x, k) => x.kind === "string" && ((k > i && k < close) || printedLines.has(x.line))).map((x) => x.value).join(" ");
        // logger.info(`Your wallet seed is: ${seed}`): shown to the user on purpose, but a logger also writes
        // to its other destinations (log files, CI output), which is the real exposure
        const toUser = t.value !== "console" && /\byour\b[^`'"]*(seed|mnemonic|phrase|key|password)|save|back ?up|write (it |this |them )?down/i.test(text);
        const shownOnPurpose = t.value === "console" && /save|back ?up|write (it |this |them )?down|keep (it|this|them)|store (it|this|them)|don'?t lose|you'?ll need|recovery (words|phrase)|exactly as printed/i.test(text);
        out.push({
          ruleId: "MS102",
          severity: shownOnPurpose ? "low" : toUser ? "medium" : "high",
          confidence: "medium",
          loc: loc(t),
          message: shownOnPurpose
            ? `'${secrets.join("', '")}' is printed for the user to save. That is fine in an interactive CLI, but stdout is often recorded (CI logs, terminal history, screen sharing). Print it only when a person is at the terminal, and never in scripts that run in CI.`
            : toUser
              ? `'${secrets.join("', '")}' is shown to the user through ${t.value}.${tokens[i + 2].value}(). A logger also writes it to its other destinations (log files on disk, CI output, log services), where it stays. Print it once with console, only when a person is at the terminal, and keep it out of the logger.`
              : `'${secrets.join("', '")}' looks like a secret and is passed to ${t.value}.${tokens[i + 2].value}(). Logs are stored and shared (CI output, crash reports, browser consoles). Remove it or log a non-reversible identifier instead.`,
        });
      }
    }
  }
  out.push(...hardcodedSecrets(tokens), ...browserStorage(tokens), ...indexedDbStorage(tokens), ...insecureRandomness(tokens), ...secretsOverNetwork(tokens), ...checkSdkMore(tokens));
  return out;
}

/** A string that looks like real key material: 32 random bytes in hex, or a BIP-39 style mnemonic. */
function looksLikeKeyMaterial(literal: string): "hex" | "mnemonic" | undefined {
  const v = literal.slice(1, -1).trim();
  const hex = v.replace(/^0x/i, "");
  // low-entropy values such as 000…001 are well-known development seeds, not leaks
  // placeholders such as a1b2c3d4…, abcdef0123…, or the same 16 or 32 characters repeated, are not keys
  const placeholder = (h: string) =>
    h.slice(0, 32) === h.slice(32) ||
    h.slice(0, 16).repeat(4) === h ||
    /(?:0123456789|123456789a|abcdef|a1b2c3d4|deadbeef|cafebabe|feedface)/i.test(h);
  if (/^[0-9a-fA-F]{64}$/.test(hex) && new Set(hex.toLowerCase()).size >= 8 && !placeholder(hex)) return "hex";
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
    return (t.kind === "ident" || t.kind === "string") && (/privatestate/i.test(v.replace(/[-_\s]/g, "")) || (t.kind === "ident" ? isSecretValue(v) : isSecretName(v)));
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

/** MS104 for IndexedDB-style stores: store.put(privateState), localforage.setItem("seed", …), idbSet("private-state", …). */
const IDB_OBJECT = /(idb|indexeddb|objectstore|store|db|localforage|keyval|dexie|table)$/i;
const IDB_METHODS = new Set(["put", "add", "set", "setItem"]);
function indexedDbStorage(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  const usesIdbKeyval = tokens.some((x) => x.kind === "string" && /idb-keyval/.test(x.value));
  // const store = providers.privateStateProvider: Midnight's own private state store, encrypted by design
  const providerNames = new Set<string>();
  for (let i = 1; i + 2 < tokens.length; i++) {
    if (tokens[i].kind !== "ident" || tokens[i + 1].value !== "=" || !["const", "let", "var"].includes(tokens[i - 1].value)) continue;
    for (let j = i + 2; j < tokens.length && j < i + 12 && tokens[j].value !== ";"; j++) if (/privateStateProvider/i.test(tokens[j].value)) providerNames.add(tokens[i].value);
    // const store = new Map(): kept in memory for the session, not written to the browser
    if (tokens[i + 2].value === "new" && /^(Map|WeakMap|Set)$/.test(tokens[i + 3]?.value ?? "")) providerNames.add(tokens[i].value);
  }
  for (let i = 0; i + 3 < tokens.length; i++) {
    const t = tokens[i];
    let open = -1;
    if (t.kind === "ident" && IDB_OBJECT.test(t.value) && tokens[i + 1].value === "." && IDB_METHODS.has(tokens[i + 2].value) && tokens[i + 3].value === "(") open = i + 3;
    else if (t.kind === "ident" && (t.value === "set" || t.value === "setMany") && tokens[i - 1]?.value !== "." && tokens[i + 1].value === "(" && usesIdbKeyval) open = i + 1;
    if (open === -1 || providerNames.has(t.value) || /privateStateProvider/i.test(t.value)) continue;
    const parts: Token[] = [];
    for (let j = open, depth = 0; j < tokens.length; j++) {
      const v = tokens[j].value;
      if (v === "(") depth++;
      else if (v === ")" && --depth === 0) break;
      if (j === open) continue;
      if (tokens[j].kind === "string") parts.push(tokens[j], ...templateExpressionTokens(tokens[j]));
      else parts.push(tokens[j]);
    }
    const hit = parts.find((x) => {
      if (x.kind !== "ident" && x.kind !== "string") return false;
      const v = x.kind === "string" ? x.value.slice(1, -1) : x.value;
      return /privatestate/i.test(v.replace(/[-_\s]/g, "")) || (x.kind === "ident" ? isSecretValue(v) : isSecretName(v));
    });
    if (!hit) continue;
    out.push({
      ruleId: "MS104",
      severity: "high",
      confidence: "medium",
      loc: { line: t.line, col: t.col },
      message: `Private data ('${hit.kind === "string" ? hit.value.slice(1, -1) : hit.value}') is saved to browser storage (${t.value}) unencrypted, where any script on the page can read it (an extension, an injected script, a compromised dependency). Keep private state in the Midnight private state provider, or encrypt it with a key the user controls.`,
    });
  }
  return out;
}

/** Names of values that must be unpredictable: secrets, plus nonces, salts and randomness. */
// "random" on its own is an adjective (randomHex for a mock address, randomDelay); the nouns are what must be secret
const isRandomnessName = (name: string) => isSecretName(name) || /(^|_)(nonce|salt|randomness|rand|blind(ing)?(_factor)?|entropy|coin_?seed)(?![a-z])/i.test(name.replace(/([a-z0-9])([A-Z])/g, "$1_$2"));

/** The tokens of the statement around index i: back to the previous `;`, or a `{`/`}` outside any parentheses. */
function statementAround(tokens: Token[], i: number): Token[] {
  let start = i;
  let paren = 0; // < 0 while inside the arguments of an enclosing call
  let brace = 0; // > 0 while inside an object literal or block that closes before i
  for (let j = i - 1; j >= 0; j--) {
    const v = tokens[j].value;
    if (v === ")" || v === "]") paren++;
    else if (v === "(" || v === "[") paren--;
    else if (v === "}") {
      if (paren >= 0 && brace === 0) break;
      brace++;
    } else if (v === "{") {
      if (brace === 0) break;
      brace--;
    } else if (v === ";" && paren >= 0 && brace === 0) break;
    start = j;
  }
  return tokens.slice(start, i + 1);
}

/** MS105: Math.random() used to make a secret, seed, key, nonce, salt or commitment randomness. */
/** The name a value at index i is assigned to: `name = …`, `name: …`, or the function it is returned from. */
function assignedName(tokens: Token[], i: number): string | undefined {
  const stmt = statementAround(tokens, i);
  const names: string[] = [];
  for (let k = 0; k + 1 < stmt.length; k++) {
    const next = stmt[k + 1].value;
    if (stmt[k].kind === "ident" && (next === "=" || next === ":") && stmt[k + 2]?.value !== "=" && stmt[k + 2]?.value !== ">") names.push(stmt[k].value);
  }
  if (names.length) return names.find(isRandomnessName) ?? names[0];
  for (let j = i - 1; j >= 0 && j >= i - 200; j--) {
    if (tokens[j].value === "function" && tokens[j + 1]?.kind === "ident") return tokens[j + 1].value;
  }
  return undefined;
}

function insecureRandomness(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  const isMathRandom = (i: number) => tokens[i].value === "Math" && tokens[i + 1]?.value === "." && tokens[i + 2]?.value === "random" && tokens[i + 3]?.value === "(";
  // values and wrappers made from Math.random() under a neutral name: `const r = Math.random()`, `const rnd = () => Math.random()`
  const tainted = new Set<string>();
  const flag = (i: number, target: string) =>
    out.push({
      ruleId: "MS105",
      severity: "high",
      confidence: "medium",
      loc: { line: tokens[i].line, col: tokens[i].col },
      message: `'${target}' is made with Math.random(), which is not cryptographically secure: its output can be predicted from earlier values. Secrets, seeds, nonces and commitment randomness need crypto.getRandomValues() (browser) or crypto.randomBytes() (Node.js).`,
    });
  // follow only names bound once (`const r = …`): a `let` that is reassigned elsewhere
  // (a mock value in a fallback branch, a real one otherwise) is not one random value
  const assignments = new Map<string, number>();
  const declaredConst = new Set<string>();
  for (let i = 1; i + 1 < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind !== "ident") continue;
    if (tokens[i - 1].value === "const") declaredConst.add(t.value);
    if (tokens[i + 1].value === "=" && tokens[i + 2]?.value !== "=" && tokens[i - 1].value !== ".") assignments.set(t.value, (assignments.get(t.value) ?? 0) + 1);
  }
  const constOnly = (name: string) => declaredConst.has(name) && (assignments.get(name) ?? 0) <= 1;
  for (let pass = 0; pass < 2; pass++) {
    for (let i = 0; i + 3 < tokens.length; i++) {
      // `if (crypto.getRandomValues) … else Math.random()`: a fallback for environments without crypto
      const fallback = (k: number) => tokens.slice(Math.max(0, k - 40), k).some((t) => t.value === "getRandomValues" || t.value === "randomBytes") && tokens.slice(Math.max(0, k - 30), k).some((t) => t.value === "else");
      // xs.sort(() => Math.random() - 0.5): shuffling an order, not making a value
      const shuffle = (k: number) => tokens.slice(Math.max(0, k - 7), k).some((t, m, arr) => t.value === "sort" && arr[m + 1]?.value === "(");
      const direct = isMathRandom(i) && !fallback(i) && !shuffle(i);
      const viaName = pass === 1 && tokens[i].kind === "ident" && tainted.has(tokens[i].value) && tokens[i + 1]?.value !== "=" && tokens[i + 1]?.value !== ":" && tokens[i - 1]?.value !== "const" && tokens[i - 1]?.value !== "let" && tokens[i - 1]?.value !== "function";
      // (`temperature: number` is a parameter or an object key that happens to share the tainted name, not the value)
      if (!(pass === 0 ? direct : viaName)) continue;
      const target = assignedName(tokens, i);
      if (!target) continue;
      if (isRandomnessName(target)) {
        if (!out.some((f) => f.loc.line === tokens[i].line)) flag(i, target);
      } else if (pass === 0 && constOnly(target)) tainted.add(target);
    }
  }
  return out;
}

const PASS_THROUGH_FNS = new Set(["stringify", "encodeURIComponent", "encodeURI", "String", "from", "toString", "btoa", "toHex", "toBase64"]);
const NETWORK_CALLS = new Set(["fetch", "axios", "request", "got", "ky", "XMLHttpRequest"]);
const NETWORK_METHODS = new Set(["get", "post", "put", "patch", "delete", "request", "open", "send", "sendBeacon"]);

/** MS106: a secret key, seed or password sent in a network request (URL, query or body). */
function secretsOverNetwork(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i + 1 < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind !== "ident") continue;
    let open = -1;
    let what = "";
    if (NETWORK_CALLS.has(t.value) && tokens[i + 1].value === "(" && tokens[i - 1]?.value !== ".") {
      open = i + 1;
      what = `${t.value}()`;
    } else if (
      (NETWORK_CALLS.has(t.value) || ["http", "https", "navigator", "xhr", "client", "api"].includes(t.value) || /(^ws|socket|websocket|channel|peer|conn(ection)?)$/i.test(t.value)) &&
      tokens[i + 1].value === "." &&
      NETWORK_METHODS.has(tokens[i + 2]?.value ?? "") &&
      tokens[i + 3]?.value === "("
    ) {
      open = i + 3;
      what = `${t.value}.${tokens[i + 2].value}()`;
    }
    if (open === -1) continue;
    const args: Token[] = [];
    for (let j = open, depth = 0; j < tokens.length; j++) {
      const v = tokens[j].value;
      if (v === "(" || v === "[" || v === "{") depth++;
      else if ((v === ")" || v === "]" || v === "}") && --depth === 0) break;
      if (j === open) continue;
      if (tokens[j].kind === "string") args.push(...templateExpressionTokens(tokens[j]));
      else args.push(tokens[j]);
    }
    // a secret passed through another function first (publicKeyOf(seed)) is a derived value,
    // except functions that only encode it (JSON.stringify, encodeURIComponent, …)
    const derivedDepth: number[] = [];
    let derived = 0;
    const secret = args.find((a, k) => {
      if (a.value === "(") {
        const fn = args[k - 1];
        const encodes = fn?.kind === "ident" && PASS_THROUGH_FNS.has(fn.value);
        const isCall = fn?.kind === "ident" || fn?.value === ")";
        derivedDepth.push(isCall && !encodes ? 1 : 0);
        derived += derivedDepth[derivedDepth.length - 1];
        return false;
      }
      if (a.value === ")") {
        derived -= derivedDepth.pop() ?? 0;
        return false;
      }
      if (derived > 0 || a.kind !== "ident" || !isSecretValue(a.value)) return false;
      const next = args[k + 1]?.value;
      if (next === "(") return false; // a function such as hashSecret(...)
      if (next === "." && SAFE_PROPERTIES.has(args[k + 2]?.value ?? "")) return false;
      return true;
    });
    if (!secret) continue;
    out.push({
      ruleId: "MS106",
      severity: "high",
      confidence: "medium",
      loc: { line: t.line, col: t.col },
      message: `'${secret.value}' looks like a secret and is sent in a network request (${what}). Whoever runs or logs that server, proxy or analytics endpoint can read it. Keep secrets on the user's device; send a public key, a signature or a hash instead.`,
    });
  }
  return out;
}
