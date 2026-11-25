// More token-level checks for DApp TypeScript/JavaScript:
//   MS107 tls-verification-disabled   certificate checks turned off
//   MS108 dynamic-code-execution      eval, new Function, or a string passed to setTimeout
//   MS109 insecure-transport          a remote indexer or node reached over http:// or ws://
//   MS110 secret-in-error             a secret put into an error message
//   MS111 secret-written-to-file      a secret written to disk unencrypted
//   MS112 postmessage-wildcard        postMessage to any origin ("*")
//   MS113 weak-witness-randomness     a witness implementation returns zero bytes or a clock value as randomness
//   MS114 secret-in-url               a secret put into the page URL, query string or history
//   MS115 hardcoded-password          a password or passphrase written into the source
//   MS116 secret-rendered-in-ui       a secret shown in JSX
//   MS117 secret-sent-to-analytics    a secret passed to an analytics or error-tracking call
//   MS118 unsafe-html                 HTML from a variable written into the page (innerHTML, dangerouslySetInnerHTML)
//   MS119 secret-in-public-env        a secret read from a variable that the bundler ships to the browser
//   MS120 secret-from-public-data     a secret computed only from public values (an address, a public key)

import type { RawFinding } from "./analyzer.js";
import { isSecretName } from "./analyzer.js";
import { isSecretValue, withSecretValues } from "./secret-flow.js";
import { lex, type Token } from "./lexer.js";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal"]);
const SAFE_PROPERTIES = new Set(["kind", "type", "length", "size", "name", "id", "label", "source", "constructor", "network", "networkId", "message"]);
const loc = (t: Token) => ({ line: t.line, col: t.col });

/** Index of the `)` that closes the `(` at `open`. */
function closeOf(tokens: Token[], open: number): number {
  let depth = 0;
  for (let j = open; j < tokens.length; j++) {
    if (tokens[j].value === "(") depth++;
    else if (tokens[j].value === ")" && --depth === 0) return j;
  }
  return tokens.length - 1;
}

/** Secret names passed as values in the argument tokens: directly, in ${…}, or as an object shorthand; not through another call. */
/** Words that make a name describe a secret (its length, where it is kept) rather than hold one. */
const METADATA_WORDS = new Set(["length", "len", "min", "max", "size", "count", "limit", "env", "name", "path", "file", "label", "prefix", "type", "kind", "url", "hint", "placeholder", "policy", "pattern", "regex"]);

function directSecrets(tokens: Token[], open: number): string[] {
  const close = closeOf(tokens, open);
  const inner: Token[] = [];
  for (let j = open + 1; j < close; j++) {
    const t = tokens[j];
    if (t.kind === "string" && t.value.startsWith("`")) {
      const re = /\$\{([^}]*)\}/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(t.value))) for (const x of lex(m[1]).tokens) if (x.kind !== "eof") inner.push(x);
    } else inner.push(t);
  }
  const out: string[] = [];
  let call = 0;
  const stack: number[] = [];
  for (let k = 0; k < inner.length; k++) {
    const t = inner[k];
    if (t.value === "(") {
      const isCall = inner[k - 1]?.kind === "ident" && !["stringify", "String", "encodeURIComponent", "from", "Error"].includes(inner[k - 1].value);
      stack.push(isCall ? 1 : 0);
      call += stack[stack.length - 1];
      continue;
    }
    if (t.value === ")") {
      call -= stack.pop() ?? 0;
      continue;
    }
    if (call > 0 || t.kind !== "ident" || !isSecretValue(t.value)) continue;
    // the name of a secret (an environment variable, a file), not the secret
    if (/(Env|Var|Name|Path|File|Dir|Label|Prefix|Id|Length|Len|Type|Kind|Url|Key[sS]?Env)$/.test(t.value)) continue;
    // MIN_PASSPHRASE_LENGTH, maxPasswordSize: a rule about a secret, not the secret
    if (t.value.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/).some((w) => METADATA_WORDS.has(w))) continue;
    // SECRET_BYTES in an error message: a size constant (an error would not print raw bytes)
    if (/^[A-Z0-9_]+_BYTES$/.test(t.value)) continue;
    const next = inner[k + 1]?.value;
    if (next === "(" || next === ":") continue;
    if (next === "." && SAFE_PROPERTIES.has(inner[k + 2]?.value ?? "")) continue;
    if (inner[k - 1]?.value === ".") continue; // obj.secretKey is a property of something else
    if (!out.includes(t.value)) out.push(t.value);
  }
  return out;
}

function tlsDisabled(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i + 2 < tokens.length; i++) {
    const t = tokens[i];
    const name = t.kind === "ident" ? t.value : t.kind === "string" ? t.value.slice(1, -1) : "";
    const v = tokens[i + 2];
    let hit = false;
    if ((name === "rejectUnauthorized" || name === "strictSSL") && tokens[i + 1].value === ":" && v.value === "false") hit = true;
    if (name === "NODE_TLS_REJECT_UNAUTHORIZED" && (tokens[i + 1].value === "=" || tokens[i + 1].value === ":" || tokens[i + 1].value === "]") ) {
      for (let k = i + 1; k < i + 5 && k < tokens.length; k++) if (/^["'`]0["'`]$/.test(tokens[k].value) || tokens[k].value === "0") hit = true;
    }
    if (!hit) continue;
    out.push({
      ruleId: "MS107",
      severity: "high",
      confidence: "high",
      loc: loc(t),
      message: `TLS certificate checks are turned off (${name}). Anyone on the network path can impersonate the indexer, node or wallet backend, read what the DApp sends and feed it false chain data. Remove it, and add the right CA certificate if a self-signed one is the reason.`,
    });
  }
  return out;
}

function dynamicCode(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i + 1 < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind !== "ident") continue;
    const prev = tokens[i - 1]?.value;
    let what: string | undefined;
    if (t.value === "eval" && tokens[i + 1].value === "(" && prev !== "." && prev !== "function") what = "eval()";
    if (t.value === "Function" && prev === "new" && tokens[i + 1].value === "(") what = "new Function()";
    if ((t.value === "setTimeout" || t.value === "setInterval") && prev !== "." && tokens[i + 1].value === "(" && tokens[i + 2]?.kind === "string") what = `${t.value}() with a string`;
    if (!what) continue;
    out.push({
      ruleId: "MS108",
      severity: "high",
      confidence: "medium",
      loc: loc(t),
      message: `${what} runs a string as code. If any part of it can come from outside (a URL, a message, chain data), an attacker can run code in the DApp, where the user's keys and private state are. Use a function or a parser instead.`,
    });
  }
  return out;
}

const CHAIN_CONTEXT = /(indexer|node|rpc|substrate|relay|graphql|pubsub)/i;

function insecureTransport(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind !== "string") continue;
    const m = t.value.slice(1, -1).match(/^(http|ws):\/\/(\[[^\]]+\]|[^/:?#$]+)(?::(\d+))?/i);
    if (!m) continue;
    const host = m[2].toLowerCase();
    if (LOCAL_HOSTS.has(host) || !host.includes(".") || /^(10|127|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(host) || host.endsWith(".local") || host.endsWith(".internal")) continue;
    if (m[3] === "6300") continue; // proof server: MS101
    // the URL itself or the name it is assigned to must be about the chain
    let context = CHAIN_CONTEXT.test(t.value);
    for (let j = i - 1; j >= 0 && j >= i - 6 && !context; j--) {
      if ([",", ";", "{", "}"].includes(tokens[j].value)) break;
      if (tokens[j].kind === "ident" && CHAIN_CONTEXT.test(tokens[j].value)) context = true;
    }
    if (!context) continue;
    out.push({
      ruleId: "MS109",
      severity: "medium",
      confidence: "medium",
      loc: loc(t),
      message: `The DApp talks to a remote ${/indexer/i.test(t.value) ? "indexer" : "chain service"} (${host}) over unencrypted ${m[1].toLowerCase()}://. Anyone on the network path can read the requests (which addresses and contracts a user follows) and change the answers. Use https:// or wss://.`,
    });
  }
  return out;
}

const WRITE_FILE = new Set(["writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream"]);

function secretSinks(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i + 1 < tokens.length; i++) {
    const t = tokens[i];
    // MS110: new Error(`… ${secret}`) / throw `…`
    if (t.kind === "ident" && /Error$/.test(t.value) && tokens[i - 1]?.value === "new" && tokens[i + 1].value === "(") {
      const s = directSecrets(tokens, i + 1);
      if (s.length) {
        out.push({
          ruleId: "MS110",
          severity: "medium",
          confidence: "medium",
          loc: loc(t),
          message: `'${s.join("', '")}' looks like a secret and is put into an error message. Errors end up in logs, crash reports and error trackers, and are often shown to users. Leave the secret out of the message.`,
        });
      }
    }
    // MS111: fs.writeFileSync(path, secret)
    if (t.kind === "ident" && WRITE_FILE.has(t.value) && tokens[i + 1].value === "(") {
      const s = directSecrets(tokens, i + 1);
      // { mode: 0o600 }: the file is deliberately private to the user
      const restricted = tokens.slice(i + 1, closeOf(tokens, i + 1)).some((x) => x.value === "mode");
      if (s.length && !restricted) {
        out.push({
          ruleId: "MS111",
          severity: "medium",
          confidence: "medium",
          loc: loc(t),
          message: `'${s.join("', '")}' looks like a secret and is written to a file as is. Files are copied into backups, Docker images and commits. Encrypt it first, or keep it in the operating system's keychain or a secret manager.`,
        });
      }
    }
    // MS112: x.postMessage(data, "*")
    if (t.value === "postMessage" && tokens[i - 1]?.value === "." && tokens[i + 1].value === "(") {
      const close = closeOf(tokens, i + 1);
      let depth = 0;
      let wildcard = false;
      for (let j = i + 1; j < close; j++) {
        const v = tokens[j].value;
        if (v === "(" || v === "{" || v === "[") depth++;
        else if (v === ")" || v === "}" || v === "]") depth--;
        if (depth === 1 && tokens[j].kind === "string" && /^["'`]\*["'`]$/.test(v) && tokens[j - 1]?.value === ",") wildcard = true;
        if (depth === 2 && tokens[j].kind === "string" && /^["'`]\*["'`]$/.test(v) && tokens[j - 2]?.value === "targetOrigin") wildcard = true;
      }
      if (wildcard) {
        out.push({
          ruleId: "MS112",
          severity: "medium",
          confidence: "high",
          loc: loc(t),
          message: `postMessage(…, "*") sends the message to whatever page is in the target window, including one an attacker navigated there. Pass the exact origin you expect, such as "https://app.example.com".`,
        });
      }
    }
  }
  return out;
}

const isRandomnessName = (name: string) =>
  isSecretName(name) || /(^|_)(nonce|salt|randomness|rand|blind(ing)?(_factor)?|entropy)(?![a-z])/i.test(name.replace(/([a-z0-9])([A-Z])/g, "$1_$2"));

/** MS113: inside `witnesses = { … }`, a randomness or secret witness that returns fresh zero bytes or a clock value. */
function weakWitnessRandomness(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i + 2 < tokens.length; i++) {
    if (tokens[i].kind !== "ident" || !/witnesses$/i.test(tokens[i].value)) continue;
    // deploymentWitnesses, placeholderWitnesses: stand-ins the constructor needs, never run by a circuit
    if (/deploy|placeholder|dummy|stub|noop/i.test(tokens[i].value)) continue;
    // find the object literal that follows: `witnesses = {`, `witnesses: Witnesses<…> = {`
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
    let propStart = open + 1;
    for (let j = open; j < tokens.length; j++) {
      const v = tokens[j].value;
      if (v === "{" || v === "(" || v === "[") depth++;
      else if (v === "}" || v === ")" || v === "]") depth--;
      const endOfProp = (depth === 1 && v === ",") || depth === 0;
      if (!endOfProp) continue;
      const prop = tokens.slice(propStart, j);
      propStart = j + 1;
      const name = prop[0]?.kind === "ident" ? prop[0].value : prop[0]?.kind === "string" ? prop[0].value.slice(1, -1) : "";
      if (name && isRandomnessName(name)) {
        const text = prop.map((t) => t.value).join(" ");
        const strong = /getRandomValues|randomBytes|randomFill|randomUUID|crypto|\. fill|\. set \(/.test(text);
        const zero = /new Uint8Array \( \d+ \)|Buffer \. alloc \(|new Array \( \d+ \)/.test(text);
        const clock = /Date \. now|performance \. now|new Date/.test(text);
        if (!strong && (zero || clock)) {
          out.push({
            ruleId: "MS113",
            severity: "critical",
            confidence: "medium",
            loc: { line: prop[0].line, col: prop[0].col },
            message: `The witness '${name}' returns ${zero ? "a newly allocated buffer, which is all zeros" : "a clock value, which anyone can guess"}. The contract uses this value as secret randomness, so every commitment made with it can be opened by trying candidate values. Return crypto.getRandomValues(new Uint8Array(32)) (and keep it in private state if it is needed later).`,
          });
        }
      }
      if (depth === 0) break;
    }
  }
  return out;
}

/** MS114: a secret written into the URL (location, history, URLSearchParams). */
function secretInUrl(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i + 2 < tokens.length; i++) {
    const t = tokens[i];
    let open = -1;
    let what = "";
    if (t.value === "history" && tokens[i + 1].value === "." && /^(push|replace)State$/.test(tokens[i + 2].value) && tokens[i + 3]?.value === "(") {
      open = i + 3;
      what = `history.${tokens[i + 2].value}()`;
    } else if (t.value === "URLSearchParams" && tokens[i - 1]?.value === "new" && tokens[i + 1].value === "(") {
      open = i + 1;
      what = "URLSearchParams";
    } else if ((t.value === "searchParams" || t.value === "params") && tokens[i + 1].value === "." && /^(set|append)$/.test(tokens[i + 2].value) && tokens[i + 3]?.value === "(") {
      open = i + 3;
      what = `${t.value}.${tokens[i + 2].value}()`;
    } else if (t.value === "location" && tokens[i + 1].value === "." && /^(hash|href|search)$/.test(tokens[i + 2].value) && tokens[i + 3]?.value === "=" && tokens[i + 4]?.value !== "=") {
      // location.hash = `#${seed}`: treat the right-hand side like an argument list
      const rhs: Token[] = [{ ...tokens[i + 3], value: "(" }];
      for (let k = i + 4; k < tokens.length && tokens[k].value !== ";" && tokens[k].line === t.line; k++) rhs.push(tokens[k]);
      rhs.push({ ...t, value: ")" });
      const sec = directSecrets(rhs, 0);
      if (sec.length) out.push(urlFinding(t, `location.${tokens[i + 2].value}`, sec));
      continue;
    }
    if (open === -1) continue;
    const sec = directSecrets(tokens, open);
    if (sec.length) out.push(urlFinding(t, what, sec));
  }
  return out;
}
const urlFinding = (t: Token, what: string, sec: string[]): RawFinding => ({
  ruleId: "MS114",
  severity: "high",
  confidence: "medium",
  loc: { line: t.line, col: t.col },
  message: `'${sec.join("', '")}' looks like a secret and is put into the URL (${what}). URLs are kept in browser history, synced across devices, sent in Referer headers and logged by servers and proxies. Keep secrets out of URLs.`,
});

/** MS115: a password or passphrase written into the source. */
function hardcodedPassword(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i + 2 < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind !== "ident" || !/(password|passphrase|passwd)(Provider)?$/i.test(t.value) || /(env|name|label|field|placeholder|hint|min|max|length|policy|regex|pattern|type)/i.test(t.value)) continue;
    const op = tokens[i + 1].value;
    let v = tokens[i + 2];
    // passwordProvider: () => "…"
    if ((op === ":" || op === "=") && tokens[i + 2].value === "(" && tokens[i + 3]?.value === ")" && tokens[i + 4]?.value === "=>") v = tokens[i + 5];
    if (!(op === "=" || op === ":" || op === "(") || !v || v.kind !== "string" || v.value.startsWith("`")) continue;
    const lit = v.value.slice(1, -1);
    if (lit.length < 4) continue;
    // a mask ('****') or a UI label ("intro", "월렛 만들기", 'Password'): plain words, not a password
    if (/^[*xX•·.\-]+$/.test(lit) || /^[A-Za-z]+$/.test(lit) || /\s/.test(lit) || /[^\x00-\x7f]/.test(lit)) continue;
    // a password labeled as a throwaway (test, local devnet, demo) is a deliberate development value
    const words = (x: string) => x.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/);
    const THROWAWAY = new Set(["test", "testing", "local", "dev", "devnet", "demo", "example", "sample", "dummy", "fixture"]);
    if (words(lit).some((w) => THROWAWAY.has(w)) || words(t.value).some((w) => THROWAWAY.has(w))) continue;
    out.push({
      ruleId: "MS115",
      severity: "high",
      confidence: "medium",
      loc: { line: t.line, col: t.col },
      message: `'${t.value}' is set to a password written in the source. Anyone with the code or the bundle has it. If it protects the private state store, every user's private state is protected by the same public password. Ask the user for it, or derive it from the wallet.`,
    });
  }
  return out;
}

/** MS116: a secret rendered in JSX: <div>{seed}</div>, value={mnemonic}. */
function secretInUi(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 1; i + 2 < tokens.length; i++) {
    if (tokens[i].value !== "{" || tokens[i + 1].kind !== "ident" || tokens[i + 2].value !== "}") continue;
    const prev = tokens[i - 1].value;
    const inText = prev === ">" ;
    const inAttr = prev === "=" && /^(value|children|title|alt|placeholder|label)$/.test(tokens[i - 2]?.value ?? "") && tokens[i - 3]?.kind === "ident";
    if (!(inText || inAttr) || !isSecretValue(tokens[i + 1].value)) continue;
    out.push({
      ruleId: "MS116",
      severity: "medium",
      confidence: "medium",
      loc: { line: tokens[i + 1].line, col: tokens[i + 1].col },
      message: `'${tokens[i + 1].value}' looks like a secret and is shown on screen. Screenshots, screen sharing, session-replay tools and browser extensions can capture it. If the user must see it (a backup phrase), show it only on request, behind a reveal button, and exclude it from session replay.`,
    });
  }
  return out;
}

const ANALYTICS = /^(analytics|posthog|mixpanel|amplitude|segment|Sentry|datadogRum|LogRocket|heap|gtag|ga|plausible|umami|rudderanalytics)$/;
const ANALYTICS_METHODS = /^(track|capture|identify|setUser|setContext|setExtra|setExtras|setTag|addBreadcrumb|captureMessage|captureException|page|event|log|register|people)$/;

/** MS117: a secret passed to analytics or error tracking. */
function secretToAnalytics(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i + 3 < tokens.length; i++) {
    const t = tokens[i];
    let open = -1;
    if (ANALYTICS.test(t.value) && tokens[i + 1].value === "." && ANALYTICS_METHODS.test(tokens[i + 2].value) && tokens[i + 3].value === "(") open = i + 3;
    else if ((t.value === "gtag" || t.value === "plausible") && tokens[i + 1].value === "(" && tokens[i - 1]?.value !== ".") open = i + 1;
    if (open === -1) continue;
    const sec = directSecrets(tokens, open);
    if (!sec.length) continue;
    out.push({
      ruleId: "MS117",
      severity: "high",
      confidence: "medium",
      loc: { line: t.line, col: t.col },
      message: `'${sec.join("', '")}' looks like a secret and is sent to ${t.value} (analytics or error tracking). Those services store it, and many people and vendors can read it. Send a non-reversible identifier instead.`,
    });
  }
  return out;
}

/** MS118: HTML from a variable written into the page. */
function unsafeHtml(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 0; i + 2 < tokens.length; i++) {
    const t = tokens[i];
    let hit = "";
    if ((t.value === "innerHTML" || t.value === "outerHTML") && tokens[i - 1]?.value === "." && (tokens[i + 1].value === "=" || tokens[i + 1].value === "+") && tokens[i + 2].value !== "=") {
      const v = tokens[i + 1].value === "+" ? tokens[i + 3] : tokens[i + 2];
      if (v && !(v.kind === "string" && !v.value.startsWith("`"))) hit = t.value;
    }
    if (t.value === "dangerouslySetInnerHTML") hit = t.value;
    if (t.value === "write" && tokens[i - 1]?.value === "." && tokens[i - 2]?.value === "document" && tokens[i + 1].value === "(") hit = "document.write";
    if (t.value === "insertAdjacentHTML" && tokens[i + 1].value === "(") hit = t.value;
    if (!hit) continue;
    out.push({
      ruleId: "MS118",
      // a hygiene warning: most innerHTML in DApps renders the app's own values; only attacker-controlled HTML is XSS
      severity: "low",
      confidence: "medium",
      loc: { line: t.line, col: t.col },
      message: `${hit} puts HTML into the page. If any part comes from chain data, a URL or another user, it can run script in the DApp, where it can read private state and ask the wallet to sign. Use textContent, or sanitize with a library such as DOMPurify.`,
    });
  }
  return out;
}

/** MS119: a secret read from an environment variable that the bundler inlines into the browser bundle. */
function secretInPublicEnv(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (const t of tokens) {
    if (t.kind !== "ident" && t.kind !== "string") continue;
    const name = t.kind === "string" ? t.value.slice(1, -1) : t.value;
    const m = name.match(/^(VITE_|NEXT_PUBLIC_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_)(.+)$/);
    if (!m) continue;
    const rest = m[2];
    if (!(isSecretName(rest) || /(PRIVATE_KEY|SECRET|MNEMONIC|SEED|PASSWORD|API_SECRET)/.test(rest)) || /PUBLIC_KEY|ADDRESS|_URL|_URI|_ID$/.test(rest)) continue;
    out.push({
      ruleId: "MS119",
      severity: "critical",
      confidence: "high",
      loc: { line: t.line, col: t.col },
      message: `${name} has the ${m[1]} prefix, so the bundler copies its value into the JavaScript sent to every visitor. A seed, key or password here is public. Keep it on a server, or have each user provide their own.`,
    });
  }
  return out;
}

const PUBLIC_NAME = /(pub(lic)?_?key|pubkey|address|addr|account(id)?|wallet(address|id)?|username|email|did|handle)$/i;
const RANDOM_SOURCE = /^(getRandomValues|randomBytes|randomUUID|generateKey|generateMnemonic|generateRandomSeed|randomSeed)$/;

/** MS120: `const voterSecret = hash(walletAddress)`: a secret that anyone can recompute from public data. */
function secretFromPublicData(tokens: Token[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (let i = 1; i + 2 < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind !== "ident" || (tokens[i - 1].value !== "const" && tokens[i - 1].value !== "let") || tokens[i + 1].value !== "=") continue;
    if (!isSecretName(t.value) || /(hash|commit|id$|pk$|public|pub)/i.test(t.value)) continue;
    // contractIdSeed, sessionIdSeed: a seed for an identifier, not a secret
    if (t.value.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/).includes("id")) continue;
    // the right-hand side up to the end of the statement
    const rhs: Token[] = [];
    let depth = 0;
    for (let j = i + 2; j < tokens.length; j++) {
      const v = tokens[j].value;
      if (v === "(" || v === "[" || v === "{") depth++;
      else if (v === ")" || v === "]" || v === "}") depth--;
      if ((v === ";" && depth <= 0) || depth < 0) break;
      if (tokens[j].line > t.line + 3) break;
      if (tokens[j].kind === "string" && v.startsWith("`")) rhs.push(...lex(v.slice(1, -1).replace(/\$\{([^}]*)\}/g, " $1 ")).tokens.filter((x) => x.kind !== "eof"));
      else rhs.push(tokens[j]);
    }
    // a function (`const seedFor = (addr) => …`) is not a stored secret
    if (rhs.some((x) => x.value === "=>" || x.value === "function")) continue;
    // await service.secretFor(address): a method of some other object, computed where we cannot see, maybe with a key
    const firstCall = rhs.findIndex((x) => x.value === "(");
    if (rhs[0]?.value === "await" && firstCall > 0 && rhs.slice(1, firstCall).some((x) => x.value === ".")) continue;
    const idents = rhs.filter((x) => x.kind === "ident");
    const publicInput = idents.find((x, k) => PUBLIC_NAME.test(x.value) && rhs[rhs.indexOf(x) + 1]?.value !== "(" && k >= 0);
    if (!publicInput) continue;
    const hasSecretOrRandom = idents.some((x) => (isSecretName(x.value) && x.value !== t.value) || RANDOM_SOURCE.test(x.value) || /random|entropy|mnemonic|seed|password|passphrase|signature|sign/i.test(x.value));
    if (hasSecretOrRandom) continue;
    out.push({
      ruleId: "MS120",
      severity: "high",
      confidence: "medium",
      loc: { line: t.line, col: t.col },
      message: `'${t.value}' is used as a secret, but it is computed only from '${publicInput.value}', which is public. Anyone who knows the ${publicInput.value} can compute the same value and act as this user. Derive secrets from fresh randomness (crypto.getRandomValues) or a wallet signature, and keep them in private state.`,
    });
  }
  return out;
}

export function checkSdkMore(tokens: Token[]): RawFinding[] {
  return [
    ...tlsDisabled(tokens),
    ...dynamicCode(tokens),
    ...insecureTransport(tokens),
    ...secretSinks(tokens),
    ...weakWitnessRandomness(tokens),
    ...secretInUrl(tokens),
    ...hardcodedPassword(tokens),
    ...secretInUi(tokens),
    ...secretToAnalytics(tokens),
    ...unsafeHtml(tokens),
    ...secretInPublicEnv(tokens),
    ...secretFromPublicData(tokens),
  ];
}
