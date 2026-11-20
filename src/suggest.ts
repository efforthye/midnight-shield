// Suggested fixes: for each finding, the flagged line and how it could look
// after the fix. These are suggestions for a person or an AI agent to apply,
// not automatic edits: most fixes change on-chain values (a hash, a
// commitment) or need a name only the author knows (a domain tag, a witness).
// Names the author must choose are written as placeholders like `myapp`.

export interface Suggestion {
  /** the flagged source line(s), as written */
  before: string[];
  /** the same place after the fix */
  after: string[];
  /** what else the fix needs, in one sentence */
  note?: string;
}

const indentOf = (line: string) => line.match(/^\s*/)![0];

/** Find `name(` in a line and return the index range of its argument list (inside the parentheses). */
function callArgs(line: string, name: string, from = 0): { start: number; open: number; close: number } | undefined {
  const re = new RegExp(`\\b${name}\\b`, "g");
  re.lastIndex = from;
  for (let m = re.exec(line); m; m = re.exec(line)) {
    let i = m.index + name.length;
    // skip generic arguments: persistentHash<Vector<2, Bytes<32>>>(…)
    if (line[i] === "<") {
      let depth = 0;
      for (; i < line.length; i++) {
        if (line[i] === "<") depth++;
        else if (line[i] === ">" && --depth === 0) {
          i++;
          break;
        }
      }
    }
    if (line[i] !== "(") continue;
    let depth = 0;
    for (let j = i; j < line.length; j++) {
      if (line[j] === "(" || line[j] === "[") depth++;
      else if (line[j] === ")" || line[j] === "]") {
        if (--depth === 0) return { start: m.index, open: i, close: j };
      }
    }
  }
  return undefined;
}

/** Split a top-level comma list. */
function splitArgs(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of s) {
    if ("([<{".includes(ch)) depth++;
    else if (")]>}".includes(ch)) depth--;
    if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const quoted = (message: string) => message.match(/'([^']+)'/)?.[1];

function hashToCommit(line: string): string | undefined {
  for (const fn of ["persistentHash", "transientHash"]) {
    const c = callArgs(line, fn);
    if (!c) continue;
    const commit = fn === "persistentHash" ? "persistentCommit" : "transientCommit";
    const head = line.slice(c.start, c.open).replace(fn, commit);
    return `${line.slice(0, c.start)}${head}(${line.slice(c.open + 1, c.close)}, randomness())${line.slice(c.close + 1)}`;
  }
  return undefined;
}

function addDomainTag(line: string): string | undefined {
  for (const fn of ["persistentHash", "transientHash"]) {
    const c = callArgs(line, fn);
    if (!c) continue;
    const typeText = line.slice(c.start + fn.length, c.open); // "<Vector<2, Bytes<32>>>" or "<Bytes<32>>"
    const args = line.slice(c.open + 1, c.close).trim();
    const tag = `pad(32, "myapp:purpose:")`;
    const vec = typeText.match(/^<Vector<(\d+),\s*(.+)>>$/);
    if (vec && args.startsWith("[")) {
      return `${line.slice(0, c.start)}${fn}<Vector<${Number(vec[1]) + 1}, ${vec[2]}>>([${tag}, ${args.slice(1)})${line.slice(c.close + 1)}`;
    }
    const inner = typeText.match(/^<(.+)>$/)?.[1] ?? "Bytes<32>";
    return `${line.slice(0, c.start)}${fn}<Vector<2, ${inner}>>([${tag}, ${args}])${line.slice(c.close + 1)}`;
  }
  return undefined;
}

function weakRandomness(line: string): string | undefined {
  for (const fn of ["persistentCommit", "transientCommit"]) {
    const c = callArgs(line, fn);
    if (!c) continue;
    const args = splitArgs(line.slice(c.open + 1, c.close));
    if (args.length < 2) continue;
    args[args.length - 1] = "randomness()";
    return `${line.slice(0, c.open + 1)}${args.join(", ")}${line.slice(c.close)}`;
  }
  return undefined;
}

function hashDisclosedSecret(line: string, secret: string): string | undefined {
  const c = callArgs(line, "disclose");
  if (!c) return undefined;
  const inner = line.slice(c.open + 1, c.close).trim();
  if (!inner.includes(secret.replace(/\(\)$/, ""))) return undefined;
  return `${line.slice(0, c.open + 1)}persistentHash<Vector<2, Bytes<32>>>([pad(32, "myapp:public-key:"), ${inner}])${line.slice(c.close)}`;
}

export function suggestFix(ruleId: string, message: string, line: string): Suggestion | undefined {
  const ind = indentOf(line);
  const before = [line];
  switch (ruleId) {
    case "MS001": {
      if (!line.includes("ownPublicKey()")) return undefined;
      return {
        before,
        after: [line.replace("ownPublicKey()", "deriveId(secretKey())")],
        note: 'Store deriveId(secret) in the ledger field instead of a public key, with circuit deriveId(sk: Bytes<32>): Bytes<32> { return persistentHash<Vector<2, Bytes<32>>>([pad(32, "myapp:owner:"), sk]); }.',
      };
    }
    case "MS002": {
      const w = message.match(/Witness '([^']+)'/)?.[1];
      if (!w) return undefined;
      return {
        before,
        after: [`${ind}assert(${w} <= MAX_VALUE, "value out of range");`, line],
        note: `Check ${w} against something the contract trusts: a range, a ledger value or a set. MAX_VALUE stands for your limit.`,
      };
    }
    case "MS003": {
      const after = hashToCommit(line);
      if (!after) return undefined;
      return { before, after: [after], note: "Add witness randomness(): Bytes<32>; returning fresh random bytes, and keep them to open the commitment later." };
    }
    case "MS004": {
      const after = weakRandomness(line);
      if (!after) return undefined;
      return { before, after: [after], note: "randomness() is a witness that returns fresh random bytes for each commitment, kept privately by the user." };
    }
    case "MS005": {
      const after = addDomainTag(line);
      if (!after) return undefined;
      return { before, after: [after], note: 'Use a tag unique to this app and purpose, for example "votingapp:nullifier:".' };
    }
    case "MS006":
      return { before: [], after: ["pragma language_version >= 0.28.0;"], note: "Add at the top of the file (or run with --fix)." };
    case "MS007": {
      const secret = quoted(message) ?? "";
      const after = hashDisclosedSecret(line, secret);
      if (!after) return undefined;
      return { before, after: [after], note: "Publish a domain-separated hash of the secret, never the secret itself." };
    }
    case "MS008":
      return {
        before,
        after: [
          line,
          `${ind}const nullifier = disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "myapp:nullifier:"), secretKey()]));`,
          `${ind}assert(!nullifiers.member(nullifier), "already used");`,
          `${ind}nullifiers.insert(nullifier);`,
        ],
        note: "Add export ledger nullifiers: Set<Bytes<32>>; so each member can act once.",
      };
    case "MS009": {
      const path = quoted(message) ?? "path";
      return {
        before,
        after: [`${ind}assert(disclose(${path}.leaf == deriveLeaf(secretKey())), "not your path");`, line],
        note: "deriveLeaf is how the contract computes a member's leaf from their secret when they join.",
      };
    }
    case "MS010": {
      let after = line.replace(/pad\(32, "([^"]*)"\)/, 'pad(32, "$1"), pad(32, "<this circuit>")');
      if (after === line) {
        const c = callArgs(line, "disclose");
        if (!c) return undefined;
        const inner = line.slice(c.open + 1, c.close).trim();
        after = `${line.slice(0, c.open + 1)}persistentHash<Vector<2, Bytes<32>>>([pad(32, "<this circuit>"), ${inner}])${line.slice(c.close)}`;
      }
      return {
        before,
        after: [after],
        note: "Mix a per-action value (the circuit's name, a round or a nonce) into the hash so tags from different actions cannot be linked.",
      };
    }
    case "MS011": {
      const field = message.match(/changes '([^']+)'/)?.[1] ?? "ownerId";
      return {
        before,
        after: [`${ind}assert(deriveId(secretKey()) == ${field}, "not the owner");`, line],
        note: "Check the caller the same way the rest of the contract does before changing who is authorized.",
      };
    }
    case "MS101": {
      const after = line.replace(/(["'])(?:https?|wss?):\/\/[^"']*\1/, 'process.env.MIDNIGHT_PROOF_SERVER ?? "http://localhost:6300"');
      return after === line ? undefined : { before, after: [after], note: "Run the proof server on the user's own machine." };
    }
    case "MS102": {
      const names = [...message.matchAll(/'([^']+)'/g)].map((m) => m[1]).filter((n) => !n.includes("("));
      let after = line;
      for (const n of names) {
        after = after.replace(new RegExp(`\\$\\{${n}\\}`, "g"), "[redacted]").replace(new RegExp(`,\\s*${n}\\b(?=\\s*[,)])`, "g"), "");
      }
      return after === line ? undefined : { before, after: [after], note: "Log a non-reversible identifier (such as a public key) if you need one." };
    }
    case "MS103": {
      const name = quoted(message) ?? "SECRET";
      const env = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toUpperCase();
      const after = line.replace(/(["'])[^"']{20,}\1/, `process.env.${env} ?? ""`);
      return after === line ? undefined : { before, after: [after], note: "Then treat the exposed key as leaked: move its funds and stop using it." };
    }
    case "MS104":
      return {
        before,
        after: [`${ind}await providers.privateStateProvider.set(privateStateId, privateState);`],
        note: "Keep private state in the Midnight private state provider instead of web storage.",
      };
    default:
      return undefined;
  }
}

export interface DiffLine {
  kind: "-" | "+" | " ";
  text: string;
}

/**
 * The suggestion as diff lines, without common indentation. A flagged line
 * that the fix keeps as it is (lines added around it) shows as context.
 */
export function suggestionDiff(s: Suggestion): DiffLine[] {
  const all = [...s.before, ...s.after].filter((l) => l.trim());
  const pad = all.length ? Math.min(...all.map((l) => l.match(/^\s*/)![0].length)) : 0;
  const strip = (l: string) => l.slice(Math.min(pad, l.match(/^\s*/)![0].length));
  const kept = s.before.filter((b) => s.after.includes(b));
  const out: DiffLine[] = [];
  for (const b of s.before) if (!kept.includes(b)) out.push({ kind: "-", text: strip(b) });
  for (const a of s.after) out.push({ kind: kept.includes(a) ? " " : "+", text: strip(a) });
  return out;
}
