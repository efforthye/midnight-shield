import type { GuardKind, Who } from "./access.js";
import type { AccessEntry, ConstraintEntry, DisclosureEntry, Finding } from "./linter.js";
import type { Constraint, InputReport } from "./constraints.js";
import { suggestionDiff } from "./suggest.js";
import { RULES, SEVERITY_ORDER, ruleDocUrl, type RuleMeta, type Severity } from "./rules.js";

export const VERSION = "0.6.1";

const COLORS: Record<Severity, string> = {
  critical: "\x1b[35m",
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
};
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";

export interface TextOptions {
  color?: boolean;
  /** show the source line and a caret under each finding (default: true) */
  codeFrame?: boolean;
  /** show the rule documentation link (default: true) */
  links?: boolean;
  /** show a suggested fix under each finding (default: true) */
  suggestions?: boolean;
}

function caretLength(snippet: string, col: number): number {
  const rest = snippet.slice(col - 1);
  const m = rest.match(/^[A-Za-z_$][\w$]*(\(\))?/);
  return m ? m[0].length : 1;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function severitySummary(findings: Finding[], c: (code: string, s: string) => string): string {
  const counts = new Map<Severity, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  return SEVERITY_ORDER.filter((sv) => counts.has(sv))
    .map((sv) => c(COLORS[sv], `${counts.get(sv)} ${sv}`))
    .join(", ");
}

export function formatText(all: Finding[], fileCount: number, options: TextOptions | boolean = {}): string {
  const opts: TextOptions = typeof options === "boolean" ? { color: options } : options;
  const color = opts.color ?? true;
  const codeFrame = opts.codeFrame ?? true;
  const links = opts.links ?? true;
  const suggestions = opts.suggestions ?? true;
  const c = (code: string, s: string) => (color ? code + s + RESET : s);
  const findings = all.filter((f) => !f.suppressed);
  const suppressed = all.filter((f) => f.suppressed);
  const lines: string[] = [];

  let currentFile = "";
  for (const f of findings) {
    if (f.file !== currentFile) {
      if (currentFile) lines.push("");
      lines.push(c(BOLD + "\x1b[4m", f.file));
      currentFile = f.file;
    }
    lines.push("");
    const sev = c(BOLD + COLORS[f.severity], f.severity.toUpperCase().padEnd(8));
    const conf = f.confidence === "high" ? "" : c(DIM, ` (${f.confidence} confidence)`);
    const fix = f.fix ? c("\x1b[32m", " [fixable]") : "";
    lines.push(`  ${sev}  ${c(BOLD, f.ruleId)} ${c(DIM, f.ruleName)}  ${c(DIM, `${f.file}:${f.line}:${f.col}`)}${conf}${fix}`);
    lines.push(`  ${f.message}`);
    if (codeFrame && f.snippet.trim()) {
      const num = String(f.line);
      const gutter = " ".repeat(num.length);
      const text = f.snippet.replace(/\t/g, " ");
      lines.push(`    ${c(DIM, num + " │")} ${text}`);
      lines.push(`    ${c(DIM, gutter + " │")} ${" ".repeat(Math.max(0, f.col - 1))}${c(COLORS[f.severity], "^".repeat(caretLength(text, f.col)))}`);
    }
    if (suggestions && f.suggestion) {
      lines.push(`  ${c(BOLD, "Suggested fix")}`);
      for (const d of suggestionDiff(f.suggestion)) {
        const text = `${d.kind} ${d.text}`;
        lines.push(`    ${d.kind === "-" ? c("\x1b[31m", text) : d.kind === "+" ? c("\x1b[32m", text) : c(DIM, text)}`);
      }
      if (f.suggestion.note) lines.push(`  ${c(DIM, f.suggestion.note)}`);
    }
    if (links) lines.push(`  ${c(DIM, "→ " + f.docUrl)}`);
  }

  if (suppressed.length) {
    if (lines.length) lines.push("");
    lines.push(c(BOLD, `Suppressed (${suppressed.length})`));
    for (const f of suppressed) {
      lines.push(`  ${c(DIM, `${f.file}:${f.line}:${f.col}`)}  ${f.ruleId} ${f.ruleName}  ${c(DIM, `[${f.suppressed}]`)}${f.suppressionReason ? `  ${c(DIM, "— " + f.suppressionReason)}` : ""}`);
    }
  }

  if (lines.length) lines.push("");
  const files = plural(fileCount, "file");
  const extra = suppressed.length ? c(DIM, `, ${suppressed.length} suppressed`) : "";
  const fixable = findings.filter((f) => f.fix).length;
  const fixNote = fixable ? c(DIM, `\n  ${plural(fixable, "finding")} can be fixed with --fix.`) : "";
  lines.push(
    findings.length
      ? `${c(BOLD, `✖ ${plural(findings.length, "finding")}`)} in ${files} (${severitySummary(findings, c)})${extra}${fixNote}`
      : c("\x1b[32m", `✔ No findings in ${files}.`) + extra,
  );
  return lines.join("\n");
}

export function formatJson(findings: Finding[]): string {
  const active = findings.filter((f) => !f.suppressed);
  return JSON.stringify(
    {
      tool: "midnight-shield",
      version: VERSION,
      summary: {
        findings: active.length,
        suppressed: findings.length - active.length,
        bySeverity: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, active.filter((f) => f.severity === s).length])),
      },
      findings,
    },
    null,
    2,
  );
}

const SARIF_LEVEL: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "0.0",
};

export function formatSarif(findings: Finding[], extraRules: RuleMeta[] = []): string {
  const rules = [...RULES, ...extraRules];
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "midnight-shield",
            version: VERSION,
            informationUri: "https://github.com/efforthye/midnight-shield",
            rules: rules.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.summary },
              helpUri: ruleDocUrl(r.id, r),
              defaultConfiguration: { level: SARIF_LEVEL[r.severity] },
              properties: {
                tags: ["security", "privacy", "midnight", "compact"],
                precision: r.confidence,
                "security-severity": SECURITY_SEVERITY[r.severity],
              },
            })),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: SARIF_LEVEL[f.severity],
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: { startLine: f.line, startColumn: f.col },
              },
            },
          ],
          partialFingerprints: { "midnightShield/v1": f.fingerprint },
          properties: { confidence: f.confidence },
          ...(f.suppressed ? { suppressions: [{ kind: f.suppressed === "inline" ? "inSource" : "external", ...(f.suppressionReason ? { justification: f.suppressionReason } : {}) }] } : {}),
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

const SEVERITY_ICON: Record<Severity, string> = {
  critical: "🟣",
  high: "🔴",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

function mdEscape(s: string): string {
  return s.replace(/\|/g, "\\|");
}

/** A Markdown report for audits and pull requests. */
export function formatMarkdown(all: Finding[], fileCount: number, options: { title?: string; date?: string } = {}): string {
  const findings = all.filter((f) => !f.suppressed);
  const suppressed = all.filter((f) => f.suppressed);
  const out: string[] = [];
  out.push(`# ${options.title ?? "Midnight Shield report"}`);
  out.push("");
  out.push(`Generated by [Midnight Shield](https://github.com/efforthye/midnight-shield) ${VERSION}${options.date ? ` on ${options.date}` : ""}. Scanned ${plural(fileCount, "file")}.`);
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Severity | Findings |");
  out.push("| --- | --- |");
  for (const s of SEVERITY_ORDER) out.push(`| ${SEVERITY_ICON[s]} ${s} | ${findings.filter((f) => f.severity === s).length} |`);
  out.push(`| **Total** | **${findings.length}** |`);
  if (suppressed.length) out.push(`| Suppressed | ${suppressed.length} |`);
  out.push("");

  if (findings.length) {
    out.push("## Findings");
    out.push("");
    out.push("| # | Severity | Rule | Location | Confidence |");
    out.push("| --- | --- | --- | --- | --- |");
    findings.forEach((f, i) => {
      out.push(`| ${i + 1} | ${SEVERITY_ICON[f.severity]} ${f.severity} | [${f.ruleId}](${f.docUrl}) ${f.ruleName} | \`${f.file}:${f.line}\` | ${f.confidence} |`);
    });
    out.push("");
    findings.forEach((f, i) => {
      out.push(`### ${i + 1}. ${f.ruleId} ${f.ruleName}`);
      out.push("");
      out.push(`**${f.severity}** · ${f.confidence} confidence · \`${f.file}:${f.line}:${f.col}\``);
      out.push("");
      out.push(f.message);
      out.push("");
      if (f.snippet.trim()) {
        out.push("```compact");
        out.push(f.snippet.replace(/^\s+/, ""));
        out.push("```");
        out.push("");
      }
      if (f.suggestion) {
        out.push("Suggested fix:");
        out.push("");
        out.push("```diff");
        for (const d of suggestionDiff(f.suggestion)) out.push(`${d.kind} ${d.text}`);
        out.push("```");
        out.push("");
        if (f.suggestion.note) {
          out.push(f.suggestion.note);
          out.push("");
        }
      }
      out.push(`How to fix: [${f.ruleId}](${f.docUrl})`);
      out.push("");
    });
  } else {
    out.push("No findings. ✔");
    out.push("");
  }

  if (suppressed.length) {
    out.push("## Suppressed findings");
    out.push("");
    out.push("| Rule | Location | Reason |");
    out.push("| --- | --- | --- |");
    for (const f of suppressed) out.push(`| ${f.ruleId} ${f.ruleName} | \`${f.file}:${f.line}\` | ${f.suppressed === "inline" ? "inline comment" : "baseline"} |`);
    out.push("");
  }

  out.push("---");
  out.push("");
  out.push("_A static analyzer reduces risk but does not prove a contract is secure. Contracts that hold value should also get a manual review._");
  return out.join("\n");
}

// ---------- disclosure map ----------

const PROTECTION_LABEL: Record<DisclosureEntry["protection"], string> = {
  raw: "RAW",
  hash: "hash",
  commit: "commitment",
  public: "public data",
  constant: "constant",
};

function describeVia(d: DisclosureEntry): string {
  if (d.via === "return") return "return value";
  if (d.via === "ledger write") return `ledger ${d.target ?? ""}`.trim();
  return "disclose()";
}

function describeSources(d: DisclosureEntry): string {
  return d.sources.length ? d.sources.map((s) => (s.startsWith("witness:") ? `${s.slice(8)}()` : s.slice(6))).join(", ") : "-";
}

export function formatDisclosures(entries: DisclosureEntry[], options: { color?: boolean } = {}): string {
  const color = options.color ?? true;
  const c = (code: string, s: string) => (color ? code + s + RESET : s);
  const lines: string[] = [];
  let currentFile = "";
  const shown = entries.filter((e) => e.protection !== "constant");
  for (const d of shown) {
    if (d.file !== currentFile) {
      if (currentFile) lines.push("");
      lines.push(c(BOLD + "\x1b[4m", d.file));
      lines.push(c(DIM, `  ${"line".padEnd(6)}${"circuit".padEnd(18)}${"becomes public via".padEnd(26)}${"private inputs".padEnd(28)}protection`));
      currentFile = d.file;
    }
    const prot =
      d.protection === "raw"
        ? c("\x1b[31m", `RAW${d.secretBits !== undefined ? ` (${plural(d.secretBits, "bit")})` : ""}`)
        : d.protection === "hash" && d.secretBits !== undefined && d.secretBits <= 32
          ? c("\x1b[33m", `hash (${plural(d.secretBits, "bit")})`)
          : d.protection === "commit"
            ? c("\x1b[32m", PROTECTION_LABEL.commit)
            : PROTECTION_LABEL[d.protection];
    const flags = d.findings.length ? c("\x1b[33m", `  ⚠ ${d.findings.join(", ")}`) : "";
    lines.push(`  ${String(d.loc.line).padEnd(6)}${d.circuit.slice(0, 17).padEnd(18)}${describeVia(d).slice(0, 25).padEnd(26)}${describeSources(d).slice(0, 27).padEnd(28)}${prot}${flags}`);
  }
  if (!shown.length) lines.push("Nothing in these files becomes public.");
  const raw = shown.filter((d) => d.protection === "raw").length;
  lines.push("");
  lines.push(`${plural(shown.length, "disclosure point")}, ${raw} of them publish private data without a hash or commitment.`);
  return lines.join("\n");
}

export function formatDisclosuresMarkdown(entries: DisclosureEntry[]): string {
  const out = ["# Disclosure map", "", "Every point where data becomes public: `disclose()`, ledger writes, and return values of exported circuits.", ""];
  out.push("| File | Line | Circuit | Becomes public via | Private inputs | Protection | Findings |");
  out.push("| --- | --- | --- | --- | --- | --- | --- |");
  for (const d of entries.filter((e) => e.protection !== "constant")) {
    const prot = PROTECTION_LABEL[d.protection] + (d.secretBits !== undefined && d.protection !== "public" ? ` (${plural(d.secretBits, "bit")})` : "");
    out.push(`| \`${d.file}\` | ${d.loc.line} | ${mdEscape(d.circuit)} | ${mdEscape(describeVia(d))} | ${mdEscape(describeSources(d))} | ${prot} | ${d.findings.join(", ")} |`);
  }
  return out.join("\n");
}

const GUARD_SHORT: Record<GuardKind, string> = {
  secret: "secret",
  "allow-list": "allow-list",
  signature: "signature",
  merkle: "Merkle proof",
  "caller-key": "ownPublicKey()",
  "claimed-id": "claimed id",
  "witness-result": "witness result",
  imported: "imported",
  "one-time": "one-time",
  state: "state",
  input: "inputs",
};

const WHO_LABEL: Record<Who, string> = {
  restricted: "restricted",
  imported: "unread import",
  bypassable: "BYPASSABLE",
  anyone: "anyone",
};

/** Caller checks first, grouped by kind with their lines; one-time, state and input checks once, at the end. */
function describeGuards(a: AccessEntry): string {
  const groups = new Map<string, string[]>();
  for (const g of a.guards) {
    if (g.kind === "state" || g.kind === "input" || g.kind === "one-time") continue;
    const label = g.kind === "imported" && g.callee ? `${g.callee}()` : GUARD_SHORT[g.kind];
    const at = `${g.line}${g.bypass ? ` (${g.bypass})` : ""}`;
    const list = groups.get(label) ?? [];
    if (!list.includes(at)) list.push(at);
    groups.set(label, list);
  }
  const parts = [...groups].map(([label, at]) => `${label} l.${at.join(", ")}`);
  if (a.guards.some((g) => g.kind === "one-time")) parts.push("one-time");
  if (a.guards.some((g) => g.kind === "state")) parts.push("state");
  if (a.guards.some((g) => g.kind === "input")) parts.push("inputs");
  return parts.join(", ") || "-";
}

const uniq = (xs: string[]) => [...new Set(xs)];
const accessWrites = (a: AccessEntry) => uniq(a.writes.map((w) => w.field)).join(", ") || "-";
const accessTokens = (a: AccessEntry) => uniq(a.tokens.map((t) => t.op)).join(", ") || "-";

function accessSummary(entries: AccessEntry[]): string {
  const count = (w: Who) => entries.filter((e) => e.who === w).length;
  const openActing = entries.filter((e) => e.who === "anyone" && (e.writes.length || e.tokens.some((t) => !t.op.startsWith("receive")))).length;
  return (
    `${plural(entries.length, "exported circuit")}: ${count("restricted")} check the caller, ${count("imported")} call imported code that could not be read (it may check the caller), ` +
    `${count("bypassable")} have only checks anyone can pass, ${count("anyone")} are open to anyone (${openActing} of them change state or move tokens).`
  );
}

export function formatAccess(entries: AccessEntry[], options: { color?: boolean } = {}): string {
  const color = options.color ?? true;
  const c = (code: string, s: string) => (color ? code + s + RESET : s);
  const lines: string[] = [];
  let currentFile = "";
  for (const a of entries) {
    if (a.file !== currentFile) {
      if (currentFile) lines.push("");
      lines.push(c(BOLD + "\x1b[4m", a.file));
      lines.push(c(DIM, `  ${"circuit".padEnd(22)}${"who can call".padEnd(16)}${"changes".padEnd(26)}${"tokens".padEnd(16)}checks`));
      currentFile = a.file;
    }
    const acts = a.writes.length > 0 || a.tokens.length > 0;
    const who =
      a.who === "restricted" ? c("\x1b[32m", WHO_LABEL.restricted.padEnd(16))
      : a.who === "bypassable" ? c("\x1b[31m", WHO_LABEL.bypassable.padEnd(16))
      : a.who === "imported" ? c("\x1b[33m", WHO_LABEL.imported.padEnd(16))
      : acts ? c("\x1b[31m", "anyone".padEnd(16)) : c(DIM, "anyone".padEnd(16));
    const name = (a.module ? `${a.name} (module)` : a.name).slice(0, 21).padEnd(22);
    const flags = a.findings.length ? c("\x1b[33m", `  ⚠ ${a.findings.join(", ")}`) : "";
    lines.push(`  ${name}${who}${accessWrites(a).slice(0, 25).padEnd(26)}${accessTokens(a).slice(0, 15).padEnd(16)}${describeGuards(a)}${flags}`);
  }
  if (!entries.length) lines.push("No exported circuits in these files.");
  else {
    lines.push("");
    lines.push(accessSummary(entries));
    lines.push(c(DIM, "BYPASSABLE: every caller check is one the prover controls (MS001 ownPublicKey(), MS009 unbound Merkle path, MS013 witness result, MS036 a stored id compared with a parameter)."));
  }
  return lines.join("\n");
}

export function formatAccessMarkdown(entries: AccessEntry[]): string {
  const out = ["# Access map", "", "Who can call each exported circuit, what it checks, which ledger fields it changes and which tokens it moves.", ""];
  out.push("| File | Circuit | Who can call | Changes | Tokens | Checks | Findings |");
  out.push("| --- | --- | --- | --- | --- | --- | --- |");
  for (const a of entries) {
    out.push(`| \`${a.file}\` | ${mdEscape(a.module ? `${a.name} (module)` : a.name)} | ${WHO_LABEL[a.who]} | ${mdEscape(accessWrites(a))} | ${mdEscape(accessTokens(a))} | ${mdEscape(describeGuards(a))} | ${a.findings.join(", ")} |`);
  }
  if (entries.length) out.push("", accessSummary(entries));
  return out.join("\n");
}

const SHORT_CONSTRAINT: Record<Constraint, string> = {
  "tied to ledger": "ledger",
  "hash or signature": "hash",
  "bounded by constant": "constant",
  membership: "membership",
  "coin value": "coin",
  "only other prover values": "prover values only",
};

/** The strongest constraint on an input decides its status. */
function inputStatus(i: InputReport): Status {
  const kinds = new Set(i.constraints.map((c) => c.kind));
  if (kinds.has("tied to ledger") || kinds.has("hash or signature") || kinds.has("membership") || kinds.has("coin value")) return "anchored";
  if (kinds.has("bounded by constant")) return "bounded";
  if (kinds.has("only other prover values")) return "circular";
  if (i.hashedOnly) return "secret";
  return i.kind === "witness" && i.reaches.length ? "free" : "input";
}

type Status = "anchored" | "bounded" | "circular" | "secret" | "input" | "free";
const STATUS_LABEL: Record<Status, string> = { anchored: "anchored", bounded: "bounded", circular: "CIRCULAR", secret: "secret", input: "input", free: "FREE" };

function describeConstraints(i: InputReport): string {
  const groups = new Map<string, number[]>();
  for (const c of i.constraints) {
    const k = SHORT_CONSTRAINT[c.kind];
    const list = groups.get(k) ?? [];
    if (!list.includes(c.line)) list.push(c.line);
    groups.set(k, list);
  }
  return [...groups].map(([k, lines]) => (k === "coin" ? k : `${k} l.${lines.join(", ")}`)).join(", ") || "-";
}

/** Inputs worth showing: anything that reaches state or a transfer, and anything checked. */
const shownInputs = (c: ConstraintEntry) => c.inputs.filter((i) => i.reaches.length || i.constraints.length);

export function formatConstraints(entries: ConstraintEntry[], options: { color?: boolean } = {}): string {
  const color = options.color ?? true;
  const c = (code: string, s: string) => (color ? code + s + RESET : s);
  const lines: string[] = [];
  let currentFile = "";
  let free = 0;
  let circular = 0;
  for (const e of entries) {
    const inputs = shownInputs(e);
    if (!inputs.length) continue;
    if (e.file !== currentFile) {
      if (currentFile) lines.push("");
      lines.push(c(BOLD + "\x1b[4m", e.file));
      lines.push(c(DIM, `  ${"circuit".padEnd(20)}${"prover-chosen value".padEnd(24)}${"status".padEnd(11)}${"reaches".padEnd(34)}constrained by`));
      currentFile = e.file;
    }
    inputs.forEach((i, n) => {
      const st = inputStatus(i);
      // a free parameter that only reaches state is ordinary input; a free witness is what MS002 is about
      const loud = st === "free" || st === "circular";
      if (st === "circular") circular++;
      if (st === "free") free++;
      const status = st === "anchored" ? c("\x1b[32m", STATUS_LABEL[st].padEnd(11)) : loud ? c("\x1b[31m", STATUS_LABEL[st].padEnd(11)) : STATUS_LABEL[st].padEnd(11);
      const name = (n === 0 ? (e.module ? `${e.name} (module)` : e.name) : "").slice(0, 19).padEnd(20);
      lines.push(`  ${name}${i.name.slice(0, 23).padEnd(24)}${status}${(i.reaches.join(", ") || "-").slice(0, 33).padEnd(34)}${describeConstraints(i)}`);
    });
  }
  if (!lines.length) return "No prover-chosen values reach state, transfers or checks in these files.";
  lines.push("");
  lines.push(`${plural(free, "witness value")} reach state or a transfer with no check (FREE), ${plural(circular, "value")} only checked against other prover-chosen values (CIRCULAR).`);
  lines.push(c(DIM, "anchored: tied to ledger state, a hash, a membership proof or a received coin. bounded: limited by a constant only. secret: only used hashed. input: a parameter used as given."));
  return lines.join("\n");
}

export function formatConstraintsMarkdown(entries: ConstraintEntry[]): string {
  const out = ["# Witness constraint report", "", "Every value the prover chooses (witness results and circuit parameters), where it ends up, and what constrains it.", ""];
  out.push("| File | Circuit | Value | Status | Reaches | Constrained by |");
  out.push("| --- | --- | --- | --- | --- | --- |");
  for (const e of entries) {
    for (const i of shownInputs(e)) {
      out.push(`| \`${e.file}\` | ${mdEscape(e.name)} | \`${mdEscape(i.name)}\` | ${STATUS_LABEL[inputStatus(i)]} | ${mdEscape(i.reaches.join(", ") || "-")} | ${mdEscape(describeConstraints(i))} |`);
    }
  }
  return out.join("\n");
}
