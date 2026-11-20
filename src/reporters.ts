import type { DisclosureEntry, Finding } from "./linter.js";
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
      lines.push(`  ${c(DIM, `${f.file}:${f.line}:${f.col}`)}  ${f.ruleId} ${f.ruleName}  ${c(DIM, `[${f.suppressed}]`)}`);
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
          ...(f.suppressed ? { suppressions: [{ kind: f.suppressed === "inline" ? "inSource" : "external" }] } : {}),
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
