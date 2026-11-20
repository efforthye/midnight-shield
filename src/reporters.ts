import type { Finding } from "./linter.js";
import { RULES, SEVERITY_ORDER, ruleDocUrl, type Severity } from "./rules.js";

const COLORS: Record<Severity, string> = {
  critical: "\x1b[35m",
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
};
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";

export interface TextOptions {
  color?: boolean;
  /** show the source line and a caret under each finding (default: true) */
  codeFrame?: boolean;
  /** show the rule documentation link (default: true) */
  links?: boolean;
}

function caretLength(snippet: string, col: number): number {
  const rest = snippet.slice(col - 1);
  const m = rest.match(/^[A-Za-z_$][\w$]*(\(\))?/);
  return m ? m[0].length : 1;
}

export function formatText(findings: Finding[], fileCount: number, options: TextOptions | boolean = {}): string {
  const opts: TextOptions = typeof options === "boolean" ? { color: options } : options;
  const color = opts.color ?? true;
  const codeFrame = opts.codeFrame ?? true;
  const links = opts.links ?? true;
  const c = (code: string, s: string) => (color ? code + s + RESET : s);
  const lines: string[] = [];
  let currentFile = "";
  for (const f of findings) {
    if (f.file !== currentFile) {
      if (currentFile) lines.push("");
      lines.push(c("\x1b[1;4m", f.file));
      currentFile = f.file;
    }
    lines.push("");
    const sev = c("\x1b[1m" + COLORS[f.severity], f.severity.toUpperCase().padEnd(8));
    lines.push(`  ${sev}  ${c("\x1b[1m", f.ruleId)} ${c(DIM, f.ruleName)}  ${c(DIM, `${f.file}:${f.line}:${f.col}`)}`);
    lines.push(`  ${f.message}`);
    if (codeFrame && f.snippet.trim()) {
      const num = String(f.line);
      const gutter = " ".repeat(num.length);
      const text = f.snippet.replace(/\t/g, " ");
      lines.push(`    ${c(DIM, num + " │")} ${text}`);
      lines.push(`    ${c(DIM, gutter + " │")} ${" ".repeat(Math.max(0, f.col - 1))}${c(COLORS[f.severity], "^".repeat(caretLength(text, f.col)))}`);
    }
    if (links) lines.push(`  ${c(DIM, "→ " + f.docUrl)}`);
  }
  const counts = new Map<Severity, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const summary = SEVERITY_ORDER.filter((sv) => counts.has(sv))
    .map((sv) => c(COLORS[sv], `${counts.get(sv)} ${sv}`))
    .join(", ");
  if (lines.length) lines.push("");
  const files = `${fileCount} file${fileCount === 1 ? "" : "s"}`;
  lines.push(
    findings.length
      ? `${c("\x1b[1m", `✖ ${findings.length} finding${findings.length === 1 ? "" : "s"}`)} in ${files} (${summary})`
      : c("\x1b[32m", `✔ No findings in ${files}.`),
  );
  return lines.join("\n");
}

export function formatJson(findings: Finding[]): string {
  return JSON.stringify({ tool: "midnight-shield", version: VERSION, findings }, null, 2);
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

export function formatSarif(findings: Finding[]): string {
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
            rules: RULES.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.summary },
              helpUri: ruleDocUrl(r.id),
              defaultConfiguration: { level: SARIF_LEVEL[r.severity] },
              properties: {
                tags: ["security", "privacy", "midnight", "compact"],
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
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

export const VERSION = "0.3.0";
