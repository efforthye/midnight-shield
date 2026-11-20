import type { Finding } from "./linter.js";
import { RULES, ruleDocUrl, type Severity } from "./rules.js";

const COLORS: Record<Severity, string> = {
  critical: "\x1b[35m",
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
};
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";

export function formatText(findings: Finding[], fileCount: number, color = true): string {
  const c = (code: string, s: string) => (color ? code + s + RESET : s);
  const lines: string[] = [];
  let currentFile = "";
  for (const f of findings) {
    if (f.file !== currentFile) {
      if (currentFile) lines.push("");
      lines.push(c("\x1b[4m", f.file));
      currentFile = f.file;
    }
    const sev = c(COLORS[f.severity], f.severity.toUpperCase().padEnd(8));
    lines.push(`  ${`${f.line}:${f.col}`.padEnd(8)} ${sev} ${f.ruleId} ${c(DIM, f.ruleName)}`);
    lines.push(`           ${f.message}`);
  }
  const counts = new Map<Severity, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const summary = [...counts.entries()].map(([s, n]) => `${n} ${s}`).join(", ");
  if (lines.length) lines.push("");
  lines.push(
    findings.length
      ? `${findings.length} finding${findings.length === 1 ? "" : "s"} in ${fileCount} file${fileCount === 1 ? "" : "s"} (${summary})`
      : `No findings in ${fileCount} file${fileCount === 1 ? "" : "s"}.`,
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

export const VERSION = "0.1.0";
