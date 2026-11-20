// Privacy diff: what a change (a pull request) makes public that was private
// before, and which findings it adds or fixes. Works on two snapshots taken
// with `midnight-shield snapshot`, so the base and the head can be scanned in
// different checkouts. Browser-safe.

import type { DisclosureEntry, Finding } from "./linter.js";
import { SEVERITY_ORDER, type Severity } from "./rules.js";

export interface SnapshotFinding {
  fingerprint: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  confidence: string;
  file: string;
  line: number;
  message: string;
  docUrl: string;
}

export interface SnapshotDisclosure {
  file: string;
  line: number;
  circuit: string;
  via: DisclosureEntry["via"];
  target?: string;
  sources: string[];
  protection: DisclosureEntry["protection"];
  secretBits?: number;
}

export interface Snapshot {
  tool: "midnight-shield";
  snapshot: 1;
  version: string;
  findings: SnapshotFinding[];
  disclosures: SnapshotDisclosure[];
}

export function createSnapshot(findings: Finding[], disclosures: DisclosureEntry[], version: string): Snapshot {
  return {
    tool: "midnight-shield",
    snapshot: 1,
    version,
    findings: findings
      .filter((f) => !f.suppressed)
      .map((f) => ({ fingerprint: f.fingerprint, ruleId: f.ruleId, ruleName: f.ruleName, severity: f.severity, confidence: f.confidence, file: f.file, line: f.line, message: f.message, docUrl: f.docUrl })),
    disclosures: disclosures
      .filter((d) => d.protection !== "constant")
      .map((d) => ({ file: d.file, line: d.loc.line, circuit: d.circuit, via: d.via, target: d.target, sources: [...d.sources].sort(), protection: d.protection, secretBits: d.secretBits })),
  };
}

export function readSnapshot(json: string, name: string): Snapshot {
  let data: Snapshot;
  try {
    data = JSON.parse(json);
  } catch {
    throw new Error(`${name} is not valid JSON`);
  }
  if (data?.tool !== "midnight-shield" || data.snapshot !== 1 || !Array.isArray(data.findings) || !Array.isArray(data.disclosures)) {
    throw new Error(`${name} is not a Midnight Shield snapshot (create one with: midnight-shield snapshot -o ${name})`);
  }
  return data;
}

export interface ProtectionChange {
  before: SnapshotDisclosure;
  after: SnapshotDisclosure;
}

export interface PrivacyDiff {
  /** data that becomes public in head but not in base */
  added: SnapshotDisclosure[];
  /** data public in base that head no longer publishes */
  removed: SnapshotDisclosure[];
  /** the same data, published with a different protection (e.g. hash → raw) */
  changed: ProtectionChange[];
  newFindings: SnapshotFinding[];
  fixedFindings: SnapshotFinding[];
}

/** Where and what is published, without the line number (code moves) or the protection. */
const place = (d: SnapshotDisclosure) => [d.file, d.circuit, d.via, d.target ?? "", d.sources.join(",")].join("|");
const PROTECTION_RANK: Record<string, number> = { raw: 0, hash: 1, commit: 2, public: 3, constant: 4 };

/** Multiset difference by key. */
function minus<T>(a: T[], b: T[], key: (x: T) => string): T[] {
  const counts = new Map<string, number>();
  for (const x of b) counts.set(key(x), (counts.get(key(x)) ?? 0) + 1);
  const out: T[] = [];
  for (const x of a) {
    const n = counts.get(key(x)) ?? 0;
    if (n > 0) counts.set(key(x), n - 1);
    else out.push(x);
  }
  return out;
}

export function diffSnapshots(base: Snapshot, head: Snapshot): PrivacyDiff {
  const full = (d: SnapshotDisclosure) => `${place(d)}|${d.protection}`;
  let added = minus(head.disclosures, base.disclosures, full);
  let removed = minus(base.disclosures, head.disclosures, full);
  // pair an added and a removed entry at the same place: its protection changed
  const changed: ProtectionChange[] = [];
  for (const a of [...added]) {
    const i = removed.findIndex((r) => place(r) === place(a));
    if (i === -1) continue;
    changed.push({ before: removed[i], after: a });
    removed = removed.filter((_, k) => k !== i);
    added = added.filter((x) => x !== a);
  }
  const fp = (f: SnapshotFinding) => f.fingerprint;
  const bySeverity = (x: SnapshotFinding, y: SnapshotFinding) => SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity) || x.file.localeCompare(y.file) || x.line - y.line;
  return {
    added,
    removed,
    changed,
    newFindings: minus(head.findings, base.findings, fp).sort(bySeverity),
    fixedFindings: minus(base.findings, head.findings, fp).sort(bySeverity),
  };
}

export function diffIsEmpty(d: PrivacyDiff): boolean {
  return !d.added.length && !d.removed.length && !d.changed.length && !d.newFindings.length && !d.fixedFindings.length;
}

/** A protection change that exposes more than before (commitment → hash → raw). */
export function isWeakening(c: ProtectionChange): boolean {
  return (PROTECTION_RANK[c.after.protection] ?? 9) < (PROTECTION_RANK[c.before.protection] ?? 9);
}

const SEVERITY_ICON: Record<Severity, string> = { critical: "🟣", high: "🔴", medium: "🟡", low: "🔵", info: "⚪" };

function protectionText(d: SnapshotDisclosure): string {
  const bits = d.secretBits !== undefined ? ` (${d.secretBits} bit${d.secretBits === 1 ? "" : "s"})` : "";
  if (d.protection === "raw") return `**raw**${bits}`;
  if (d.protection === "hash") return `hash${d.secretBits !== undefined && d.secretBits <= 32 ? bits : ""}`;
  if (d.protection === "commit") return "commitment";
  return d.protection;
}

const viaText = (d: SnapshotDisclosure) => (d.via === "return" ? "return value" : d.via === "ledger write" ? `ledger \`${d.target ?? ""}\`` : "`disclose()`");
const sourcesText = (d: SnapshotDisclosure) => (d.sources.length ? d.sources.map((s) => `\`${s.replace(/^witness:(.*)$/, "$1()").replace(/^param:/, "")}\``).join(", ") : "-");

function disclosureTable(rows: SnapshotDisclosure[]): string[] {
  return [
    "| Location | Circuit | Becomes public via | Private inputs | Protection |",
    "| --- | --- | --- | --- | --- |",
    ...rows.map((d) => `| \`${d.file}:${d.line}\` | \`${d.circuit}\` | ${viaText(d)} | ${sourcesText(d)} | ${protectionText(d)} |`),
  ];
}

function findingTable(rows: SnapshotFinding[]): string[] {
  return [
    "| Severity | Rule | Location | Message |",
    "| --- | --- | --- | --- |",
    ...rows.map((f) => `| ${SEVERITY_ICON[f.severity]} ${f.severity} | [${f.ruleId}](${f.docUrl}) ${f.ruleName} | \`${f.file}:${f.line}\` | ${f.message.split(". ")[0].replace(/\|/g, "\\|")}. |`),
  ];
}

/** The pull request comment. `marker` lets the Action find and update its own comment. */
export function formatDiffMarkdown(d: PrivacyDiff, options: { marker?: string; scanUrl?: string } = {}): string {
  const out: string[] = [];
  if (options.marker) out.push(options.marker);
  out.push("## 🛡️ Midnight Shield privacy diff");
  out.push("");
  if (diffIsEmpty(d)) {
    out.push("✅ This change does not make anything new public, and adds no findings.");
  } else {
    const weakened = d.changed.filter(isWeakening);
    const summary = [
      `**${d.added.length}** new public data`,
      weakened.length ? `**${weakened.length}** weaker protection` : "",
      `**${d.newFindings.length}** new finding${d.newFindings.length === 1 ? "" : "s"}`,
      d.fixedFindings.length ? `**${d.fixedFindings.length}** fixed` : "",
      d.removed.length ? `**${d.removed.length}** no longer public` : "",
    ].filter(Boolean);
    out.push(summary.join(" · "));
    if (d.added.length) {
      out.push("", "### Newly made public", "", "Values that this change publishes on chain. Check that each one is meant to be public.", "", ...disclosureTable(d.added));
    }
    if (d.changed.length) {
      out.push("", "### Protection changed", "", "| Location | Circuit | Before | After |", "| --- | --- | --- | --- |");
      for (const c of d.changed) out.push(`| \`${c.after.file}:${c.after.line}\` | \`${c.after.circuit}\` | ${protectionText(c.before)} | ${protectionText(c.after)}${isWeakening(c) ? " ⚠️" : ""} |`);
    }
    if (d.newFindings.length) out.push("", "### New findings", "", ...findingTable(d.newFindings));
    if (d.fixedFindings.length) out.push("", "### Fixed", "", ...findingTable(d.fixedFindings));
    if (d.removed.length) out.push("", "<details><summary>No longer public</summary>", "", ...disclosureTable(d.removed), "", "</details>");
  }
  out.push("");
  out.push(`<sub>[Midnight Shield](https://github.com/efforthye/midnight-shield) static analysis${options.scanUrl ? ` · [open in the playground](${options.scanUrl})` : ""} · A clean result is not an audit.</sub>`);
  return out.join("\n");
}

export function formatDiffText(d: PrivacyDiff): string {
  if (diffIsEmpty(d)) return "✔ No change in what becomes public, and no new findings.";
  const out: string[] = [];
  const line = (x: SnapshotDisclosure) => `${x.file}:${x.line}  ${x.circuit}  ${x.via === "ledger write" ? `ledger ${x.target}` : x.via}  ${x.sources.join(", ") || "-"}  ${x.protection}`;
  if (d.added.length) out.push(`Newly made public (${d.added.length})`, ...d.added.map((x) => "  + " + line(x)), "");
  if (d.changed.length) out.push(`Protection changed (${d.changed.length})`, ...d.changed.map((c) => `  ~ ${line(c.after)}  (was ${c.before.protection})`), "");
  if (d.newFindings.length) out.push(`New findings (${d.newFindings.length})`, ...d.newFindings.map((f) => `  + ${f.severity.toUpperCase()} ${f.ruleId} ${f.file}:${f.line}`), "");
  if (d.fixedFindings.length) out.push(`Fixed (${d.fixedFindings.length})`, ...d.fixedFindings.map((f) => `  - ${f.ruleId} ${f.file}:${f.line}`), "");
  if (d.removed.length) out.push(`No longer public (${d.removed.length})`, ...d.removed.map((x) => "  - " + line(x)), "");
  return out.join("\n").trimEnd();
}
