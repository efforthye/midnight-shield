import { Analyzer, type DisclosureEvent, type ImportResolver, type RawFinding } from "./analyzer.js";
import type { Program } from "./ast.js";
import { pragmaFix, type TextEdit } from "./fixes.js";
import { lex } from "./lexer.js";
import { parse } from "./parser.js";
import { runCustomRule, type CustomRule } from "./plugins.js";
import { isSdkFile, isTestFile, lintSdkSource } from "./sdk.js";
import { checkAuthWrites } from "./auth-writes.js";
import { checkStructural } from "./structural.js";
import { checkContract } from "./contract-checks.js";
import { suggestFix, type Suggestion } from "./suggest.js";
import { CONFIDENCE_ORDER, RULES_BY_ID, SEVERITY_ORDER, ruleDocUrl, type Confidence, type RuleMeta, type Severity } from "./rules.js";

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  /** how sure the rule is that this is a real problem */
  confidence: Confidence;
  message: string;
  file: string;
  line: number;
  col: number;
  docUrl: string;
  /** the source line the finding points at */
  snippet: string;
  /** stable ID that survives unrelated edits (used by baselines) */
  fingerprint: string;
  /** set when the finding is hidden by an inline comment or a baseline */
  suppressed?: "inline" | "baseline";
  /** a safe automatic fix, when one exists */
  fix?: TextEdit;
  /** a suggested fix to review and apply by hand (see suggest.ts) */
  suggestion?: Suggestion;
}

export interface LintOptions {
  /** rule IDs to skip */
  disable?: string[];
  /** only report findings at or above this severity */
  minSeverity?: Severity;
  /** only report findings at or above this confidence */
  minConfidence?: Confidence;
  /** glob patterns of files to skip, e.g. "**\/test/**" */
  ignore?: string[];
  /** resolves `import "path"` so imported circuits are followed */
  resolver?: ImportResolver;
  /** absolute path of the file, used to resolve relative imports */
  absolutePath?: string;
  /** custom rules loaded from plugins */
  plugins?: CustomRule[];
  /** fingerprints of accepted findings (from a baseline file) */
  baseline?: Set<string>;
  /** also return suppressed findings, marked with `suppressed` */
  includeSuppressed?: boolean;
  /** also check TypeScript/JavaScript files (MS101, MS102); default true */
  sdk?: boolean;
}

const DIRECTIVE = /shield-disable(-next-line|-line|-file)?\b([^\n]*)/;

interface Suppressions {
  file: Set<string> | "all" | undefined;
  lines: Map<number, Set<string> | "all">;
}

function parseIds(rest: string): Set<string> | "all" {
  const ids = rest.match(/\b[A-Z][A-Z0-9]*\d{3}\b/g);
  return ids && ids.length ? new Set(ids) : "all";
}

function collectSuppressions(source: string): Suppressions {
  const { comments } = lex(source);
  const out: Suppressions = { file: undefined, lines: new Map() };
  const addLine = (line: number, ids: Set<string> | "all") => {
    const prev = out.lines.get(line);
    if (prev === "all" || ids === "all") out.lines.set(line, "all");
    else out.lines.set(line, new Set([...(prev ?? []), ...ids]));
  };
  for (const c of comments) {
    const m = c.text.match(DIRECTIVE);
    if (!m) continue;
    const ids = parseIds(m[2]);
    if (m[1] === "-file") out.file = ids;
    else if (m[1] === "-next-line") addLine(c.endLine + 1, ids);
    else addLine(c.line, ids);
  }
  return out;
}

function isSuppressed(s: Suppressions, ruleId: string, line: number): boolean {
  const match = (v: Set<string> | "all" | undefined) => v === "all" || (v instanceof Set && v.has(ruleId));
  return match(s.file) || match(s.lines.get(line));
}

/** Fingerprint = rule + file + the trimmed source line + occurrence index, so moving code up or down keeps it stable. */
function fingerprint(ruleId: string, file: string, snippet: string, occurrence: number): string {
  return hash53(`${ruleId}|${file}|${snippet.trim()}|${occurrence}`);
}

/** cyrb53: a small, fast, well-distributed 53-bit string hash (no Node APIs, so it also runs in the browser). */
function hash53(str: string): string {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(14, "0");
}

function metaFor(ruleId: string, plugins: CustomRule[] = []): RuleMeta {
  return RULES_BY_ID.get(ruleId) ?? plugins.find((p) => p.id === ruleId)!;
}

interface Analysis {
  program?: Program;
  analyzer?: Analyzer;
  raw: RawFinding[];
}

/** MS030: invisible bidirectional-control characters that make code read differently from how it runs (Trojan Source). */
function bidiCharacters(source: string): RawFinding[] {
  const out: RawFinding[] = [];
  const lines = source.split(/\r?\n/);
  lines.forEach((l, i) => {
    const m = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/.exec(l);
    if (!m) return;
    out.push({
      ruleId: "MS030",
      severity: "high",
      confidence: "high",
      loc: { line: i + 1, col: m.index + 1 },
      message: `This line contains an invisible text-direction character (U+${m[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}). It can make the code look different from what the compiler sees, for example hiding a check inside a comment (the "Trojan Source" attack). Remove it.`,
    });
  });
  return out;
}

function analyze(source: string, file: string, options: LintOptions): Analysis {
  if (isSdkFile(file)) return { raw: isTestFile(file) ? [] : [...lintSdkSource(source), ...bidiCharacters(source)] };
  const program = parse(source);
  const analyzer = new Analyzer(program, options.resolver, options.absolutePath);
  const raw = analyzer.run();
  raw.push(...checkAuthWrites(program), ...checkStructural(program), ...checkContract(program), ...bidiCharacters(source));
  for (const rule of options.plugins ?? []) raw.push(...runCustomRule(rule, file, source, program));
  return { program, analyzer, raw };
}

export function lintSource(source: string, file = "contract.compact", options: LintOptions = {}): Finding[] {
  const { raw } = analyze(source, file, options);
  return toFindings(raw, source, file, options);
}

function toFindings(raw: RawFinding[], source: string, file: string, options: LintOptions): Finding[] {
  const lines = source.split(/\r?\n/);
  const suppressions = collectSuppressions(source);
  const disabled = new Set(options.disable ?? []);
  const minRank = SEVERITY_ORDER.indexOf(options.minSeverity ?? "info");
  const minConf = CONFIDENCE_ORDER.indexOf(options.minConfidence ?? "low");
  const occurrences = new Map<string, number>();

  const all: Finding[] = raw
    .filter((f) => !disabled.has(f.ruleId))
    .filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= minRank)
    .filter((f) => CONFIDENCE_ORDER.indexOf(f.confidence) <= minConf)
    .sort((a, b) => a.loc.line - b.loc.line || a.loc.col - b.loc.col)
    .map((f) => {
      const meta = metaFor(f.ruleId, options.plugins);
      const snippet = lines[f.loc.line - 1] ?? "";
      const key = `${f.ruleId}|${snippet.trim()}`;
      const n = occurrences.get(key) ?? 0;
      occurrences.set(key, n + 1);
      const finding: Finding = {
        ruleId: f.ruleId,
        ruleName: meta.name,
        severity: f.severity,
        confidence: f.confidence,
        message: f.message,
        file,
        line: f.loc.line,
        col: f.loc.col,
        docUrl: ruleDocUrl(f.ruleId, meta),
        snippet,
        fingerprint: fingerprint(f.ruleId, file, snippet, n),
      };
      if (f.ruleId === "MS006") finding.fix = pragmaFix(source);
      const suggestion = suggestFix(f.ruleId, f.message, snippet);
      if (suggestion) finding.suggestion = suggestion;
      if (isSuppressed(suppressions, f.ruleId, f.loc.line)) finding.suppressed = "inline";
      else if (options.baseline?.has(finding.fingerprint)) finding.suppressed = "baseline";
      return finding;
    });

  return options.includeSuppressed ? all : all.filter((f) => !f.suppressed);
}

export interface DisclosureEntry extends DisclosureEvent {
  file: string;
  snippet: string;
  /** rule IDs reported on the same line */
  findings: string[];
}

/** List every point where data becomes public in a file (the disclosure map). */
export function mapDisclosures(source: string, file = "contract.compact", options: LintOptions = {}): DisclosureEntry[] {
  const { analyzer, raw } = analyze(source, file, options);
  if (!analyzer) return [];
  const lines = source.split(/\r?\n/);
  return analyzer.getDisclosures().map((d) => ({
    ...d,
    file,
    snippet: lines[d.loc.line - 1] ?? "",
    findings: [...new Set(raw.filter((f) => f.loc.line === d.loc.line && f.ruleId !== "MS000").map((f) => f.ruleId))].sort(),
  }));
}


// ---------- baselines ----------

export interface BaselineFile {
  tool: "midnight-shield";
  version: 1;
  findings: { fingerprint: string; ruleId: string; file: string; line: number; message: string }[];
}

export function createBaseline(findings: Finding[]): BaselineFile {
  return {
    tool: "midnight-shield",
    version: 1,
    findings: findings
      .filter((f) => f.suppressed !== "inline")
      .map((f) => ({ fingerprint: f.fingerprint, ruleId: f.ruleId, file: f.file, line: f.line, message: f.message })),
  };
}

