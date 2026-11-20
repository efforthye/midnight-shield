import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { Analyzer } from "./analyzer.js";
import { lex } from "./lexer.js";
import { parse } from "./parser.js";
import { RULES_BY_ID, SEVERITY_ORDER, ruleDocUrl, type Severity } from "./rules.js";

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  col: number;
  docUrl: string;
}

export interface LintOptions {
  /** rule IDs to skip */
  disable?: string[];
  /** only report findings at or above this severity */
  minSeverity?: Severity;
}

const DIRECTIVE = /shield-disable(-next-line|-line|-file)?\b([^\n]*)/;

interface Suppressions {
  file: Set<string> | "all" | undefined;
  lines: Map<number, Set<string> | "all">;
}

function parseIds(rest: string): Set<string> | "all" {
  const ids = rest.match(/MS\d{3}/g);
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

export function lintSource(source: string, file = "contract.compact", options: LintOptions = {}): Finding[] {
  const program = parse(source);
  const raw = new Analyzer(program).run();
  const suppressions = collectSuppressions(source);
  const disabled = new Set(options.disable ?? []);
  const minRank = SEVERITY_ORDER.indexOf(options.minSeverity ?? "info");

  return raw
    .filter((f) => !disabled.has(f.ruleId))
    .filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= minRank)
    .filter((f) => !isSuppressed(suppressions, f.ruleId, f.loc.line))
    .map((f) => ({
      ruleId: f.ruleId,
      ruleName: RULES_BY_ID.get(f.ruleId)!.name,
      severity: f.severity,
      message: f.message,
      file,
      line: f.loc.line,
      col: f.loc.col,
      docUrl: ruleDocUrl(f.ruleId),
    }))
    .sort((a, b) => a.line - b.line || a.col - b.col);
}

const IGNORED_DIRS = new Set(["node_modules", ".git", "dist", "build", "managed"]);

export function findCompactFiles(paths: string[]): string[] {
  const out: string[] = [];
  const walk = (p: string) => {
    const st = statSync(p);
    if (st.isDirectory()) {
      for (const name of readdirSync(p).sort()) {
        if (IGNORED_DIRS.has(name) || name.startsWith(".")) continue;
        walk(join(p, name));
      }
    } else if (p.endsWith(".compact")) {
      out.push(p);
    }
  };
  for (const p of paths) walk(p);
  return out;
}

export function lintFiles(paths: string[], options: LintOptions = {}, cwd = process.cwd()): Finding[] {
  const findings: Finding[] = [];
  for (const file of findCompactFiles(paths)) {
    const source = readFileSync(file, "utf8");
    findings.push(...lintSource(source, relative(cwd, file).split("\\").join("/"), options));
  }
  return findings;
}
