import { checkFreeNullifiers, checkSelfSatisfiable, constraintMap, witnessRoles, type CircuitConstraints } from "./constraints.js";
import { accessMap, checkClaimedIdentity, checkInconsistentGuards, type CircuitAccess } from "./access.js";
import { Analyzer, type DisclosureEvent, type Evidence, type ImportResolver, type RawFinding } from "./analyzer.js";
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
  /** the reason given in the suppression comment (`-- reason`) */
  suppressionReason?: string;
  /** a safe automatic fix, when one exists */
  fix?: TextEdit;
  /** the engine's verdict behind the finding: value, where it goes, which checks it passes */
  evidence?: Evidence;
  /** set when the attack was run in the Compact runtime and went through (midnight-shield --confirm / exploit) */
  confirmed?: { detail: string; repro?: string };
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
  /** inline suppressions only count when they give a reason (`-- why`) */
  requireSuppressionReason?: boolean;
  /** also return suppressed findings, marked with `suppressed` */
  includeSuppressed?: boolean;
  /** also check TypeScript/JavaScript files (MS101, MS102); default true */
  sdk?: boolean;
}

const DIRECTIVE = /shield-disable(-next-line|-line|-file)?\b([^\n]*)/;

interface Suppressions {
  file: Set<string> | "all" | undefined;
  lines: Map<number, Set<string> | "all">;
  /** the reason written after `--`, by line (0 for the whole file) */
  reasons: Map<number, string>;
}

/** `MS005 MS003 -- the reason` → the IDs before `--` and the reason after it. */
function parseDirective(rest: string): { ids: Set<string> | "all"; reason?: string } {
  const at = rest.indexOf("--");
  const head = at === -1 ? rest : rest.slice(0, at);
  const reason = at === -1 ? undefined : rest.slice(at + 2).replace(/\*\/\s*$/, "").trim() || undefined;
  const ids = head.match(/\b[A-Z][A-Z0-9]*\d{3}\b/g);
  return { ids: ids && ids.length ? new Set(ids) : "all", reason };
}

function collectSuppressions(source: string): Suppressions {
  const { comments } = lex(source);
  const out: Suppressions = { file: undefined, lines: new Map(), reasons: new Map() };
  const addLine = (line: number, ids: Set<string> | "all") => {
    const prev = out.lines.get(line);
    if (prev === "all" || ids === "all") out.lines.set(line, "all");
    else out.lines.set(line, new Set([...(prev ?? []), ...ids]));
  };
  for (const c of comments) {
    const m = c.text.match(DIRECTIVE);
    if (!m) continue;
    const { ids, reason } = parseDirective(m[2]);
    const line = m[1] === "-file" ? 0 : m[1] === "-next-line" ? c.endLine + 1 : c.line;
    if (m[1] === "-file") out.file = ids;
    else addLine(line, ids);
    if (reason) out.reasons.set(line, reason);
  }
  return out;
}

/** Whether a comment suppresses this finding, and the reason it gives. */
function suppression(s: Suppressions, ruleId: string, line: number): { reason?: string } | undefined {
  const match = (v: Set<string> | "all" | undefined) => v === "all" || (v instanceof Set && v.has(ruleId));
  if (match(s.lines.get(line))) return { reason: s.reasons.get(line) };
  if (match(s.file)) return { reason: s.reasons.get(0) };
  return undefined;
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

/** Deploy and end-to-end scripts stub out witnesses they never run (zeros as a voter secret, say). */
const SCRIPT_FILE = /(^|\/)(e2e[^/]*|[^/]*deploy[^/]*|[^/]*\.e2e)\.[cm]?[jt]sx?$/i;

/**
 * Rules and the constraint engine must agree. MS002 is kept only where the
 * engine also sees the witness reach state with nothing constraining it, and
 * its message then says exactly where it goes. Every kept finding carries the
 * engine's verdict as evidence.
 */
function explainWithEngine(program: Program, raw: RawFinding[]): void {
  const map = constraintMap(program).filter((c) => !c.module);
  for (let i = raw.length - 1; i >= 0; i--) {
    const f = raw[i];
    if (f.ruleId !== "MS002") continue;
    const w = f.message.match(/Witness '([^']+)\(\)'/)?.[1];
    if (!w) continue;
    const name = `${w}()`;
    const free = map.flatMap((c) => c.inputs.filter((x) => x.name === name && !x.constraints.length && !x.hashedOnly && x.reaches.length > 0).map((x) => ({ c, x })));
    if (!free.length) {
      // the engine found a check on it in every circuit that uses it: no finding
      if (map.some((c) => c.inputs.some((x) => x.name === name))) raw.splice(i, 1);
      continue;
    }
    const { c, x } = free[0];
    const reaches = x.reaches;
    f.message = `Witness '${name}' goes into ${reaches.map((r) => (r === "return value" ? "the return value" : `'${r}'`)).join(", ")} of '${c.name}' and nothing checks its value: no assert compares it with a range, a ledger value or a membership proof. The prover's DApp can return any value here. Check it against something the contract trusts before using it.`;
    f.evidence = { circuit: c.name, value: name, reaches, checks: [], verdict: "FREE" };
  }
  for (const f of raw) {
    if (f.ruleId !== "MS037" || f.evidence) continue;
    const c = map.find((m) => m.selfSatisfiable.some((s) => s.line === f.loc.line));
    const s = c?.selfSatisfiable.find((x) => x.line === f.loc.line);
    if (c && s) f.evidence = { circuit: c.name, value: s.inputs.join(", "), reaches: [], checks: [{ kind: "only other prover values", line: s.line }], verdict: "CIRCULAR" };
  }
}

/** Access findings carry the access map's verdict for the circuit they are in. */
function explainAccess(program: Program, raw: RawFinding[], imports: Parameters<typeof accessMap>[2]): void {
  const ACCESS_RULES = new Set(["MS001", "MS009", "MS013", "MS019", "MS020", "MS035", "MS036"]);
  if (!raw.some((f) => ACCESS_RULES.has(f.ruleId) && !f.evidence)) return;
  const map = accessMap(program, raw, imports).filter((c) => !c.module);
  for (const f of raw) {
    if (!ACCESS_RULES.has(f.ruleId) || f.evidence) continue;
    const c = map.find((m) => m.guards.some((g) => g.line === f.loc.line) || m.writes.some((w) => w.line === f.loc.line) || m.tokens.some((t) => t.line === f.loc.line));
    if (!c) continue;
    f.evidence = {
      circuit: c.name,
      value: [...new Set(c.writes.map((w) => w.field))].join(", ") || "-",
      reaches: [...new Set([...c.writes.map((w) => w.field), ...c.tokens.map((t) => t.op)])],
      checks: c.guards.map((g) => ({ kind: g.bypass ? `${g.kind} (${g.bypass})` : g.kind, line: g.line })),
      verdict: c.who.toUpperCase(),
    };
  }
}

/** A minified or bundled build output: one huge line, or a webpack/Next.js chunk. Not source anyone wrote. */
function isBuildOutput(source: string): boolean {
  if (/webpackChunk|__NEXT_P|\/\*! For license information/.test(source.slice(0, 2000))) return true;
  const lines = source.split("\n");
  return lines.some((l) => l.length > 2000);
}

/** A copy of the Compact standard library (vendored for reference). */
const isStdlibCopy = (source: string) => /This file is part of Compact\./.test(source.slice(0, 400)) && /module\s+CompactStandardLibrary|export circuit (persistentHash|sendShielded|mintShieldedToken)\b/.test(source);

function analyze(source: string, file: string, options: LintOptions): Analysis {
  if (isSdkFile(file)) {
    if (isTestFile(file) || isBuildOutput(source)) return { raw: [] };
    const raw = [...lintSdkSource(source), ...bidiCharacters(source)];
    return { raw: SCRIPT_FILE.test(file.split("\\").join("/")) ? raw.filter((f) => f.ruleId !== "MS113") : raw };
  }
  if (isStdlibCopy(source)) return { raw: [] };
  const program = parse(source);
  // one engine pass decides how each witness is used; the analyzer's rules read it instead of guessing from names
  const analyzer = new Analyzer(program, options.resolver, options.absolutePath, witnessRoles(program));
  const raw = analyzer.run();
  raw.push(...checkAuthWrites(program), ...checkStructural(program), ...checkContract(program), ...bidiCharacters(source));
  // one finding per helper: the same `assertOnlyOwner()` called from twelve circuits is one bug, not twelve
  const byHelper = new Map<string, RawFinding>();
  for (let i = 0; i < raw.length; i++) {
    const f = raw[i];
    const helper = f.ruleId === "MS001" ? f.message.match(/is passed to '([^']+)'/)?.[1] : undefined;
    if (!helper) continue;
    const first = byHelper.get(helper);
    if (!first) {
      byHelper.set(helper, f);
      continue;
    }
    const extra = Number(first.message.match(/\(also called from (\d+) other places?\)/)?.[1] ?? 0) + 1;
    first.message = first.message.replace(/ \(also called from \d+ other places?\)/, "") + ` (also called from ${extra} other place${extra === 1 ? "" : "s"})`;
    raw.splice(i--, 1);
  }
  // an owner field anyone can overwrite is MS011's finding; MS034 would say the same thing
  const ownerWrites = new Set(raw.filter((f) => f.ruleId === "MS011").map((f) => `${f.loc.line}:${f.loc.col}`));
  for (let i = raw.length - 1; i >= 0; i--) if (raw[i].ruleId === "MS034" && ownerWrites.has(`${raw[i].loc.line}:${raw[i].loc.col}`)) raw.splice(i, 1);
  // MS035 (a field guarded in one circuit, open in another) at a write that MS011 or MS034 already reports says less
  const reportedWrites = new Set(raw.filter((f) => f.ruleId === "MS011" || f.ruleId === "MS034").map((f) => f.loc.line));
  const imports = { resolver: options.resolver, file: options.absolutePath };
  raw.push(...checkClaimedIdentity(program, raw, imports));
  // MS013 already reports an assert on a witness's Boolean
  const witnessAsserts = new Set(raw.filter((f) => f.ruleId === "MS013").map((f) => f.loc.line));
  raw.push(...checkSelfSatisfiable(program).filter((f) => !witnessAsserts.has(f.loc.line)));
  raw.push(...checkFreeNullifiers(program));
  raw.push(...checkInconsistentGuards(program, raw, imports).filter((f) => !reportedWrites.has(f.loc.line)));
  explainAccess(program, raw, imports);
  explainWithEngine(program, raw);
  for (const rule of options.plugins ?? []) raw.push(...runCustomRule(rule, file, source, program));
  return { program, analyzer, raw };
}

export function lintSource(source: string, file = "contract.compact", options: LintOptions = {}): Finding[] {
  const { raw } = analyze(source, file, options);
  return toFindings(raw, source, file, options);
}

export function toFindings(raw: RawFinding[], source: string, file: string, options: LintOptions): Finding[] {
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
    // the same rule saying the same thing twice on one line is one finding
    .filter((f, i, all) => all.findIndex((g) => g.ruleId === f.ruleId && g.loc.line === f.loc.line && g.message === f.message) === i)
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
      if (f.evidence) finding.evidence = f.evidence;
      if (f.ruleId === "MS006") finding.fix = pragmaFix(source);
      const suggestion = suggestFix(f.ruleId, f.message, snippet);
      if (suggestion) finding.suggestion = suggestion;
      const inline = suppression(suppressions, f.ruleId, f.loc.line);
      // with requireSuppressionReason, a comment without `-- reason` does not hide the finding
      if (inline && (inline.reason || !options.requireSuppressionReason)) {
        finding.suppressed = "inline";
        if (inline.reason) finding.suppressionReason = inline.reason;
      }
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
export interface AccessEntry extends CircuitAccess {
  file: string;
  /** rules reported inside this circuit's lines (the circuit itself, not its helpers) */
  findings: string[];
}

/** The access map of a Compact file: who can call each exported circuit, what it checks and what it changes. */
export function mapAccess(source: string, file = "contract.compact", options: LintOptions = {}): AccessEntry[] {
  if (isSdkFile(file)) return [];
  const { program, raw } = analyze(source, file, options);
  if (!program) return [];
  return accessMap(program, raw, { resolver: options.resolver, file: options.absolutePath }).map((c) => {
    const lines = new Set([...c.guards.map((g) => g.line), ...c.writes.map((w) => w.line), ...c.tokens.map((t) => t.line)]);
    return { ...c, file, findings: [...new Set(raw.filter((f) => lines.has(f.loc.line) && f.ruleId !== "MS000" && f.ruleId !== "MS033").map((f) => f.ruleId))].sort() };
  });
}

export interface ConstraintEntry extends CircuitConstraints {
  file: string;
}

/** The witness constraint report of a Compact file: what each prover-chosen value reaches, and what constrains it. */
export function mapConstraints(source: string, file = "contract.compact"): ConstraintEntry[] {
  if (isSdkFile(file)) return [];
  return constraintMap(parse(source)).map((c) => ({ ...c, file }));
}

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

