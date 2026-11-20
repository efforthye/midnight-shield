// Custom rule API. A plugin is an ES module whose default export (or `rules`
// export) is an array of rules:
//
//   export default [{
//     id: "ACME001", name: "no-debug-ledger", severity: "low", summary: "...",
//     check(ctx) {
//       ctx.visit({ call(expr, callee, where) {
//         if (callee === "debugLog") ctx.report({ loc: expr.loc, message: "..." });
//       }});
//     },
//   }];

import type { Loc, Program } from "./ast.js";
import { CONFIDENCE_ORDER, SEVERITY_ORDER, type Confidence, type RuleMeta, type Severity } from "./rules.js";
import { walkProgram, type Visitor } from "./walk.js";

export interface PluginReport {
  /** where the problem is; or give `line` (and optionally `col`) */
  loc?: Loc;
  line?: number;
  col?: number;
  message: string;
  severity?: Severity;
  confidence?: Confidence;
}

export interface RuleContext {
  /** path of the file being checked, as shown in reports */
  file: string;
  source: string;
  program: Program;
  report(r: PluginReport): void;
  /** walk every circuit, statement and expression in the file */
  visit(visitor: Visitor): void;
}

export interface CustomRule extends RuleMeta {
  check(ctx: RuleContext): void;
}

export class PluginError extends Error {}

const ID_PATTERN = /^[A-Z][A-Z0-9]*\d{3}$/;

export function validateRule(raw: unknown, source: string): CustomRule {
  const r = raw as Partial<CustomRule>;
  const where = `${source}: rule ${r?.id ?? "(no id)"}`;
  if (!r || typeof r !== "object") throw new PluginError(`${source}: each rule must be an object`);
  if (typeof r.id !== "string" || !ID_PATTERN.test(r.id)) throw new PluginError(`${where}: "id" must look like ACME001 (capital letters, then 3 digits)`);
  if (r.id.startsWith("MS")) throw new PluginError(`${where}: the "MS" prefix is reserved for built-in rules`);
  if (typeof r.name !== "string" || !r.name) throw new PluginError(`${where}: "name" is required`);
  if (!SEVERITY_ORDER.includes(r.severity as Severity)) throw new PluginError(`${where}: "severity" must be one of ${SEVERITY_ORDER.join(", ")}`);
  if (r.confidence !== undefined && !CONFIDENCE_ORDER.includes(r.confidence)) throw new PluginError(`${where}: "confidence" must be one of ${CONFIDENCE_ORDER.join(", ")}`);
  if (typeof r.summary !== "string" || !r.summary) throw new PluginError(`${where}: "summary" is required`);
  if (typeof r.check !== "function") throw new PluginError(`${where}: "check(ctx)" must be a function`);
  return { ...r, confidence: r.confidence ?? "medium" } as CustomRule;
}

export function runCustomRule(rule: CustomRule, file: string, source: string, program: Program) {
  const out: { ruleId: string; severity: Severity; confidence: Confidence; message: string; loc: Loc }[] = [];
  const ctx: RuleContext = {
    file,
    source,
    program,
    report(r) {
      const loc = r.loc ?? { line: r.line ?? 1, col: r.col ?? 1 };
      out.push({ ruleId: rule.id, severity: r.severity ?? rule.severity, confidence: r.confidence ?? rule.confidence, message: r.message, loc });
    },
    visit(visitor) {
      walkProgram(program, visitor);
    },
  };
  try {
    rule.check(ctx);
  } catch (e) {
    throw new PluginError(`rule ${rule.id} crashed on ${file}: ${(e as Error).message}`);
  }
  return out;
}
