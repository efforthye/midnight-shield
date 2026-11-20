import { lintSource, type Finding } from "../src/linter.js";

export const HEADER = "pragma language_version >= 0.28.0;\nimport CompactStandardLibrary;\n";

export function lint(source: string): Finding[] {
  return lintSource(HEADER + source);
}

export function count(source: string, ruleId: string): number {
  return lint(source).filter((f) => f.ruleId === ruleId).length;
}
