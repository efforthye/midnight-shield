// Safe automatic fixes. Only fixes that cannot change what a contract does, or
// the values it stores, are offered. Fixes that change hashes or commitments
// (for example adding a domain tag) would change on-chain values and break
// existing deployments, so they are left to the developer (or the AI skill).

export interface TextEdit {
  /** 1-based line to insert before */
  line: number;
  insert: string;
}

export const DEFAULT_PRAGMA = "pragma language_version >= 0.28.0;";

/** MS006: insert a pragma after any leading comments and blank lines. */
export function pragmaFix(source: string, pragma = DEFAULT_PRAGMA): TextEdit {
  const lines = source.split(/\r?\n/);
  let i = 0;
  let inBlock = false;
  for (; i < lines.length; i++) {
    const t = lines[i].trim();
    if (inBlock) {
      if (t.includes("*/")) inBlock = false;
      continue;
    }
    if (t === "" || t.startsWith("//")) continue;
    if (t.startsWith("/*")) {
      if (!t.includes("*/")) inBlock = true;
      continue;
    }
    break;
  }
  // put it right after the leading comment block (skip trailing blank lines back)
  let at = i;
  while (at > 0 && lines[at - 1].trim() === "") at--;
  const eol = source.includes("\r\n") ? "\r\n" : "\n";
  return { line: at + 1, insert: pragma + eol };
}

/** Apply edits to a source string. Edits are applied bottom-up so line numbers stay valid. */
export function applyEdits(source: string, edits: TextEdit[]): string {
  const eol = source.includes("\r\n") ? "\r\n" : "\n";
  const lines = source.split(/\r?\n/);
  const sorted = [...edits].sort((a, b) => b.line - a.line);
  for (const e of sorted) {
    const idx = Math.max(0, Math.min(lines.length, e.line - 1));
    const text = e.insert.endsWith(eol) ? e.insert.slice(0, -eol.length) : e.insert;
    lines.splice(idx, 0, ...text.split(/\r?\n/));
  }
  return lines.join(eol);
}
