// Upgrade check: compare two versions of a contract and report the changes
// that break the deployed contract's state or the DApps that call it. This is
// the Compact counterpart of slither-check-upgradeability.
//
// Why order matters: the compiled contract reads and writes ledger fields by
// their position in declaration order (field 0, field 1, ...), not by name.
// A deployed contract keeps its state; the contract maintenance authority can
// only swap circuit verifier keys. New circuits compiled from source where a
// field moved, changed type or disappeared read the old state in the wrong
// place. Enum values are stored as their index, so reordering enum members
// changes the meaning of stored values too.

import { accessMap, type CircuitAccess, type Who } from "./access.js";
import { Analyzer, type ImportResolver } from "./analyzer.js";
import type { Decl, Program, TypeRef } from "./ast.js";
import { parse } from "./parser.js";
import type { Severity } from "./rules.js";

export type UpgradeKind =
  | "field-removed"
  | "field-moved"
  | "field-type-changed"
  | "field-renamed"
  | "field-added"
  | "field-sealed-changed"
  | "type-changed" // a struct or enum stored in the ledger changed shape
  | "circuit-removed"
  | "circuit-added"
  | "circuit-signature-changed"
  | "witness-changed"
  | "access-weakened"
  | "pragma-changed";

export interface UpgradeChange {
  kind: UpgradeKind;
  severity: Severity;
  /** the field, circuit, witness or type the change is about */
  subject: string;
  message: string;
  oldLine?: number;
  newLine?: number;
}

interface Field {
  name: string;
  type: string;
  sealed: boolean;
  line: number;
}

interface Shape {
  fields: Field[];
  circuits: Map<string, { signature: string; line: number }>;
  witnesses: Map<string, { signature: string; line: number }>;
  /** structs and enums by name: enum members, or struct fields with types */
  types: Map<string, { text: string; members: string[]; enumType: boolean; line: number }>;
  pragma?: string;
  access: Map<string, CircuitAccess>;
}

const norm = (t?: TypeRef) => (t ? t.text.replace(/\s+/g, "") : "[]");

/** Ledger fields in declaration order, following imports where they appear (their fields take positions too). */
function collectShape(program: Program, file: string | undefined, resolver: ImportResolver | undefined): Shape {
  const shape: Shape = { fields: [], circuits: new Map(), witnesses: new Map(), types: new Map(), access: new Map() };
  const seen = new Set<string>();
  const walk = (decls: Decl[], prefix: string, from: string | undefined, depth: number, top: boolean) => {
    for (const d of decls) {
      switch (d.kind) {
        case "pragma":
          if (top && /language_version/.test(d.text)) shape.pragma = d.text.replace(/\s+/g, "").replace(/^language_version/, "");
          break;
        case "ledger":
          shape.fields.push({ name: prefix + d.name, type: norm(d.type), sealed: d.sealed, line: top ? d.loc.line : 0 });
          break;
        case "circuit":
          if (top && d.exported) shape.circuits.set(d.name, { signature: `(${d.params.map((p) => norm(p.type)).join(", ")}): ${norm(d.returnType)}`, line: d.loc.line });
          break;
        case "witness":
          if (top) shape.witnesses.set(d.name, { signature: `(${d.params.map((p) => norm(p.type)).join(", ")}): ${norm(d.returnType)}`, line: d.loc.line });
          break;
        case "struct":
          if (top) shape.types.set(d.name, { text: d.fields.map((f) => `${f.name}: ${norm(f.type)}`).join(", "), members: d.fields.map((f) => `${f.name}: ${norm(f.type)}`), enumType: false, line: d.loc.line });
          break;
        case "enum":
          if (top) shape.types.set(d.name, { text: d.members.join(", "), members: d.members, enumType: true, line: d.loc.line });
          break;
        case "module":
          walk(d.decls, prefix, from, depth, top);
          break;
        case "import": {
          if (!d.isPath || !resolver || depth > 4) break;
          const r = resolver(from, d.target);
          if (!r || seen.has(r.file + "|" + prefix + d.prefix)) break;
          seen.add(r.file + "|" + prefix + d.prefix);
          walk(r.program.decls, prefix + d.prefix, r.file, depth + 1, false);
          break;
        }
      }
    }
  };
  walk(program.decls, "", file, 0, true);
  const raw = new Analyzer(program, resolver, file).run();
  for (const c of accessMap(program, raw, { resolver, file })) if (!c.module) shape.access.set(c.name, c);
  return shape;
}

const RANK: Record<Who, number> = { restricted: 3, imported: 2, bypassable: 1, anyone: 0 };
const WHO_TEXT: Record<Who, string> = { restricted: "checks the caller", imported: "calls an imported check", bypassable: "has only checks anyone can pass", anyone: "is open to anyone" };

/** Type names a ledger type mentions, so a change to a stored struct or enum is noticed. */
const typeNames = (t: string) => new Set(t.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []);

export function compareShapes(oldS: Shape, newS: Shape): UpgradeChange[] {
  const out: UpgradeChange[] = [];
  const add = (c: UpgradeChange) => out.push(c);

  // ledger layout. Fields are matched by name; a field that left one position and a new
  // one of the same type at the same position is a rename.
  const oldIdx = new Map(oldS.fields.map((f, i) => [f.name, i]));
  const newIdx = new Map(newS.fields.map((f, i) => [f.name, i]));
  const removed = oldS.fields.map((f, i) => ({ f, i })).filter((x) => !newIdx.has(x.f.name));
  const added = newS.fields.map((f, i) => ({ f, i })).filter((x) => !oldIdx.has(x.f.name));
  const renamedOld = new Set<string>();
  const renamedNew = new Set<string>();
  for (const r of removed) {
    const a = added.find((x) => x.i === r.i && x.f.type === r.f.type && !renamedNew.has(x.f.name));
    if (!a) continue;
    renamedOld.add(r.f.name);
    renamedNew.add(a.f.name);
    add({ kind: "field-renamed", severity: "low", subject: a.f.name, oldLine: r.f.line || undefined, newLine: a.f.line || undefined, message: `Ledger field '${r.f.name}' was renamed to '${a.f.name}' (same position and type). The state is unaffected, but DApps that read ledger().${r.f.name} need the new name.` });
  }
  const shiftedAfter = (pos: number, list: Field[]) => list.slice(pos + 1).map((x) => x.name);
  const shiftText = (names: string[]) => (names.length ? ` Every field after it moves one position (${names.slice(0, 5).join(", ")}${names.length > 5 ? `, and ${names.length - 5} more` : ""}), so each of them reads its neighbour's old value.` : "");
  for (const r of removed) {
    if (renamedOld.has(r.f.name)) continue;
    add({ kind: "field-removed", severity: "critical", subject: r.f.name, oldLine: r.f.line || undefined, message: `Ledger field '${r.f.name}' (position ${r.i}) is gone. The deployed state still holds it.${shiftText(shiftedAfter(r.i, oldS.fields).filter((n) => newIdx.has(n)))} Keep the field, even if unused, so every position stays the same.` });
  }
  for (const a of added) {
    if (renamedNew.has(a.f.name)) continue;
    const atEnd = a.i >= oldS.fields.length;
    add({
      kind: atEnd ? "field-added" : "field-moved",
      severity: atEnd ? "high" : "critical",
      subject: a.f.name,
      newLine: a.f.line || undefined,
      message: atEnd
        ? `New ledger field '${a.f.name}' at position ${a.i}${a.f.line ? "" : " (from an imported module)"}. The deployed state has nothing at this position, so circuits that use it fail on the existing contract. Swapping verifier keys cannot add state: this needs a new deployment, with the old state migrated.`
        : `New ledger field '${a.f.name}' is inserted at position ${a.i}${a.f.line ? "" : " (from an imported module)"}, where the deployed state holds '${oldS.fields[a.i].name}'.${shiftText(shiftedAfter(a.i, newS.fields).filter((n) => oldIdx.has(n)))} Add new fields at the end.`,
    });
  }
  // fields kept by name: moved out of order, or changed type
  const removedBefore = (i: number) => removed.filter((r) => r.i < i && !renamedOld.has(r.f.name)).length;
  const addedBefore = (i: number) => added.filter((a) => a.i < i && !renamedNew.has(a.f.name)).length;
  for (const [i, o] of oldS.fields.entries()) {
    const j = newIdx.get(o.name);
    if (j === undefined) continue;
    const f = newS.fields[j];
    const expected = i - removedBefore(i) + addedBefore(j);
    if (j !== expected) add({ kind: "field-moved", severity: "critical", subject: o.name, oldLine: o.line || undefined, newLine: f.line || undefined, message: `Ledger field '${o.name}' moved from position ${i} to ${j}. Fields are stored by position, not by name, so it now reads whatever the deployed state holds at position ${j}. Keep the original order.` });
    if (o.type !== f.type) add({ kind: "field-type-changed", severity: "critical", subject: o.name, oldLine: o.line || undefined, newLine: f.line || undefined, message: `Ledger field '${o.name}' changed type from ${o.type} to ${f.type}. The deployed state holds a ${o.type} there; new circuits will read it as ${f.type}.` });
    if (o.sealed !== f.sealed) add({ kind: "field-sealed-changed", severity: "medium", subject: o.name, newLine: f.line || undefined, message: `Ledger field '${o.name}' is ${f.sealed ? "now sealed: circuits can no longer change it" : "no longer sealed: circuits can now change a value that was fixed at deployment, which DApps and users may rely on"}.` });
  }

  // structs and enums that ledger fields store
  const stored = new Set<string>();
  for (const f of oldS.fields) for (const t of typeNames(f.type)) stored.add(t);
  for (const [name, o] of oldS.types) {
    const t = newS.types.get(name);
    if (!t || !stored.has(name) || t.text === o.text) continue;
    const appended = o.members.every((m, i) => t.members[i] === m);
    if (o.enumType) {
      add({
        kind: "type-changed",
        severity: appended ? "low" : "critical",
        subject: name,
        newLine: t.line,
        message: appended
          ? `Enum '${name}' gained members at the end (${t.members.slice(o.members.length).join(", ")}). Stored values keep their meaning.`
          : `Enum '${name}' changed from [${o.text}] to [${t.text}]. The ledger stores enum values by index, so stored values now mean a different member. Only add members at the end.`,
      });
    } else {
      add({ kind: "type-changed", severity: "critical", subject: name, newLine: t.line, message: `Struct '${name}', stored in the ledger, changed from {${o.text}} to {${t.text}}. Values already stored keep the old layout.` });
    }
  }

  // exported circuits: what DApps call, and what verifier keys exist for
  for (const [name, o] of oldS.circuits) {
    const c = newS.circuits.get(name);
    if (!c) {
      add({ kind: "circuit-removed", severity: "medium", subject: name, oldLine: o.line, message: `Exported circuit '${name}' was removed from the source, but on the deployed contract it stays callable until the maintenance authority removes its verifier key. If it was removed because it is unsafe, remove the key too. DApps that call it need updating.` });
    } else if (c.signature !== o.signature) {
      add({ kind: "circuit-signature-changed", severity: "medium", subject: name, oldLine: o.line, newLine: c.line, message: `Exported circuit '${name}' changed from ${o.signature} to ${c.signature}. Its verifier key must be replaced, and every DApp that calls it must be updated at the same time.` });
    }
  }
  for (const [name, c] of newS.circuits) {
    if (!oldS.circuits.has(name)) add({ kind: "circuit-added", severity: "info", subject: name, newLine: c.line, message: `New exported circuit '${name}'. On the deployed contract it needs its verifier key inserted by the maintenance authority.` });
  }

  // witnesses: the DApp implements them
  for (const [name, o] of oldS.witnesses) {
    const w = newS.witnesses.get(name);
    if (w && w.signature !== o.signature) add({ kind: "witness-changed", severity: "medium", subject: name, oldLine: o.line, newLine: w.line, message: `Witness '${name}' changed from ${o.signature} to ${w.signature}. The DApp's implementation must change with it, or proofs will be built from the wrong values.` });
  }
  for (const [name, w] of newS.witnesses) {
    if (!oldS.witnesses.has(name)) add({ kind: "witness-changed", severity: "low", subject: name, newLine: w.line, message: `New witness '${name}'. Every DApp must implement it before the new circuits can be used.` });
  }

  // a circuit that checked the caller and now checks less
  for (const [name, o] of oldS.access) {
    const c = newS.access.get(name);
    if (!c || RANK[c.who] >= RANK[o.who]) continue;
    const acts = c.writes.length > 0 || c.tokens.some((t) => !t.op.startsWith("receive"));
    add({
      kind: "access-weakened",
      severity: acts ? "high" : "medium",
      subject: name,
      newLine: c.line,
      message: `'${name}' ${WHO_TEXT[o.who]} in the old version but ${WHO_TEXT[c.who]} in the new one${acts ? `, and it ${[c.writes.length ? `changes ${[...new Set(c.writes.map((w) => w.field))].join(", ")}` : "", c.tokens.length ? `moves tokens (${[...new Set(c.tokens.map((t) => t.op))].join(", ")})` : ""].filter(Boolean).join(" and ")}` : ""}. Check that the guard was removed on purpose.`,
    });
  }

  if (oldS.pragma && newS.pragma && oldS.pragma !== newS.pragma) {
    add({ kind: "pragma-changed", severity: "info", subject: "pragma", message: `The language version changed (${oldS.pragma} → ${newS.pragma}). Recompile every circuit with one compiler version; values stored with transientHash or transientCommit may not be reproducible across versions (MS012).` });
  }

  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return out.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
}

export function compareContracts(oldSource: string, newSource: string, options: { oldFile?: string; newFile?: string; resolver?: ImportResolver } = {}): UpgradeChange[] {
  const o = collectShape(parse(oldSource), options.oldFile, options.resolver);
  const n = collectShape(parse(newSource), options.newFile, options.resolver);
  return compareShapes(o, n);
}

export interface FileUpgrade {
  file: string;
  changes: UpgradeChange[];
}

const ICON: Record<Severity, string> = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" };

export function formatUpgradeText(files: FileUpgrade[], options: { color?: boolean } = {}): string {
  const color = options.color ?? true;
  const paint: Record<Severity, string> = { critical: "\x1b[35m", high: "\x1b[31m", medium: "\x1b[33m", low: "\x1b[36m", info: "\x1b[2m" };
  const c = (code: string, s: string) => (color ? code + s + "\x1b[0m" : s);
  const lines: string[] = [];
  let total = 0;
  for (const f of files) {
    if (!f.changes.length) continue;
    lines.push(c("\x1b[1m\x1b[4m", f.file));
    for (const ch of f.changes) {
      total++;
      const at = ch.newLine ? `new line ${ch.newLine}` : ch.oldLine ? `old line ${ch.oldLine}` : "";
      lines.push(`  ${c(paint[ch.severity], ICON[ch.severity].padEnd(9))} ${ch.kind}  ${ch.subject}${at ? c("\x1b[2m", `  (${at})`) : ""}`);
      lines.push(`  ${ch.message}`);
      lines.push("");
    }
  }
  if (!total) return "No changes that affect the deployed state, the DApp interface or who can call what.";
  const by = (s: Severity) => files.flatMap((f) => f.changes).filter((x) => x.severity === s).length;
  lines.push(`${total} change${total === 1 ? "" : "s"}: ${(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => `${by(s)} ${s}`).join(", ")}.`);
  return lines.join("\n");
}

export function formatUpgradeMarkdown(files: FileUpgrade[]): string {
  const out = ["# Upgrade check", "", "Changes between the two versions that affect the deployed ledger state, the DApp interface, or who can call what.", ""];
  const rows = files.flatMap((f) => f.changes.map((ch) => ({ f, ch })));
  if (!rows.length) return [...out, "No changes found."].join("\n");
  out.push("| Severity | File | Change | Subject | Details |", "| --- | --- | --- | --- | --- |");
  for (const { f, ch } of rows) out.push(`| ${ch.severity} | \`${f.file}\` | ${ch.kind} | \`${ch.subject}\` | ${ch.message.replace(/\|/g, "\\|")} |`);
  return out.join("\n");
}
