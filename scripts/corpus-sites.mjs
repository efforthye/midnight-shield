// How much relevant code the rules actually looked at in the corpus. "No findings" on
// well-maintained code only means something if the rules met the patterns they check:
// this counts, per core rule, the places in the corpus where the rule had to decide.
//
//   node scripts/corpus-sites.mjs [corpus dir]   (default .cache/corpus, filled by npm run verify)

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { lintSource } from "../dist/src/linter.js";
import { parse } from "../dist/src/parser.js";

const root = process.argv[2] ?? ".cache/corpus";
const files = [];
const walk = (d) => {
  for (const n of readdirSync(d)) {
    if (n === "node_modules" || n.startsWith(".")) continue;
    const p = join(d, n);
    if (statSync(p).isDirectory()) walk(p);
    else if (n.endsWith(".compact")) files.push(p);
  }
};
walk(root);

const sites = {
  "MS001 ownPublicKey() used": 0,
  "MS002 witness calls": 0,
  "MS004/MS014 commitments": 0,
  "MS007 secret-typed witnesses": 0,
  "MS008/MS009 Merkle root checks": 0,
  "MS009 leaves bound to the caller": 0,
  "MS011/MS034 exported circuits that write state": 0,
  "MS013 Boolean witnesses": 0,
  "MS018 nullifier-style set checks": 0,
  "MS019/MS020 token sends and mints": 0,
};
const flagged = {};

function* exprs(e) {
  if (!e || typeof e !== "object") return;
  if (Array.isArray(e)) {
    for (const x of e) yield* exprs(x);
    return;
  }
  if (e.kind) yield e;
  for (const [k, v] of Object.entries(e)) if (k !== "loc" && typeof v === "object") yield* exprs(v);
}

for (const f of files) {
  const src = readFileSync(f, "utf8");
  const program = parse(src);
  const witnesses = new Map();
  for (const d of exprs(program.decls)) if (d.kind === "witness") witnesses.set(d.name, d.returnType?.name);
  for (const d of exprs(program.decls)) {
    if (d.kind === "witness" && d.returnType?.name === "Boolean") sites["MS013 Boolean witnesses"]++;
    if (d.kind === "witness" && d.returnType?.name === "Bytes") sites["MS007 secret-typed witnesses"]++;
    if (d.kind === "circuit" && d.exported && d.body) {
      const writes = [...exprs(d.body)].some((x) => x.kind === "assign" || (x.kind === "call" && x.callee?.kind === "member" && ["insert", "write", "increment", "decrement", "remove", "resetToDefault"].includes(x.callee.property)));
      if (writes) sites["MS011/MS034 exported circuits that write state"]++;
    }
    if (d.kind !== "call") continue;
    const name = d.callee?.kind === "ident" ? d.callee.name : d.callee?.kind === "member" ? d.callee.property : "";
    if (name === "ownPublicKey") sites["MS001 ownPublicKey() used"]++;
    if (d.callee?.kind === "ident" && witnesses.has(name)) sites["MS002 witness calls"]++;
    if (name === "persistentCommit" || name === "transientCommit") sites["MS004/MS014 commitments"]++;
    if (name === "checkRoot") sites["MS008/MS009 Merkle root checks"]++;
    if (/^(send|sendImmediate|sendShielded|sendImmediateShielded|sendUnshielded|mintToken|mintShieldedToken|mintUnshieldedToken)$/.test(name)) sites["MS019/MS020 token sends and mints"]++;
  }
  for (const d of exprs(program.decls)) {
    if (d.kind === "binary" && (d.op === "==" || d.op === "!=") && [d.left, d.right].some((x) => x?.kind === "member" && x.property === "leaf")) sites["MS009 leaves bound to the caller"]++;
    if (d.kind === "unary" && d.op === "!" && [...exprs(d.arg)].some((x) => x.kind === "call" && x.callee?.property === "member")) sites["MS018 nullifier-style set checks"]++;
  }
  for (const x of lintSource(src, f)) if (!["info", "low"].includes(x.severity)) flagged[x.ruleId] = (flagged[x.ruleId] ?? 0) + 1;
}

console.log(`${files.length} Compact files under ${root}\n`);
console.log("| Pattern the rule decides on | Places in the corpus |\n| --- | ---: |");
for (const [k, v] of Object.entries(sites)) console.log(`| ${k} | ${v} |`);
console.log(`\nMedium-or-worse findings on these files: ${JSON.stringify(flagged)}`);
