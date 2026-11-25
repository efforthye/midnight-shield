// Checks the verdict commitments of the field test and the blind test
// (verify/field-verdicts.json, verify/blind-verdicts.json).
// A withheld finding is published as sha256(canonical JSON of the row + "|" + salt).
// Once a project has been told, the row and its salt go under "revealed"; this script
// recomputes each hash and confirms it matches a commitment made before the reveal.
//
//   node scripts/check-verdict.mjs
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const canonical = (v) => (Array.isArray(v) ? `[${v.map(canonical).join(",")}]` : v && typeof v === "object" ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}` : JSON.stringify(v));
let failed = 0;
for (const name of ["field-verdicts.json", "blind-verdicts.json", "blind2-verdicts.json"]) {
  const data = JSON.parse(readFileSync(new URL(`../verify/${name}`, import.meta.url), "utf8"));
  const commitments = new Set(data.withheld.map((w) => w.commitment));
  let ok = 0;
  for (const r of data.revealed ?? []) {
    const h = createHash("sha256").update(`${canonical(r.row)}|${r.salt}`).digest("hex");
    if (commitments.has(h)) ok++;
    else {
      failed++;
      console.log(`${name}: does not match any commitment: ${r.row.repo} ${r.row.file}:${r.row.line} ${r.row.rule}`);
    }
  }
  // The project lists (this sample and the next one) are committed the same way: { row: [...repos], salt }.
  for (const key of ["projects", "nextSample"]) {
    const r = data[`${key}Revealed`];
    if (!r || !data[`${key}Commitment`]) continue;
    const h = createHash("sha256").update(`${JSON.stringify(r.row)}|${r.salt}`).digest("hex");
    if (h === data[`${key}Commitment`]) console.log(`${name}: ${key} list revealed and matching.`);
    else {
      failed++;
      console.log(`${name}: the revealed ${key} list does not match its commitment.`);
    }
  }
  console.log(`${name}: ${data.public.length} published, ${data.withheld.length} withheld, ${ok} revealed and matching.`);
}
process.exitCode = failed ? 1 : 0;
