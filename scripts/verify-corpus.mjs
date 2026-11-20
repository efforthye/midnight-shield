// Corpus verification: scan real, published Compact code at pinned commits and
// compare the results with a reviewed baseline.
//
//   npm run verify             check against verify/baseline.json
//   npm run verify -- --update rewrite the baseline after reviewing changes
//
// It fails when:
//   - any file cannot be parsed (MS000),
//   - any finding is medium or worse (this code is maintained by the Midnight
//     and OpenZeppelin teams, so such a finding is almost surely a false positive),
//     unless it is listed in verify/reviewed.json: a finding a person checked
//     by hand and confirmed is real, with the reason,
//   - the per-rule finding counts differ from the baseline.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { lintFiles, listTargetFiles } from "../dist/src/index.js";

const CORPORA = [
  {
    name: "midnight-examples",
    repo: "https://github.com/midnightntwrk/midnight-examples.git",
    commit: "df56a534caa58b50f8fb738312be84abfe7108de",
  },
  {
    name: "compact-contracts",
    repo: "https://github.com/OpenZeppelin/compact-contracts.git",
    commit: "f85f1a23685c6bbedfc8c2589ae3aa128aff7c46",
  },
];

const BLOCKING = new Set(["critical", "high", "medium"]);
const root = resolve(process.env.CORPUS_DIR ?? ".cache/corpus");
const baselinePath = resolve("verify/baseline.json");
const reviewedPath = resolve("verify/reviewed.json");
const reviewed = existsSync(reviewedPath) ? JSON.parse(readFileSync(reviewedPath, "utf8")) : [];
const isReviewed = (corpus, f) => reviewed.some((r) => r.corpus === corpus && r.rule === f.ruleId && r.file === f.file);
const update = process.argv.includes("--update");

function git(args, cwd) {
  execFileSync("git", args, { cwd, stdio: ["ignore", "ignore", "inherit"] });
}

function checkout({ name, repo, commit }) {
  const dir = join(root, name);
  if (existsSync(join(dir, ".git"))) {
    const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();
    if (head === commit) return dir;
  }
  mkdirSync(dir, { recursive: true });
  if (!existsSync(join(dir, ".git"))) git(["init", "-q"], dir);
  git(["fetch", "-q", "--depth", "1", repo, commit], dir);
  git(["checkout", "-q", "--force", "FETCH_HEAD"], dir);
  return dir;
}

const result = {};
const problems = [];

for (const corpus of CORPORA) {
  process.stdout.write(`• ${corpus.name}@${corpus.commit.slice(0, 7)} ... `);
  const dir = checkout(corpus);
  const files = listTargetFiles([dir]);
  const findings = lintFiles([dir], {}, dir);
  const byRule = {};
  for (const f of findings) byRule[f.ruleId] = (byRule[f.ruleId] ?? 0) + 1;
  result[corpus.name] = { commit: corpus.commit, files: files.length, findings: Object.fromEntries(Object.entries(byRule).sort()) };
  console.log(`${files.length} files, ${findings.length} findings`);

  for (const f of findings) {
    if (f.ruleId === "MS000") problems.push(`${corpus.name}: parse error at ${f.file}:${f.line} (${f.message})`);
    else if (BLOCKING.has(f.severity) && !isReviewed(corpus.name, f)) problems.push(`${corpus.name}: ${f.severity} ${f.ruleId} at ${f.file}:${f.line}`);
  }
}

if (update) {
  mkdirSync("verify", { recursive: true });
  writeFileSync(baselinePath, JSON.stringify(result, null, 2) + "\n");
  console.log(`\nBaseline written to ${baselinePath}`);
} else {
  const baseline = existsSync(baselinePath) ? JSON.parse(readFileSync(baselinePath, "utf8")) : {};
  for (const [name, now] of Object.entries(result)) {
    const before = baseline[name];
    if (!before) {
      problems.push(`${name}: no baseline (run npm run verify -- --update)`);
      continue;
    }
    if (before.files !== now.files) problems.push(`${name}: file count ${before.files} -> ${now.files}`);
    const rules = new Set([...Object.keys(before.findings), ...Object.keys(now.findings)]);
    for (const r of [...rules].sort()) {
      const a = before.findings[r] ?? 0;
      const b = now.findings[r] ?? 0;
      if (a !== b) problems.push(`${name}: ${r} ${a} -> ${b}`);
    }
  }
}

console.log("");
console.table(
  Object.fromEntries(Object.entries(result).map(([name, r]) => [name, { files: r.files, ...r.findings }])),
);

if (update) process.exit(0);

if (problems.length) {
  console.error(`\n✖ Verification failed:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
console.log("✔ Verification passed: every file parses, no unreviewed medium-or-worse findings, results match the baseline.");
