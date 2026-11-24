// File-system helpers (Node.js only). The analysis itself lives in linter.ts
// and has no Node dependencies, so it also runs in the browser playground.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import type { ImportResolver } from "./analyzer.js";
import type { Program } from "./ast.js";
import { lintSource, mapDisclosures, toFindings, type BaselineFile, type DisclosureEntry, type Finding, type LintOptions } from "./linter.js";
import { parse } from "./parser.js";
import { isSdkFile, isTestFile } from "./sdk.js";
import { linkWitnesses } from "./witness-link.js";

const IGNORED_DIRS = new Set(["node_modules", ".git", "dist", "build", "managed", "coverage", ".cache"]);

/** Find .compact files (and, with `sdk`, TypeScript/JavaScript files) under the given paths. */
export function findCompactFiles(paths: string[], sdk = false): string[] {
  const out: string[] = [];
  const wanted = (p: string) => p.endsWith(".compact") || (sdk && isSdkFile(p) && !p.endsWith(".min.js"));
  const walk = (p: string, explicit: boolean) => {
    const st = statSync(p);
    if (st.isDirectory()) {
      for (const name of readdirSync(p).sort()) {
        if (IGNORED_DIRS.has(name) || name.startsWith(".")) continue;
        walk(join(p, name), false);
      }
    } else if (wanted(p) || (explicit && (p.endsWith(".compact") || isSdkFile(p)))) {
      out.push(p);
    }
  };
  for (const p of paths) walk(p, true);
  return out;
}

/** Resolve imports from disk, relative to the importing file. Parsed files are cached. */
export function fileImportResolver(): ImportResolver {
  const cache = new Map<string, Program | null>();
  return (fromFile, target) => {
    const base = fromFile ? dirname(fromFile) : process.cwd();
    for (const candidate of [`${target}.compact`, target]) {
      const abs = resolve(base, candidate);
      if (!cache.has(abs)) {
        cache.set(abs, existsSync(abs) && statSync(abs).isFile() ? parse(readFileSync(abs, "utf8")) : null);
      }
      const program = cache.get(abs);
      if (program) return { file: abs, program };
    }
    return undefined;
  };
}

/** Convert a glob (`*`, `**`, `?`) to a RegExp matched against forward-slash paths. */
export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += ".*";
        i++;
        if (glob[i + 1] === "/") i++;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

/** The .compact files that will be scanned: found under `paths`, minus `ignore` globs. */
export function listTargetFiles(paths: string[], ignore: string[] = [], cwd = process.cwd(), sdk = true): string[] {
  const res = ignore.map(globToRegExp);
  return findCompactFiles(paths, sdk).filter((file) => {
    const rel = relative(cwd, file).split("\\").join("/");
    return !res.some((re) => re.test(rel));
  });
}

function eachFile<T>(paths: string[], options: LintOptions, cwd: string, fn: (source: string, rel: string, opts: LintOptions) => T[]): T[] {
  const out: T[] = [];
  const resolver = options.resolver ?? fileImportResolver();
  for (const file of listTargetFiles(paths, options.ignore, cwd, options.sdk ?? true)) {
    const rel = relative(cwd, file).split("\\").join("/");
    const source = readFileSync(file, "utf8");
    out.push(...fn(source, rel, { ...options, resolver, absolutePath: resolve(file) }));
  }
  return out;
}

export function lintFiles(paths: string[], options: LintOptions = {}, cwd = process.cwd()): Finding[] {
  const sources = new Map<string, string>();
  const findings = eachFile(paths, options, cwd, (src, rel, opts) => {
    sources.set(rel, src);
    return lintSource(src, rel, opts);
  });
  // MS121 needs the contract and the DApp together
  if (options.sdk ?? true) {
    const contracts = [...sources].filter(([f]) => f.endsWith(".compact")).map(([file, src]) => ({ file, program: parse(src) }));
    const dapps = [...sources].filter(([f]) => isSdkFile(f) && !isTestFile(f)).map(([file, source]) => ({ file, source }));
    const seen = new Set(findings.filter((f) => f.ruleId === "MS113").map((f) => `${f.file}:${f.line}`));
    for (const l of linkWitnesses(contracts, dapps)) {
      if (seen.has(`${l.file}:${l.raw.loc.line}`)) continue; // MS113 already says it by name
      findings.push(...toFindings([l.raw], sources.get(l.file) ?? "", l.file, options));
    }
  }
  return findings;
}

export function mapDisclosuresInFiles(paths: string[], options: LintOptions = {}, cwd = process.cwd()): DisclosureEntry[] {
  return eachFile(paths, options, cwd, (src, rel, opts) => mapDisclosures(src, rel, opts));
}

export function readBaseline(path: string): Set<string> {
  const data = JSON.parse(readFileSync(path, "utf8")) as Partial<BaselineFile>;
  if (data.tool !== "midnight-shield" || !Array.isArray(data.findings)) throw new Error(`${path} is not a Midnight Shield baseline`);
  return new Set(data.findings.map((f) => f.fingerprint));
}
