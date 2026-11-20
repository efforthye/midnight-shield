// Scanning a set of files held in memory, such as a repository fetched by the
// web playground. Browser-safe: no Node APIs and no network access here; the
// caller downloads the files and passes them in.

import type { ImportResolver } from "./analyzer.js";
import type { Program } from "./ast.js";
import { lintSource, type Finding, type LintOptions } from "./linter.js";
import { parse } from "./parser.js";
import { SEVERITY_ORDER } from "./rules.js";
import { isSdkFile } from "./sdk.js";

/** Directories that hold dependencies or generated code, never the project's own sources. */
export const IGNORED_DIRS = ["node_modules", ".git", "dist", "build", "managed", "coverage", ".cache"];

export interface RepoRef {
  owner: string;
  repo: string;
  /** branch, tag or commit; undefined means the default branch */
  ref?: string;
  /** only scan below this directory */
  path?: string;
}

/**
 * Read `owner/repo`, `github.com/owner/repo`, or a full GitHub URL, including
 * `/tree/<ref>/<path>` links. Returns undefined when the input is not a GitHub repository.
 */
export function parseRepoUrl(input: string): RepoRef | undefined {
  let s = input.trim().replace(/\.git$/, "").replace(/\/+$/, "");
  s = s.replace(/^(https?:\/\/)?(www\.)?github\.com\//i, "");
  const parts = s.split("/").filter(Boolean);
  if (parts.length < 2) return undefined;
  const [owner, repo, kind, ref, ...rest] = parts;
  const name = /^[A-Za-z0-9_.-]+$/;
  if (!name.test(owner) || !name.test(repo)) return undefined;
  if (kind === undefined) return { owner, repo };
  if ((kind === "tree" || kind === "blob") && ref) return { owner, repo, ref, path: rest.length ? rest.join("/") : undefined };
  return undefined;
}

/** Whether a repository path should be scanned: .compact files and, with `sdk`, DApp TypeScript/JavaScript. */
export function isScannableFile(path: string, sdk = true): boolean {
  const segments = path.split("/");
  if (segments.slice(0, -1).some((d) => IGNORED_DIRS.includes(d) || d.startsWith("."))) return false;
  if (path.endsWith(".compact")) return true;
  return sdk && isSdkFile(path) && !path.endsWith(".min.js");
}

/** Normalize a POSIX path, resolving `.` and `..` segments. */
function normalize(path: string): string {
  const out: string[] = [];
  for (const seg of path.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
  }
  return out.join("/");
}

/** Resolve `import "path"` between files held in memory, the way the CLI does on disk. */
export function memoryImportResolver(files: Map<string, string>): ImportResolver {
  const cache = new Map<string, Program>();
  return (fromFile, target) => {
    const base = fromFile && fromFile.includes("/") ? fromFile.slice(0, fromFile.lastIndexOf("/")) : "";
    for (const candidate of [`${target}.compact`, target]) {
      const key = normalize(base ? `${base}/${candidate}` : candidate);
      const source = files.get(key);
      if (source === undefined) continue;
      if (!cache.has(key)) cache.set(key, parse(source));
      return { file: key, program: cache.get(key)! };
    }
    return undefined;
  };
}

/** Lint every file in the map, resolving imports between them. Findings are sorted by severity, then file and line. */
export function lintFileMap(files: Map<string, string>, options: LintOptions = {}): Finding[] {
  const resolver = memoryImportResolver(files);
  const out: Finding[] = [];
  for (const [path, source] of files) out.push(...lintSource(source, path, { ...options, resolver, absolutePath: path }));
  return out.sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );
}
