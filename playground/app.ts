import {
  lintSource,
  lintFileMap,
  mapDisclosures,
  memoryImportResolver,
  parseRepoUrl,
  isScannableFile,
  usesMidnightSdk,
  formatMarkdown,
  VERSION,
  type Finding,
  type DisclosureEntry,
  type RepoRef,
} from "../src/browser.js";
import { EXAMPLES } from "./examples.generated.js";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const code = $<HTMLTextAreaElement>("code");
const gutter = $("gutter");
const panel = $("panel");
const summary = $("summary");
const lang = $<HTMLSelectElement>("lang");
const minSeverity = $<HTMLSelectElement>("minSeverity");
const exampleSelect = $<HTMLSelectElement>("example");
const fileSelect = $<HTMLSelectElement>("fileSelect");
const fileLabel = $("fileLabel");
const repoUrl = $<HTMLInputElement>("repoUrl");
$("version").textContent = VERSION;

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR: Record<string, string> = { critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)", info: "var(--info)" };
const MAX_FILES = 400;
const MAX_FILE_BYTES = 512 * 1024;

/** A set of files being analyzed together: a GitHub repository or files opened from disk. */
interface Project {
  name: string;
  /** set for GitHub repositories, used for share links and source links */
  repo?: RepoRef & { ref: string };
  files: Map<string, string>;
  current: string;
  note?: string;
}

let project: Project | null = null;
let tab: "findings" | "disclosures" = "findings";
let allFindings: Finding[] = []; // every finding in scope, before the severity filter
let disclosures: DisclosureEntry[] = [];
let busy = false;

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
const langOf = (path: string) => (path.endsWith(".compact") ? "compact" : "ts");
const singleFileName = () => (lang.value === "ts" ? "contract.ts" : "contract.compact");
const currentFile = () => (project ? project.current : singleFileName());
const visible = () => allFindings.filter((f) => SEV_ORDER.indexOf(f.severity) <= SEV_ORDER.indexOf(minSeverity.value));

for (const ex of EXAMPLES) {
  const o = document.createElement("option");
  o.value = ex.name;
  o.textContent = ex.label;
  exampleSelect.appendChild(o);
}

// ---------------------------------------------------------------- analysis

function analyze(): void {
  if (busy) return;
  if (project) {
    project.files.set(project.current, code.value);
    allFindings = lintFileMap(project.files);
    const resolver = memoryImportResolver(project.files);
    disclosures =
      langOf(project.current) === "compact"
        ? mapDisclosures(code.value, project.current, { resolver, absolutePath: project.current }).filter((d) => d.protection !== "constant")
        : [];
  } else {
    const file = singleFileName();
    allFindings = lintSource(code.value, file);
    disclosures = lang.value === "ts" ? [] : mapDisclosures(code.value, file).filter((d) => d.protection !== "constant");
  }
  renderFileBar();
  renderGutter();
  render();
}

// ---------------------------------------------------------------- rendering

function renderFileBar(): void {
  if (!project) {
    fileSelect.hidden = true;
    lang.hidden = false;
    fileLabel.textContent = "";
    return;
  }
  lang.hidden = true;
  fileSelect.hidden = false;
  const counts = new Map<string, number>();
  for (const f of visible()) counts.set(f.file, (counts.get(f.file) ?? 0) + 1);
  fileSelect.innerHTML = [...project.files.keys()]
    .map((p) => `<option value="${esc(p)}"${p === project!.current ? " selected" : ""}>${esc(p)}${counts.get(p) ? `  (${counts.get(p)})` : ""}</option>`)
    .join("");
  fileLabel.textContent = `${project.files.size} file${project.files.size === 1 ? "" : "s"}`;
}

function renderGutter(): void {
  const file = currentFile();
  const hits = new Set(visible().filter((f) => f.file === file).map((f) => f.line));
  const n = code.value.split("\n").length;
  let html = "";
  for (let i = 1; i <= n; i++) html += hits.has(i) ? `<span class="hit">● ${i}</span>\n` : `${i}\n`;
  gutter.innerHTML = html;
  gutter.scrollTop = code.scrollTop;
}

function findingCard(f: Finding, i: number): string {
  return `<div class="finding" data-i="${i}">
    <div class="head"><span class="sev" style="color:${SEV_COLOR[f.severity]}">${f.severity.toUpperCase()}</span>
    <span class="rule">${f.ruleId} ${esc(f.ruleName)}</span><span class="loc">line ${f.line}:${f.col}</span>
    ${f.confidence !== "high" ? `<span class="conf">${f.confidence} confidence</span>` : ""}</div>
    <div class="msg">${esc(f.message)}</div>
    ${f.snippet.trim() ? `<div class="snippet">${esc(f.snippet.trim())}</div>` : ""}
    <a href="${f.docUrl}" target="_blank" rel="noopener">How to fix →</a></div>`;
}

function render(): void {
  const shown = visible();
  const counts = SEV_ORDER.map((s) => [s, shown.filter((f) => f.severity === s).length] as const).filter(([, n]) => n);
  const chip = project
    ? `<span class="chip" title="${esc(project.note ?? "")}">${esc(project.name)} · ${project.files.size} file${project.files.size === 1 ? "" : "s"}<button id="closeProject" title="Close">×</button></span>`
    : "";
  summary.innerHTML =
    chip +
    (shown.length
      ? counts.map(([s, n]) => `<span class="pill" style="color:${SEV_COLOR[s]};border-color:${SEV_COLOR[s]}">${n} ${s}</span>`).join("")
      : `<span class="pill" style="color:var(--ok);border-color:var(--ok)">No findings</span>`);
  $("closeProject")?.addEventListener("click", closeProject);

  if (tab === "findings") {
    if (!shown.length) {
      panel.innerHTML = project
        ? `<div class="empty"><div class="big">✔</div>No findings at this severity in ${project.files.size} files.${project.note ? `<br><span class="note">${esc(project.note)}</span>` : ""}</div>`
        : `<div class="empty"><div class="big">✔</div>No findings at this severity.<br>Paste your contract, open files, or scan a GitHub repository.</div>`;
      return;
    }
    if (!project) {
      panel.innerHTML = shown.map(findingCard).join("");
      return;
    }
    // group by file, current file first
    const files = [...new Set(shown.map((f) => f.file))].sort((a, b) => (a === project!.current ? -1 : b === project!.current ? 1 : 0));
    panel.innerHTML =
      files
        .map((file) => {
          const items = shown.map((f, i) => [f, i] as const).filter(([f]) => f.file === file);
          return `<div class="filehead" data-file="${esc(file)}">${esc(file)} <span class="count">${items.length}</span></div>${items.map(([f, i]) => findingCard(f, i)).join("")}`;
        })
        .join("") + (project.note ? `<p class="note">${esc(project.note)}</p>` : "");
    return;
  }

  if (!disclosures.length) {
    const isTs = project ? langOf(project.current) === "ts" : lang.value === "ts";
    panel.innerHTML = `<div class="empty">${isTs ? "The disclosure map is for Compact contracts." : "Nothing in this contract becomes public."}</div>`;
    return;
  }
  const prot = (d: DisclosureEntry) => {
    if (d.protection === "raw") return `<span class="raw">raw${d.secretBits !== undefined ? ` (${d.secretBits} bit${d.secretBits === 1 ? "" : "s"})` : ""}</span>`;
    if (d.protection === "hash") return d.secretBits !== undefined && d.secretBits <= 32 ? `<span class="weak">hash (${d.secretBits} bits)</span>` : `<span class="hash">hash</span>`;
    if (d.protection === "commit") return `<span class="commit">commitment</span>`;
    return `<span>${d.protection}</span>`;
  };
  const via = (d: DisclosureEntry) => (d.via === "return" ? "return value" : d.via === "ledger write" ? `ledger <code>${esc(d.target ?? "")}</code>` : "<code>disclose()</code>");
  const src = (d: DisclosureEntry) => (d.sources.length ? d.sources.map((s) => `<code>${esc(s.startsWith("witness:") ? s.slice(8) + "()" : s.slice(6))}</code>`).join(", ") : "-");
  panel.innerHTML = `${project ? `<p class="note">Disclosure map of <code>${esc(project.current)}</code>. Pick another file above the editor.</p>` : ""}<table><thead><tr><th>Line</th><th>Circuit</th><th>Becomes public via</th><th>Private inputs</th><th>Protection</th><th></th></tr></thead><tbody>${disclosures
    .map((d) => `<tr data-line="${d.loc.line}"><td>${d.loc.line}</td><td>${esc(d.circuit)}</td><td>${via(d)}</td><td>${src(d)}</td><td>${prot(d)}</td><td>${d.findings.map((f) => `<span class="pill">${f}</span>`).join(" ")}</td></tr>`)
    .join("")}</tbody></table><p class="note">Every point where data becomes public: <code>disclose()</code>, ledger writes, and return values of exported circuits. “raw” means private data is published as is.</p>`;
}

function progress(text: string, done = 0, total = 0): void {
  summary.innerHTML = "";
  const pct = total ? Math.round((done / total) * 100) : 0;
  panel.innerHTML = `<div class="progress">${esc(text)}${total ? `<div class="bar"><i style="width:${pct}%"></i></div>` : ""}</div>`;
}

function showError(text: string): void {
  summary.innerHTML = "";
  panel.innerHTML = `<div class="empty error">${esc(text)}</div>`;
}

// ---------------------------------------------------------------- navigation

function jumpTo(line: number): void {
  const lines = code.value.split("\n");
  const start = lines.slice(0, line - 1).reduce((n, l) => n + l.length + 1, 0);
  code.focus();
  code.setSelectionRange(start, start + (lines[line - 1]?.length ?? 0));
  code.scrollTop = Math.max(0, (line - 6) * 20);
}

function openFile(path: string, line?: number): void {
  if (!project || !project.files.has(path)) return;
  project.files.set(project.current, code.value);
  project.current = path;
  code.value = project.files.get(path)!;
  code.scrollTop = 0;
  analyze();
  if (line) jumpTo(line);
}

panel.addEventListener("click", (e) => {
  const target = e.target as HTMLElement;
  if (target.closest("a")) return;
  const head = target.closest(".filehead") as HTMLElement | null;
  if (head) return openFile(head.dataset.file!);
  const card = target.closest(".finding") as HTMLElement | null;
  if (card) {
    const f = visible()[Number(card.dataset.i)];
    if (project && f.file !== project.current) openFile(f.file, f.line);
    else jumpTo(f.line);
    return;
  }
  const row = target.closest("tr[data-line]") as HTMLElement | null;
  if (row) jumpTo(Number(row.dataset.line));
});

fileSelect.addEventListener("change", () => openFile(fileSelect.value));

// ---------------------------------------------------------------- projects

/** Keep contracts and DApp code; leave out TypeScript/JavaScript that doesn't touch the Midnight SDK. */
function relevant(entries: [string, string][], notes: string[]): [string, string][] {
  const keep = entries.filter(([p, src]) => p.endsWith(".compact") || usesMidnightSdk(src));
  const skipped = entries.length - keep.length;
  if (skipped) notes.push(`Skipped ${skipped} TypeScript/JavaScript file${skipped === 1 ? " that doesn't" : "s that don't"} use the Midnight SDK.`);
  return keep;
}

/** Order files: contracts first, then by path. */
function sortedFiles(entries: [string, string][]): Map<string, string> {
  return new Map(entries.sort(([a], [b]) => Number(b.endsWith(".compact")) - Number(a.endsWith(".compact")) || a.localeCompare(b)));
}

function openProject(p: Omit<Project, "current">): void {
  if (!p.files.size) {
    showError(`No .compact or TypeScript/JavaScript source files found in ${p.name}.`);
    return;
  }
  // start on the file with the most severe finding, or the first contract
  const first = lintFileMap(p.files)[0]?.file ?? [...p.files.keys()][0];
  project = { ...p, current: first };
  code.value = p.files.get(first)!;
  code.scrollTop = 0;
  analyze();
}

function closeProject(): void {
  project = null;
  if (location.hash.startsWith("#repo=")) history.replaceState(null, "", location.pathname);
  code.value = EXAMPLES[0].source;
  lang.value = EXAMPLES[0].lang;
  analyze();
}

async function ghJson(url: string): Promise<any> {
  const res = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
  if (res.status === 404) throw new Error("Repository, branch or path not found. Only public repositories can be scanned.");
  if (res.status === 403 || res.status === 429) {
    throw new Error(res.headers.get("x-ratelimit-remaining") === "0"
      ? "GitHub's rate limit for anonymous requests was reached (60 per hour). Try again later, or open the folder from your computer instead."
      : "GitHub refused the request. Try again later.");
  }
  if (!res.ok) throw new Error(`GitHub returned ${res.status}.`);
  return res.json();
}

async function scanRepo(ref: RepoRef): Promise<void> {
  if (busy) return;
  busy = true;
  try {
    const api = `https://api.github.com/repos/${ref.owner}/${ref.repo}`;
    progress(`Looking up ${ref.owner}/${ref.repo}…`);
    const branch = ref.ref ?? (await ghJson(api)).default_branch;
    progress("Listing files…");
    const tree = await ghJson(`${api}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
    const prefix = ref.path ? ref.path.replace(/\/$/, "") : "";
    const blobs: { path: string; size: number }[] = tree.tree.filter(
      (t: { type: string; path: string; size: number }) =>
        t.type === "blob" && t.size <= MAX_FILE_BYTES && isScannableFile(t.path) && (!prefix || t.path === prefix || t.path.startsWith(prefix + "/")),
    );
    const notes: string[] = [];
    if (tree.truncated) notes.push("GitHub truncated the file list because the repository is very large; some files were not scanned.");
    if (blobs.length > MAX_FILES) notes.push(`Scanned the first ${MAX_FILES} of ${blobs.length} files. Enter a folder URL (…/tree/<branch>/<path>) to narrow it down.`);
    const wanted = sortedFiles(blobs.map((b) => [b.path, ""])).keys();
    const paths = [...wanted].slice(0, MAX_FILES);

    const entries: [string, string][] = [];
    let done = 0;
    progress(`Downloading ${paths.length} files…`, 0, paths.length);
    const raw = (p: string) => `https://raw.githubusercontent.com/${ref.owner}/${ref.repo}/${encodeURIComponent(branch)}/${p.split("/").map(encodeURIComponent).join("/")}`;
    const queue = [...paths];
    await Promise.all(
      Array.from({ length: 8 }, async () => {
        for (let p = queue.shift(); p !== undefined; p = queue.shift()) {
          const res = await fetch(raw(p));
          if (res.ok) entries.push([p, await res.text()]);
          progress(`Downloading ${paths.length} files…`, ++done, paths.length);
        }
      }),
    );
    progress(`Analyzing ${entries.length} files…`);
    await new Promise((r) => setTimeout(r, 20));
    busy = false;
    const name = `${ref.owner}/${ref.repo}${prefix ? `/${prefix}` : ""}`;
    const kept = relevant(entries, notes);
    openProject({ name, repo: { ...ref, ref: branch }, files: sortedFiles(kept), note: notes.join(" ") || undefined });
    history.replaceState(null, "", `#repo=${ref.owner}/${ref.repo}${ref.ref || prefix ? `/tree/${branch}${prefix ? `/${prefix}` : ""}` : ""}`);
  } catch (err) {
    showError((err as Error).message || "Could not reach GitHub.");
  } finally {
    busy = false;
  }
}

$("repoForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const ref = parseRepoUrl(repoUrl.value);
  if (!ref) {
    showError("Enter a public GitHub repository, for example github.com/owner/repo or a …/tree/<branch>/<folder> link.");
    return;
  }
  void scanRepo(ref);
});

async function openLocal(list: FileList | null, label: string): Promise<void> {
  if (!list || !list.length) return;
  const files = [...list];
  // a picked folder's paths start with the folder name; drop it so imports resolve from the project root
  const relPath = (f: File) => {
    const rel = (f as File & { webkitRelativePath?: string }).webkitRelativePath;
    return rel ? rel.slice(rel.indexOf("/") + 1) : f.name;
  };
  const picked = files.filter((f) => f.size <= MAX_FILE_BYTES && isScannableFile(relPath(f)));
  progress(`Reading ${picked.length} files…`);
  const entries = await Promise.all(picked.slice(0, MAX_FILES).map(async (f) => [relPath(f), await f.text()] as [string, string]));
  const root = (files[0] as File & { webkitRelativePath?: string }).webkitRelativePath?.split("/")[0];
  const notes: string[] = picked.length > MAX_FILES ? [`Opened the first ${MAX_FILES} of ${picked.length} files.`] : [];
  // files picked one by one are always kept; a folder is filtered like a repository
  const kept = root ? relevant(entries, notes) : entries;
  openProject({ name: root || label, files: sortedFiles(kept), note: notes.join(" ") || undefined });
}

$("openFiles").addEventListener("click", () => $<HTMLInputElement>("fileInput").click());
$("openFolder").addEventListener("click", () => $<HTMLInputElement>("folderInput").click());
$<HTMLInputElement>("fileInput").addEventListener("change", (e) => void openLocal((e.target as HTMLInputElement).files, "Local files").then(() => ((e.target as HTMLInputElement).value = "")));
$<HTMLInputElement>("folderInput").addEventListener("change", (e) => void openLocal((e.target as HTMLInputElement).files, "Local folder").then(() => ((e.target as HTMLInputElement).value = "")));

// drag and drop files onto the page
document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop", (e) => {
  e.preventDefault();
  void openLocal(e.dataTransfer?.files ?? null, "Dropped files");
});

// ---------------------------------------------------------------- editor and controls

document.querySelectorAll<HTMLButtonElement>(".tab").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    tab = b.dataset.tab as typeof tab;
    render();
  }),
);

let timer: number | undefined;
code.addEventListener("input", () => {
  clearTimeout(timer);
  timer = window.setTimeout(analyze, project ? 400 : 200);
});
code.addEventListener("scroll", () => (gutter.scrollTop = code.scrollTop));
code.addEventListener("keydown", (e) => {
  if (e.key === "Tab") {
    e.preventDefault();
    const s = code.selectionStart;
    code.setRangeText("  ", s, code.selectionEnd, "end");
    analyze();
  }
});
lang.addEventListener("change", analyze);
minSeverity.addEventListener("change", () => {
  renderFileBar();
  renderGutter();
  render();
});
exampleSelect.addEventListener("change", () => {
  const ex = EXAMPLES.find((x) => x.name === exampleSelect.value);
  if (!ex) return;
  project = null;
  code.value = ex.source;
  lang.value = ex.lang;
  exampleSelect.value = "";
  analyze();
});

// share link: code is stored in the URL fragment, which browsers never send to a server
function encode(s: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function decode(s: string): string {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return new TextDecoder().decode(Uint8Array.from(b, (c) => c.charCodeAt(0)));
}
$("share").addEventListener("click", async () => {
  const url = project?.repo
    ? `${location.origin}${location.pathname}${location.hash}`
    : `${location.origin}${location.pathname}#${project ? langOf(project.current) : lang.value}:${encode(code.value)}`;
  history.replaceState(null, "", url);
  try {
    await navigator.clipboard.writeText(url);
    $("share").textContent = "Link copied ✓";
  } catch {
    $("share").textContent = "Link is in the address bar";
  }
  setTimeout(() => ($("share").textContent = "Copy share link"), 2000);
});

$("download").addEventListener("click", () => {
  const files = project ? project.files.size : 1;
  const md = formatMarkdown(allFindings, files, { title: project ? `Midnight Shield report: ${project.name}` : undefined, date: new Date().toISOString().slice(0, 10) });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
  a.download = "midnight-shield-report.md";
  a.click();
  URL.revokeObjectURL(a.href);
});

// ---------------------------------------------------------------- start

const hash = decodeURIComponent(location.hash.slice(1));
const shared = hash.match(/^(compact|ts):(.+)$/);
const repoHash = hash.match(/^repo=(.+)$/);
if (repoHash && parseRepoUrl(repoHash[1])) {
  repoUrl.value = `github.com/${repoHash[1]}`;
  code.value = "";
  void scanRepo(parseRepoUrl(repoHash[1])!);
} else {
  if (shared) {
    try {
      lang.value = shared[1];
      code.value = decode(shared[2]);
    } catch {
      code.value = EXAMPLES[0].source;
    }
  } else {
    code.value = EXAMPLES[0].source;
  }
  analyze();
}
