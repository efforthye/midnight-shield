import { lintSource, mapDisclosures, formatMarkdown, VERSION, type Finding, type DisclosureEntry } from "../src/browser.js";
import { EXAMPLES } from "./examples.generated.js";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const code = $<HTMLTextAreaElement>("code");
const gutter = $("gutter");
const panel = $("panel");
const summary = $("summary");
const lang = $<HTMLSelectElement>("lang");
const minSeverity = $<HTMLSelectElement>("minSeverity");
const exampleSelect = $<HTMLSelectElement>("example");
$("version").textContent = VERSION;

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR: Record<string, string> = { critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)", info: "var(--info)" };
let tab: "findings" | "disclosures" = "findings";
let findings: Finding[] = [];
let disclosures: DisclosureEntry[] = [];

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
const fileName = () => (lang.value === "ts" ? "contract.ts" : "contract.compact");

for (const ex of EXAMPLES) {
  const o = document.createElement("option");
  o.value = ex.name;
  o.textContent = ex.label;
  exampleSelect.appendChild(o);
}

function analyze(): void {
  const file = fileName();
  const all = lintSource(code.value, file);
  const limit = SEV_ORDER.indexOf(minSeverity.value);
  findings = all.filter((f) => SEV_ORDER.indexOf(f.severity) <= limit);
  disclosures = lang.value === "ts" ? [] : mapDisclosures(code.value, file).filter((d) => d.protection !== "constant");
  renderGutter();
  render();
}

function renderGutter(): void {
  const hits = new Set(findings.map((f) => f.line));
  const n = code.value.split("\n").length;
  let html = "";
  for (let i = 1; i <= n; i++) html += hits.has(i) ? `<span class="hit">● ${i}</span>\n` : `${i}\n`;
  gutter.innerHTML = html;
  gutter.scrollTop = code.scrollTop;
}

function render(): void {
  const counts = SEV_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n);
  summary.innerHTML = findings.length
    ? counts.map(([s, n]) => `<span class="pill" style="color:${SEV_COLOR[s]};border-color:${SEV_COLOR[s]}">${n} ${s}</span>`).join("")
    : `<span class="pill" style="color:var(--ok);border-color:var(--ok)">No findings</span>`;

  if (tab === "findings") {
    if (!findings.length) {
      panel.innerHTML = `<div class="empty"><div class="big">✔</div>No findings at this severity.<br>Try “Load an example” to see what Midnight Shield catches.</div>`;
      return;
    }
    panel.innerHTML = findings
      .map(
        (f, i) => `<div class="finding" data-i="${i}" style="border-left-color:${SEV_COLOR[f.severity]}">
          <div class="head"><span class="sev" style="color:${SEV_COLOR[f.severity]}">${f.severity.toUpperCase()}</span>
          <span class="rule">${f.ruleId} ${esc(f.ruleName)}</span><span class="loc">line ${f.line}:${f.col}</span>
          ${f.confidence !== "high" ? `<span class="conf">${f.confidence} confidence</span>` : ""}</div>
          <div class="msg">${esc(f.message)}</div>
          ${f.snippet.trim() ? `<div class="snippet">${esc(f.snippet.trim())}</div>` : ""}
          <a href="${f.docUrl}" target="_blank" rel="noopener">How to fix →</a></div>`,
      )
      .join("");
    return;
  }

  if (!disclosures.length) {
    panel.innerHTML = `<div class="empty">${lang.value === "ts" ? "The disclosure map is for Compact contracts." : "Nothing in this contract becomes public."}</div>`;
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
  panel.innerHTML = `<table><thead><tr><th>Line</th><th>Circuit</th><th>Becomes public via</th><th>Private inputs</th><th>Protection</th><th></th></tr></thead><tbody>${disclosures
    .map((d) => `<tr><td>${d.loc.line}</td><td>${esc(d.circuit)}</td><td>${via(d)}</td><td>${src(d)}</td><td>${prot(d)}</td><td>${d.findings.map((f) => `<span class="pill">${f}</span>`).join(" ")}</td></tr>`)
    .join("")}</tbody></table><p class="note">Every point where data becomes public: <code>disclose()</code>, ledger writes, and return values of exported circuits. “raw” means private data is published as is.</p>`;
}

function jumpTo(line: number): void {
  const lines = code.value.split("\n");
  const start = lines.slice(0, line - 1).reduce((n, l) => n + l.length + 1, 0);
  code.focus();
  code.setSelectionRange(start, start + (lines[line - 1]?.length ?? 0));
  code.scrollTop = Math.max(0, (line - 6) * 20);
}

panel.addEventListener("click", (e) => {
  const el = (e.target as HTMLElement).closest(".finding") as HTMLElement | null;
  if (el && !(e.target as HTMLElement).closest("a")) jumpTo(findings[Number(el.dataset.i)].line);
});

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
  timer = window.setTimeout(analyze, 200);
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
minSeverity.addEventListener("change", analyze);
exampleSelect.addEventListener("change", () => {
  const ex = EXAMPLES.find((x) => x.name === exampleSelect.value);
  if (!ex) return;
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
  const url = `${location.origin}${location.pathname}#${lang.value}:${encode(code.value)}`;
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
  const md = formatMarkdown(lintSource(code.value, fileName()), 1, { date: new Date().toISOString().slice(0, 10) });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
  a.download = "midnight-shield-report.md";
  a.click();
  URL.revokeObjectURL(a.href);
});

const hash = location.hash.slice(1);
const m = hash.match(/^(compact|ts):(.+)$/);
if (m) {
  try {
    lang.value = m[1];
    code.value = decode(m[2]);
  } catch {
    code.value = EXAMPLES[0].source;
  }
} else {
  code.value = EXAMPLES[0].source;
}
analyze();
