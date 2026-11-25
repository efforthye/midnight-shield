#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CONFIG_FILE, ConfigError, DEFAULT_CONFIG, loadConfig, withPreset, type Config, type PresetName } from "./config.js";
import { applyEdits } from "./fixes.js";
import { createBaseline, type Finding, type LintOptions } from "./linter.js";
import { lintFiles, listTargetFiles, mapAccessInFiles, mapConstraintsInFiles, mapDisclosuresInFiles, readBaseline } from "./node.js";
import { loadPlugins } from "./plugin-loader.js";
import { PluginError, type CustomRule } from "./plugins.js";
import { VERSION, formatAccess, formatAccessMarkdown, formatConstraints, formatConstraintsMarkdown, formatDisclosures, formatDisclosuresMarkdown, formatJson, formatMarkdown, formatSarif, formatText } from "./reporters.js";
import { badgeJson } from "./badge.js";
import { createSnapshot, diffIsEmpty, diffSnapshots, formatDiffMarkdown, formatDiffText, readSnapshot } from "./privacy-diff.js";
import { CONFIDENCE_ORDER, RULES, SUPPORTED_LANGUAGE, RULES_BY_ID, SEVERITY_ORDER, type Confidence, type Severity } from "./rules.js";

const HELP = `midnight-shield ${VERSION}
Static analyzer for Midnight Compact contracts and their TypeScript code.
Tested with Compact language ${SUPPORTED_LANGUAGE.min}–${SUPPORTED_LANGUAGE.max}; files outside that range get a warning (MS033).

Usage:
  midnight-shield [paths...] [options]     scan files and folders (default: .)
  midnight-shield explain <RULE>           show a rule's documentation
  midnight-shield snapshot [paths...]      save findings and the disclosure map as JSON
                                           (-o file), to compare later with diff
  midnight-shield diff <base> <head>       privacy diff of two snapshots: what became
                                           public, new and fixed findings
                                           (--format text|markdown|json, --fail-on)
  midnight-shield --init                   create ${CONFIG_FILE}

Output:
  -f, --format <text|json|sarif|markdown>  Output format (default: text)
  -o, --output <file>                      Write the report to a file
      --print disclosures                  Print the disclosure map: every point where
                                           data becomes public, and what flows there
      --print access                       Print the access map: who can call each
                                           exported circuit, what it checks, what it
                                           changes and which tokens it moves
      --print witnesses                    Print the witness constraint report: what
                                           each prover-chosen value reaches, and
                                           what constrains it
      --no-code-frame                      Do not print source lines
      --no-suggestions                     Do not print suggested fixes
      --no-color                           Disable colored output
      --badge <file>                       Also write a status badge (shields.io endpoint JSON)

Filtering:
      --fail-on <severity>                 Exit 1 at or above this severity (default: high;
                                           "none" never fails)
      --min-severity <severity>            Hide findings below this severity
      --min-confidence <confidence>        Hide findings below this confidence (high, medium, low)
      --preset <recommended|strict>        Start from a preset (recommended: medium+ confidence, fail on high;
                                           strict: everything, fail on medium, suppressions need a reason)
      --require-suppression-reason         Ignore inline suppressions that do not say why (// … MS005 -- reason)
      --disable <MS001,MS005>              Skip rules
      --ignore <glob>                      Skip files matching a glob (repeatable)
      --no-sdk                             Do not check TypeScript/JavaScript files
      --show-suppressed                    Also list findings hidden by comments or a baseline

Adoption:
      --baseline <file>                    Accept the findings recorded in this file;
                                           report only new ones
      --write-baseline <file>              Record the current findings as accepted
      --fix                                Apply safe automatic fixes
      --fix-dry-run                        Show which files --fix would change
  -c, --config <file>                      Config file (default: ./${CONFIG_FILE})
      --plugin <module>                    Load custom rules from a module (repeatable)

  -v, --version                            Print the version
  -h, --help                               Show this help
      --list-rules                         Print all rules

Suppress a finding in code:
  // shield-disable-next-line MS005
  // shield-disable-line MS005
  // shield-disable-file MS006
`;

function fail(msg: string): never {
  process.stderr.write(`midnight-shield: ${msg}\n`);
  process.exit(2);
}

function parseSeverity(v: string | undefined, flag: string): Severity {
  if (!v || !SEVERITY_ORDER.includes(v as Severity)) fail(`${flag} must be one of ${SEVERITY_ORDER.join(", ")}`);
  return v as Severity;
}

function parseConfidence(v: string | undefined, flag: string): Confidence {
  if (!v || !CONFIDENCE_ORDER.includes(v as Confidence)) fail(`${flag} must be one of ${CONFIDENCE_ORDER.join(", ")}`);
  return v as Confidence;
}

/** docs/rules lives two levels above dist/src/cli.js in the installed package. */
function docsDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "..", "docs", "rules");
}

function explain(id: string | undefined, plugins: CustomRule[]): void {
  if (!id) fail("explain needs a rule ID, e.g. midnight-shield explain MS001");
  const ruleId = id.toUpperCase();
  const builtIn = RULES_BY_ID.get(ruleId);
  const custom = plugins.find((p) => p.id === ruleId);
  const meta = builtIn ?? custom;
  if (!meta) fail(`unknown rule ${id}. Run midnight-shield --list-rules`);
  const doc = join(docsDir(), `${ruleId}.md`);
  if (builtIn && existsSync(doc)) {
    process.stdout.write(readFileSync(doc, "utf8").trimEnd() + "\n");
  } else {
    process.stdout.write(`${meta.id} ${meta.name}\n\nSeverity: ${meta.severity}\nConfidence: ${meta.confidence}\n\n${meta.summary}\n`);
    if (meta.docUrl) process.stdout.write(`\n${meta.docUrl}\n`);
  }
}

function diffCommand(paths: string[], format: string, output: string | undefined, failOn: Severity | "none" | undefined): void {
  if (paths.length !== 2) fail("diff needs two snapshots: midnight-shield diff base.json head.json");
  const [basePath, headPath] = paths;
  let diff;
  try {
    const base = readSnapshot(readFileSync(basePath, "utf8"), basePath);
    const head = readSnapshot(readFileSync(headPath, "utf8"), headPath);
    diff = diffSnapshots(base, head);
  } catch (e) {
    fail((e as Error).message);
  }
  const report =
    format === "json"
      ? JSON.stringify({ tool: "midnight-shield", version: VERSION, empty: diffIsEmpty(diff), ...diff }, null, 2)
      : format === "markdown"
        ? formatDiffMarkdown(diff, { marker: "<!-- midnight-shield-privacy-diff -->", scanUrl: process.env.MIDNIGHT_SHIELD_SCAN_URL })
        : formatDiffText(diff);
  if (output) writeFileSync(output, report + "\n");
  else process.stdout.write(report + "\n");
  // only new findings can fail a diff: existing ones are the base's
  const level = failOn ?? "none";
  if (level !== "none" && diff.newFindings.some((f) => SEVERITY_ORDER.indexOf(f.severity) <= SEVERITY_ORDER.indexOf(level))) process.exitCode = 1;
}

async function main(argv: string[]): Promise<void> {
  const paths: string[] = [];
  let format = "text";
  let output: string | undefined;
  let configPath: string | undefined;
  let failOn: Severity | "none" | undefined;
  let minSeverity: Severity | undefined;
  let minConfidence: Confidence | undefined;
  let disable: string[] | undefined;
  const ignore: string[] = [];
  const pluginPaths: string[] = [];
  let codeFrame = true;
  let suggestions = true;
  let sdk: boolean | undefined;
  let showSuppressed = false;
  let baselinePath: string | undefined;
  let writeBaseline: string | undefined;
  let fix = false;
  let fixDryRun = false;
  let print: string | undefined;
  let command: string | undefined;
  let badge: string | undefined;
  let preset: PresetName | undefined;
  let requireReason: boolean | undefined;
  let color = (Boolean(process.stdout.isTTY) || Boolean(process.env.FORCE_COLOR)) && !process.env.NO_COLOR;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined) fail(`${a} needs a value`);
      return v;
    };
    switch (a) {
      case "-h":
      case "--help":
        process.stdout.write(HELP);
        return;
      case "-v":
      case "--version":
        process.stdout.write(`${VERSION}\n`);
        return;
      case "--list-rules":
        for (const r of RULES) process.stdout.write(`${r.id}  ${r.severity.padEnd(8)} ${r.confidence.padEnd(6)} ${r.name.padEnd(28)} ${r.summary}\n`);
        return;
      case "--init":
        if (existsSync(CONFIG_FILE)) fail(`${CONFIG_FILE} already exists`);
        writeFileSync(CONFIG_FILE, JSON.stringify(DEFAULT_CONFIG, null, 2) + "\n");
        process.stdout.write(`Created ${CONFIG_FILE}\n`);
        return;
      case "-f":
      case "--format":
        format = value();
        if (!["text", "json", "sarif", "markdown", "md"].includes(format)) fail("--format must be text, json, sarif or markdown");
        if (format === "md") format = "markdown";
        break;
      case "-o":
      case "--output":
        output = value();
        break;
      case "-c":
      case "--config":
        configPath = value();
        break;
      case "--fail-on": {
        const v = value();
        failOn = v === "none" ? "none" : parseSeverity(v, "--fail-on");
        break;
      }
      case "--min-severity":
        minSeverity = parseSeverity(value(), "--min-severity");
        break;
      case "--preset": {
        const p = value();
        if (p !== "recommended" && p !== "strict") fail(`--preset must be recommended or strict, not ${p}`);
        preset = p as PresetName;
        break;
      }
      case "--require-suppression-reason":
        requireReason = true;
        break;
      case "--min-confidence":
        minConfidence = parseConfidence(value(), "--min-confidence");
        break;
      case "--disable":
        disable = value()
          .split(",")
          .map((s) => s.trim().toUpperCase())
          .filter(Boolean);
        break;
      case "--ignore":
        ignore.push(value());
        break;
      case "--plugin":
        pluginPaths.push(value());
        break;
      case "--baseline":
        baselinePath = value();
        break;
      case "--write-baseline":
        writeBaseline = value();
        break;
      case "--show-suppressed":
        showSuppressed = true;
        break;
      case "--fix":
        fix = true;
        break;
      case "--fix-dry-run":
        fixDryRun = true;
        break;
      case "--print":
        print = value();
        if (print !== "disclosures" && print !== "access" && print !== "witnesses") fail('--print supports "disclosures", "access" and "witnesses"');
        break;
      case "--badge":
        badge = value();
        break;
      case "--no-suggestions":
        suggestions = false;
        break;
      case "--no-code-frame":
        codeFrame = false;
        break;
      case "--no-sdk":
        sdk = false;
        break;
      case "--no-color":
        color = false;
        break;
      default:
        if (a.startsWith("-")) fail(`unknown option ${a}`);
        if (!command && paths.length === 0 && (a === "explain" || a === "snapshot" || a === "diff")) command = a;
        else paths.push(a);
    }
  }

  let config: Config;
  try {
    config = loadConfig(configPath) ?? {};
    // a --preset on the command line replaces the config file's preset; the file's own settings still apply
    config = withPreset(preset ? { ...config, preset } : config);
  } catch (e) {
    if (e instanceof ConfigError) fail(e.message);
    throw e;
  }
  const configDir = configPath ? dirname(resolve(configPath)) : process.cwd();

  let plugins: CustomRule[] = [];
  try {
    plugins = [
      ...(await loadPlugins(config.plugins ?? [], configDir)),
      ...(await loadPlugins(pluginPaths, process.cwd())),
    ];
  } catch (e) {
    if (e instanceof PluginError) fail(e.message);
    throw e;
  }

  if (command === "explain") return explain(paths[0], plugins);
  if (command === "diff") return diffCommand(paths, format, output, failOn);

  const baselineFile = baselinePath ?? (config.baseline ? resolve(configDir, config.baseline) : undefined);
  let baseline: Set<string> | undefined;
  if (baselineFile && !writeBaseline) {
    if (!existsSync(baselineFile)) fail(`baseline not found: ${baselineFile}`);
    try {
      baseline = readBaseline(baselineFile);
    } catch (e) {
      fail((e as Error).message);
    }
  }

  const options: LintOptions = {
    disable: disable ?? config.disable,
    // collect everything, then hide below the chosen severity here, so the hidden count can be shown
    minSeverity: "info",
    minConfidence: minConfidence ?? config.minConfidence,
    ignore: [...(config.ignore ?? []), ...ignore],
    sdk: sdk ?? config.sdk ?? true,
    plugins,
    baseline,
    includeSuppressed: true,
    requireSuppressionReason: requireReason ?? config.requireSuppressionReason,
  };
  const failLevel = failOn ?? config.failOn ?? "high";
  if (paths.length === 0) paths.push(".");

  let fileCount: number;
  let findings: Finding[];
  try {
    fileCount = listTargetFiles(paths, options.ignore, process.cwd(), options.sdk).length;
    if (print === "witnesses") {
      const entries = mapConstraintsInFiles(paths, options);
      const out =
        format === "json" ? JSON.stringify({ tool: "midnight-shield", version: VERSION, witnesses: entries }, null, 2) : format === "markdown" ? formatConstraintsMarkdown(entries) : formatConstraints(entries, { color: color && !output });
      if (output) writeFileSync(output, out + "\n");
      else process.stdout.write(out + "\n");
      return;
    }
    if (print === "access") {
      const entries = mapAccessInFiles(paths, options);
      const out =
        format === "json" ? JSON.stringify({ tool: "midnight-shield", version: VERSION, access: entries }, null, 2) : format === "markdown" ? formatAccessMarkdown(entries) : formatAccess(entries, { color: color && !output });
      if (output) writeFileSync(output, out + "\n");
      else process.stdout.write(out + "\n");
      return;
    }
    if (print === "disclosures") {
      const entries = mapDisclosuresInFiles(paths, options);
      const out =
        format === "json" ? JSON.stringify({ tool: "midnight-shield", version: VERSION, disclosures: entries }, null, 2) : format === "markdown" ? formatDisclosuresMarkdown(entries) : formatDisclosures(entries, { color: color && !output });
      if (output) writeFileSync(output, out + "\n");
      else process.stdout.write(out + "\n");
      return;
    }
    findings = lintFiles(paths, options);
  } catch (e) {
    fail((e as Error).message);
  }

  if (command === "snapshot") {
    const snap = createSnapshot(findings, mapDisclosuresInFiles(paths, options), VERSION);
    const json = JSON.stringify(snap, null, 2) + "\n";
    if (output) {
      writeFileSync(output, json);
      process.stdout.write(`Saved ${snap.findings.length} finding(s) and ${snap.disclosures.length} disclosure(s) to ${output}\n`);
    } else process.stdout.write(json);
    return;
  }

  if (fix || fixDryRun) {
    const byFile = new Map<string, Finding[]>();
    for (const f of findings) if (f.fix && !f.suppressed) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);
    for (const [file, fs] of byFile) {
      const rules = fs.map((f) => f.ruleId).join(", ");
      if (fixDryRun) {
        process.stdout.write(`would fix ${file} (${rules})\n`);
        continue;
      }
      const source = readFileSync(file, "utf8");
      writeFileSync(file, applyEdits(source, fs.map((f) => f.fix!)));
      process.stdout.write(`fixed ${file} (${rules})\n`);
    }
    if (!byFile.size) process.stdout.write("Nothing to fix automatically.\n");
    if (fixDryRun) return;
    findings = lintFiles(paths, options); // re-scan after fixing
  }

  // informational notes (unused code, a missing pragma) are hidden unless asked for: they are
  // worth a look, not worth drowning a security report in
  const shownMin = minSeverity ?? config.minSeverity ?? "low";
  const allFindings = findings;
  findings = findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= SEVERITY_ORDER.indexOf(shownMin));
  const hiddenNotes = allFindings.filter((f) => !f.suppressed && !findings.includes(f)).length;

  if (writeBaseline) {
    const data = createBaseline(findings);
    writeFileSync(writeBaseline, JSON.stringify(data, null, 2) + "\n");
    process.stdout.write(`Wrote ${data.findings.length} accepted finding(s) to ${writeBaseline}\n`);
    return;
  }

  const visible = showSuppressed ? findings : findings.filter((f) => !f.suppressed);
  const active = findings.filter((f) => !f.suppressed);
  const text = (useColor: boolean) => formatText(visible, fileCount, { color: useColor, codeFrame, suggestions });
  const report =
    format === "json"
      ? formatJson(visible)
      : format === "sarif"
        ? formatSarif(findings, plugins)
        : format === "markdown"
          ? formatMarkdown(visible, fileCount, { date: new Date().toISOString().slice(0, 10) })
          : text(color && !output);

  if (badge) writeFileSync(badge, JSON.stringify(badgeJson(findings)) + "\n");

  const hiddenNote = hiddenNotes && format === "text" ? `  ${hiddenNotes} lower-severity finding${hiddenNotes === 1 ? "" : "s"} hidden (below ${shownMin}: unused code, a missing pragma and similar); --min-severity info shows everything.\n` : "";
  if (output) {
    writeFileSync(output, report + "\n");
    process.stdout.write(text(color) + "\n" + hiddenNote);
  } else {
    process.stdout.write(report + "\n" + hiddenNote);
  }

  // parts of files that were not analyzed: say so on stderr, so a clean report is not mistaken for full coverage
  const partial = new Set(allFindings.filter((f) => f.ruleId === "MS000").map((f) => f.file));
  const versionWarned = new Set(allFindings.filter((f) => f.ruleId === "MS033").map((f) => f.file));
  if (partial.size || versionWarned.size) {
    const parts = [
      partial.size ? `${partial.size} file(s) could not be fully parsed (MS000)` : "",
      versionWarned.size ? `${versionWarned.size} file(s) target a Compact version outside ${SUPPORTED_LANGUAGE.min}–${SUPPORTED_LANGUAGE.max} (MS033)` : "",
    ].filter(Boolean);
    process.stderr.write(`midnight-shield: warning: ${parts.join("; ")}. Findings for those parts may be incomplete.\n`);
  }

  if (failLevel !== "none") {
    const limit = SEVERITY_ORDER.indexOf(failLevel);
    if (active.some((f) => SEVERITY_ORDER.indexOf(f.severity) <= limit)) process.exitCode = 1;
  }
}

main(process.argv.slice(2)).catch((e) => fail((e as Error).stack ?? String(e)));
