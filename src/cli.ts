#!/usr/bin/env node
import { existsSync, writeFileSync } from "node:fs";
import { CONFIG_FILE, ConfigError, DEFAULT_CONFIG, loadConfig } from "./config.js";
import { lintFiles, listTargetFiles, type Finding, type LintOptions } from "./linter.js";
import { VERSION, formatJson, formatSarif, formatText } from "./reporters.js";
import { RULES, SEVERITY_ORDER, type Severity } from "./rules.js";

const HELP = `midnight-shield ${VERSION}
Static analyzer for Midnight Compact contracts.

Usage:
  midnight-shield [paths...] [options]
  midnight-shield --init

Options:
  -f, --format <text|json|sarif>   Output format (default: text)
  -o, --output <file>              Write the report to a file
  -c, --config <file>              Config file (default: ./${CONFIG_FILE} if present)
      --fail-on <severity>         Exit with code 1 if a finding is at or above
                                   this severity (default: high; "none" to never fail)
      --min-severity <severity>    Hide findings below this severity (default: info)
      --disable <MS001,MS005>      Comma-separated rule IDs to skip
      --ignore <glob>              Skip files matching a glob (repeatable)
      --no-code-frame              Do not print the source line under each finding
      --list-rules                 Print all rules and exit
      --init                       Create ${CONFIG_FILE} with default settings
      --no-color                   Disable colored output
  -v, --version                    Print the version
  -h, --help                       Show this help

Severities: critical, high, medium, low, info
Command-line options override the config file.

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

function main(argv: string[]): void {
  const paths: string[] = [];
  let format = "text";
  let output: string | undefined;
  let configPath: string | undefined;
  let failOn: Severity | "none" | undefined;
  let minSeverity: Severity | undefined;
  let disable: string[] | undefined;
  const ignore: string[] = [];
  let codeFrame = true;
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
        for (const r of RULES) process.stdout.write(`${r.id}  ${r.severity.padEnd(8)} ${r.name.padEnd(28)} ${r.summary}\n`);
        return;
      case "--init":
        if (existsSync(CONFIG_FILE)) fail(`${CONFIG_FILE} already exists`);
        writeFileSync(CONFIG_FILE, JSON.stringify(DEFAULT_CONFIG, null, 2) + "\n");
        process.stdout.write(`Created ${CONFIG_FILE}\n`);
        return;
      case "-f":
      case "--format":
        format = value();
        if (!["text", "json", "sarif"].includes(format)) fail("--format must be text, json or sarif");
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
      case "--disable":
        disable = value()
          .split(",")
          .map((s) => s.trim().toUpperCase())
          .filter(Boolean);
        break;
      case "--ignore":
        ignore.push(value());
        break;
      case "--no-code-frame":
        codeFrame = false;
        break;
      case "--no-color":
        color = false;
        break;
      default:
        if (a.startsWith("-")) fail(`unknown option ${a}`);
        paths.push(a);
    }
  }

  let config;
  try {
    config = loadConfig(configPath) ?? {};
  } catch (e) {
    if (e instanceof ConfigError) fail(e.message);
    throw e;
  }

  const options: LintOptions = {
    disable: disable ?? config.disable,
    minSeverity: minSeverity ?? config.minSeverity,
    ignore: [...(config.ignore ?? []), ...ignore],
  };
  const failLevel = failOn ?? config.failOn ?? "high";
  if (paths.length === 0) paths.push(".");

  let fileCount: number;
  let findings: Finding[];
  try {
    fileCount = listTargetFiles(paths, options.ignore).length;
    findings = lintFiles(paths, options);
  } catch (e) {
    fail((e as Error).message);
  }

  const text = (useColor: boolean) => formatText(findings, fileCount, { color: useColor, codeFrame });
  const report = format === "json" ? formatJson(findings) : format === "sarif" ? formatSarif(findings) : text(color && !output);

  if (output) {
    writeFileSync(output, report + "\n");
    process.stdout.write(text(color) + "\n");
  } else {
    process.stdout.write(report + "\n");
  }

  if (failLevel !== "none") {
    const limit = SEVERITY_ORDER.indexOf(failLevel);
    if (findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) <= limit)) process.exitCode = 1;
  }
}

main(process.argv.slice(2));
