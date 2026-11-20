#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { findCompactFiles, lintFiles, type LintOptions } from "./linter.js";
import { VERSION, formatJson, formatSarif, formatText } from "./reporters.js";
import { RULES, SEVERITY_ORDER, type Severity } from "./rules.js";

const HELP = `midnight-shield ${VERSION}
Static analyzer for Midnight Compact contracts.

Usage:
  midnight-shield [paths...] [options]

Options:
  -f, --format <text|json|sarif>   Output format (default: text)
  -o, --output <file>              Write the report to a file
      --fail-on <severity>         Exit with code 1 if a finding is at or above
                                   this severity (default: high; "none" to never fail)
      --min-severity <severity>    Hide findings below this severity (default: info)
      --disable <MS001,MS005>      Comma-separated rule IDs to skip
      --list-rules                 Print all rules and exit
      --no-color                   Disable colored output
  -v, --version                    Print the version
  -h, --help                       Show this help

Severities: critical, high, medium, low, info

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
  let failOn: Severity | "none" = "high";
  let color = process.stdout.isTTY && !process.env.NO_COLOR;
  const options: LintOptions = {};

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
      case "-f":
      case "--format":
        format = value();
        if (!["text", "json", "sarif"].includes(format)) fail("--format must be text, json or sarif");
        break;
      case "-o":
      case "--output":
        output = value();
        break;
      case "--fail-on": {
        const v = value();
        failOn = v === "none" ? "none" : parseSeverity(v, "--fail-on");
        break;
      }
      case "--min-severity":
        options.minSeverity = parseSeverity(value(), "--min-severity");
        break;
      case "--disable":
        options.disable = value()
          .split(",")
          .map((s) => s.trim().toUpperCase())
          .filter(Boolean);
        break;
      case "--no-color":
        color = false;
        break;
      default:
        if (a.startsWith("-")) fail(`unknown option ${a}`);
        paths.push(a);
    }
  }

  if (paths.length === 0) paths.push(".");

  let fileCount: number;
  let findings;
  try {
    fileCount = findCompactFiles(paths).length;
    findings = lintFiles(paths, options);
  } catch (e) {
    fail((e as Error).message);
  }

  const report =
    format === "json" ? formatJson(findings) : format === "sarif" ? formatSarif(findings) : formatText(findings, fileCount, color && !output);

  if (output) {
    writeFileSync(output, report + "\n");
    if (format !== "text") process.stdout.write(formatText(findings, fileCount, color) + "\n");
  } else {
    process.stdout.write(report + "\n");
  }

  if (failOn !== "none") {
    const limit = SEVERITY_ORDER.indexOf(failOn);
    if (findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) <= limit)) process.exitCode = 1;
  }
}

main(process.argv.slice(2));
