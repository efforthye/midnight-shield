// Runs inside `npm version <patch|minor|major>`, after package.json has the new
// version and before npm commits and tags it. It keeps the other places that
// name the version in step, so a release is two commands:
//   npm version patch
//   git push --follow-tags
import { readFileSync, writeFileSync } from "node:fs";

const { version } = JSON.parse(readFileSync("package.json", "utf8"));

// 1. The version the CLI, reports and playground print.
const reporters = "src/reporters.ts";
const src = readFileSync(reporters, "utf8");
if (!/export const VERSION = "[^"]*";/.test(src)) throw new Error(`${reporters}: VERSION not found`);
writeFileSync(reporters, src.replace(/export const VERSION = "[^"]*";/, `export const VERSION = "${version}";`));

// 2. The changelog: what is under "Unreleased" becomes this version.
const changelog = "CHANGELOG.md";
const text = readFileSync(changelog, "utf8");
const nl = text.includes("\r\n") ? "\r\n" : "\n";
const start = text.indexOf("## [Unreleased]");
if (start === -1) throw new Error(`${changelog}: add your changes under "## [Unreleased]" first`);
const next = text.indexOf("## [", start + 1);
const body = text.slice(start + "## [Unreleased]".length, next === -1 ? undefined : next).trim();
if (!body) throw new Error(`${changelog}: nothing under "## [Unreleased]" to release`);
const date = new Date().toISOString().slice(0, 10);
writeFileSync(changelog, text.replace("## [Unreleased]", `## [Unreleased]${nl}${nl}## [${version}] - ${date}`));

console.log(`Prepared ${version}: ${reporters} and ${changelog} updated.`);
