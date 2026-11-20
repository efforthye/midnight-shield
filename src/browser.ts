// Browser entry point for the web playground. Everything here runs locally in
// the page: no Node APIs, no network.
export { lintSource, mapDisclosures, type Finding, type DisclosureEntry } from "./linter.js";
export { RULES, RULES_BY_ID } from "./rules.js";
export { formatMarkdown, VERSION } from "./reporters.js";
