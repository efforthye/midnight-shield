// Library entry point (Node.js). The browser playground uses src/browser.ts.
export { lintSource, mapDisclosures, createBaseline, type Finding, type LintOptions, type DisclosureEntry, type BaselineFile } from "./linter.js";
export { parseRepoUrl, isScannableFile, usesMidnightSdk, lintFileMap, memoryImportResolver, type RepoRef } from "./repo.js";
export { lintFiles, mapDisclosuresInFiles, listTargetFiles, findCompactFiles, fileImportResolver, readBaseline, globToRegExp } from "./node.js";
export { loadConfig, validateConfig, DEFAULT_CONFIG, type Config } from "./config.js";
export { loadPlugins } from "./plugin-loader.js";
export { type CustomRule, type RuleContext, type PluginReport } from "./plugins.js";
export { walkProgram, calleeName, type Visitor, type WalkContext } from "./walk.js";
export { applyEdits, pragmaFix, type TextEdit } from "./fixes.js";
export { parse } from "./parser.js";
export { RULES, RULES_BY_ID, type RuleMeta, type Severity, type Confidence } from "./rules.js";
export { formatJson, formatSarif, formatText, formatMarkdown, formatDisclosures, VERSION, type TextOptions } from "./reporters.js";
export { suggestFix, suggestionDiff, type Suggestion, type DiffLine } from "./suggest.js";
export { createSnapshot, readSnapshot, diffSnapshots, diffIsEmpty, formatDiffMarkdown, formatDiffText, type Snapshot, type PrivacyDiff } from "./privacy-diff.js";
export { badgeJson, type BadgeJson } from "./badge.js";
