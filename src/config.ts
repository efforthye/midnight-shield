import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { CONFIDENCE_ORDER, RULES_BY_ID, SEVERITY_ORDER, type Confidence, type Severity } from "./rules.js";

export const CONFIG_FILE = "midnight-shield.config.json";

export interface Config {
  /** rule IDs to skip, e.g. ["MS005"] */
  disable?: string[];
  /** exit with code 1 at or above this severity ("none" never fails) */
  failOn?: Severity | "none";
  /** hide findings below this severity */
  minSeverity?: Severity;
  /** glob patterns of files to skip, relative to the working directory */
  ignore?: string[];
  /** hide findings below this confidence */
  minConfidence?: Confidence;
  /** baseline file of accepted findings */
  baseline?: string;
  /** custom rule modules, relative to the config file */
  plugins?: string[];
  /** also check TypeScript/JavaScript files (default true) */
  sdk?: boolean;
  /** a starting set of options: "recommended" for adopting in CI, "strict" for audits */
  preset?: PresetName;
  /** inline suppressions only count when they give a reason (`-- why`) */
  requireSuppressionReason?: boolean;
}

export type PresetName = "recommended" | "strict";

/**
 * recommended: what a team can turn on in CI on day one. Low-confidence and
 *   informational findings are hidden, and only high or critical findings fail the build.
 * strict: everything is shown, medium findings fail the build, and every
 *   suppression must say why, so the suppressions double as an audit record.
 */
export const PRESETS: Record<PresetName, Config> = {
  recommended: { minSeverity: "low", minConfidence: "medium", failOn: "high" },
  strict: { minSeverity: "info", minConfidence: "low", failOn: "medium", requireSuppressionReason: true },
};

/** Settings from a preset, overridden by the settings written next to it. */
export function withPreset(config: Config): Config {
  return config.preset ? { ...PRESETS[config.preset], ...config } : config;
}

export const DEFAULT_CONFIG: Config = {
  disable: [],
  failOn: "high",
  minSeverity: "info",
  minConfidence: "low",
  ignore: [],
  plugins: [],
  sdk: true,
};

export class ConfigError extends Error {}

/** Load and validate a config file. Returns undefined when the default file does not exist. */
export function loadConfig(path?: string, cwd = process.cwd()): Config | undefined {
  const file = resolve(cwd, path ?? CONFIG_FILE);
  if (!existsSync(file)) {
    if (path) throw new ConfigError(`config file not found: ${path}`);
    return undefined;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    throw new ConfigError(`${file}: invalid JSON (${(e as Error).message})`);
  }
  return validateConfig(raw, file);
}

export function validateConfig(raw: unknown, source = "config"): Config {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new ConfigError(`${source}: expected a JSON object`);
  const obj = raw as Record<string, unknown>;
  const out: Config = {};
  for (const key of Object.keys(obj)) {
    if (!["disable", "failOn", "minSeverity", "minConfidence", "ignore", "baseline", "plugins", "sdk", "preset", "requireSuppressionReason", "$schema"].includes(key)) throw new ConfigError(`${source}: unknown key "${key}"`);
  }
  if (obj.disable !== undefined) {
    if (!Array.isArray(obj.disable) || !obj.disable.every((x) => typeof x === "string")) throw new ConfigError(`${source}: "disable" must be an array of rule IDs`);
    const ids = (obj.disable as string[]).map((x) => x.toUpperCase());
    const unknown = ids.filter((id) => !RULES_BY_ID.has(id) && /^MS\d{3}$/.test(id));
    if (unknown.length) throw new ConfigError(`${source}: unknown rule ID(s) in "disable": ${unknown.join(", ")}`);
    out.disable = ids;
  }
  if (obj.failOn !== undefined) {
    if (obj.failOn !== "none" && !SEVERITY_ORDER.includes(obj.failOn as Severity)) throw new ConfigError(`${source}: "failOn" must be one of ${SEVERITY_ORDER.join(", ")}, none`);
    out.failOn = obj.failOn as Severity | "none";
  }
  if (obj.minSeverity !== undefined) {
    if (!SEVERITY_ORDER.includes(obj.minSeverity as Severity)) throw new ConfigError(`${source}: "minSeverity" must be one of ${SEVERITY_ORDER.join(", ")}`);
    out.minSeverity = obj.minSeverity as Severity;
  }
  if (obj.minConfidence !== undefined) {
    if (!CONFIDENCE_ORDER.includes(obj.minConfidence as Confidence)) throw new ConfigError(`${source}: "minConfidence" must be one of ${CONFIDENCE_ORDER.join(", ")}`);
    out.minConfidence = obj.minConfidence as Confidence;
  }
  if (obj.baseline !== undefined) {
    if (typeof obj.baseline !== "string") throw new ConfigError(`${source}: "baseline" must be a file path`);
    out.baseline = obj.baseline;
  }
  if (obj.plugins !== undefined) {
    if (!Array.isArray(obj.plugins) || !obj.plugins.every((x) => typeof x === "string")) throw new ConfigError(`${source}: "plugins" must be an array of module paths`);
    out.plugins = obj.plugins as string[];
  }
  if (obj.sdk !== undefined) {
    if (typeof obj.sdk !== "boolean") throw new ConfigError(`${source}: "sdk" must be true or false`);
    out.sdk = obj.sdk;
  }
  if (obj.preset !== undefined) {
    if (obj.preset !== "recommended" && obj.preset !== "strict") throw new ConfigError(`${source}: "preset" must be "recommended" or "strict"`);
    out.preset = obj.preset;
  }
  if (obj.requireSuppressionReason !== undefined) {
    if (typeof obj.requireSuppressionReason !== "boolean") throw new ConfigError(`${source}: "requireSuppressionReason" must be true or false`);
    out.requireSuppressionReason = obj.requireSuppressionReason;
  }
  if (obj.ignore !== undefined) {
    if (!Array.isArray(obj.ignore) || !obj.ignore.every((x) => typeof x === "string")) throw new ConfigError(`${source}: "ignore" must be an array of glob patterns`);
    out.ignore = obj.ignore as string[];
  }
  return out;
}
