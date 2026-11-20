import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { RULES_BY_ID, SEVERITY_ORDER, type Severity } from "./rules.js";

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
}

export const DEFAULT_CONFIG: Required<Config> = {
  disable: [],
  failOn: "high",
  minSeverity: "info",
  ignore: [],
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
    if (!["disable", "failOn", "minSeverity", "ignore", "$schema"].includes(key)) throw new ConfigError(`${source}: unknown key "${key}"`);
  }
  if (obj.disable !== undefined) {
    if (!Array.isArray(obj.disable) || !obj.disable.every((x) => typeof x === "string")) throw new ConfigError(`${source}: "disable" must be an array of rule IDs`);
    const ids = (obj.disable as string[]).map((x) => x.toUpperCase());
    const unknown = ids.filter((id) => !RULES_BY_ID.has(id));
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
  if (obj.ignore !== undefined) {
    if (!Array.isArray(obj.ignore) || !obj.ignore.every((x) => typeof x === "string")) throw new ConfigError(`${source}: "ignore" must be an array of glob patterns`);
    out.ignore = obj.ignore as string[];
  }
  return out;
}
