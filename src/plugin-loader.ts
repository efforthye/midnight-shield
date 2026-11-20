// Loads plugin modules from disk (Node.js only).

import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { PluginError, validateRule, type CustomRule } from "./plugins.js";
import { RULES_BY_ID } from "./rules.js";

/** Load plugin modules (paths relative to `baseDir`) and return their validated rules. */
export async function loadPlugins(paths: string[], baseDir = process.cwd()): Promise<CustomRule[]> {
  const rules: CustomRule[] = [];
  const seen = new Set<string>();
  for (const p of paths) {
    const abs = resolve(baseDir, p);
    let mod: Record<string, unknown>;
    try {
      mod = await import(pathToFileURL(abs).href);
    } catch (e) {
      throw new PluginError(`cannot load plugin ${p}: ${(e as Error).message}`);
    }
    const list = (mod.default ?? mod.rules) as unknown;
    if (!Array.isArray(list)) throw new PluginError(`${p}: export an array of rules as default (or as "rules")`);
    for (const raw of list) {
      const rule = validateRule(raw, p);
      if (seen.has(rule.id) || RULES_BY_ID.has(rule.id)) throw new PluginError(`${p}: duplicate rule id ${rule.id}`);
      seen.add(rule.id);
      rules.push(rule);
    }
  }
  return rules;
}

