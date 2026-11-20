// A status badge in the shields.io "endpoint" format. The GitHub Action writes
// this JSON on every push, and the README shows it through
// https://img.shields.io/endpoint?url=<raw URL of the JSON>.

import type { Finding } from "./linter.js";
import { SEVERITY_ORDER, type Severity } from "./rules.js";

export interface BadgeJson {
  schemaVersion: 1;
  label: string;
  message: string;
  color: string;
  logoSvg: string;
}

/** The project logo in white, sized for a badge. */
const LOGO =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><mask id="m"><rect width="64" height="64" fill="#fff"/><circle cx="38.5" cy="25.5" r="11.5" fill="#000"/></mask><path d="M32 4.5C37.5 7.2 45.5 9.3 52.6 10.2C54.8 10.5 56 11.9 56 14.1V29C56 43.6 46.4 54.3 32 59.5C17.6 54.3 8 43.6 8 29V14.1C8 11.9 9.2 10.5 11.4 10.2C18.5 9.3 26.5 7.2 32 4.5Z" fill="none" stroke="#fff" stroke-width="5" stroke-linejoin="round"/><circle cx="31" cy="32" r="14" fill="#fff" mask="url(#m)"/></svg>';

// red for anything that should block a deploy, orange and yellow for the rest
const COLOR: Record<Severity, string> = { critical: "red", high: "red", medium: "orange", low: "yellow", info: "yellow" };

export function badgeJson(all: Finding[]): BadgeJson {
  const findings = all.filter((f) => !f.suppressed);
  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n > 0);
  const worst = counts[0]?.[0];
  // a badge has little room: show the two most severe groups
  const message = counts.length ? counts.slice(0, 2).map(([s, n]) => `${n} ${s}`).join(", ") + (counts.length > 2 ? " +" : "") : "verified";
  return { schemaVersion: 1, label: "midnight shield", message, color: worst ? COLOR[worst] : "brightgreen", logoSvg: LOGO };
}
