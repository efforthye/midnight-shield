// Rule catalog. Detection logic lives in analyzer.ts; this file is the single
// source of truth for IDs, names, severities, confidence and descriptions.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * How sure the rule is that a finding is a real problem, independent of how bad
 * it would be. Rules that rely on naming or on guessing the author's intent
 * report lower confidence.
 */
export type Confidence = "high" | "medium" | "low";
export const CONFIDENCE_ORDER: Confidence[] = ["high", "medium", "low"];

export interface RuleMeta {
  id: string;
  name: string;
  severity: Severity;
  confidence: Confidence;
  summary: string;
  /** documentation link; built-in rules point to docs/rules/<id>.md */
  docUrl?: string;
  /** a safe automatic fix exists (see fixes.ts) */
  fixable?: boolean;
}

export const RULES: RuleMeta[] = [
  {
    id: "MS000",
    name: "parse-error",
    severity: "info",
    confidence: "high",
    summary: "Part of the file could not be parsed, so analysis of that part was skipped.",
  },
  {
    id: "MS001",
    name: "own-public-key-auth",
    severity: "critical",
    confidence: "high",
    summary: "ownPublicKey() is supplied by the prover, so comparing it to a stored key does not authenticate the caller.",
  },
  {
    id: "MS002",
    name: "unconstrained-witness",
    severity: "medium",
    confidence: "medium",
    summary: "A witness result reaches public state without any assert that constrains it.",
  },
  {
    id: "MS003",
    name: "low-entropy-hash",
    severity: "high",
    confidence: "medium",
    summary: "A hash of only low-entropy private values is made public and can be reversed by brute force.",
  },
  {
    id: "MS004",
    name: "weak-commitment-randomness",
    severity: "high",
    confidence: "high",
    summary: "A commitment uses constant, public, or reused randomness, so it does not hide the committed value.",
  },
  {
    id: "MS005",
    name: "missing-domain-separation",
    severity: "low",
    confidence: "medium",
    summary: "A hash has no constant domain tag, so the same input hashed for different purposes gives linkable outputs.",
  },
  {
    id: "MS006",
    name: "missing-pragma",
    severity: "info",
    confidence: "high",
    summary: "No `pragma language_version` is declared.",
    fixable: true,
  },
  {
    id: "MS007",
    name: "disclosed-secret",
    severity: "high",
    confidence: "low",
    summary: "The raw value of a secret-named witness or parameter (secret key, seed, password) is made public.",
  },
  {
    id: "MS008",
    name: "missing-nullifier",
    severity: "medium",
    confidence: "low",
    summary: "A circuit authorizes with an anonymous Merkle membership proof and changes state without a nullifier check, so the action can be repeated.",
  },
  {
    id: "MS009",
    name: "unbound-merkle-path",
    severity: "high",
    confidence: "high",
    summary: "A Merkle path's root is checked, but the path's leaf is never tied to the caller, so anyone can reuse a public path.",
  },
  {
    id: "MS010",
    name: "linkable-ledger-update",
    severity: "medium",
    confidence: "medium",
    summary: "In a contract with anonymous (Merkle) membership, the same identifier derived from a secret is published by several circuits, so observers can link those actions to one member.",
  },
  {
    id: "MS101",
    name: "remote-proof-server",
    severity: "critical",
    confidence: "medium",
    summary: "TypeScript/JavaScript: the proof server URL points to a remote host, which would see every user's private inputs.",
  },
  {
    id: "MS102",
    name: "secret-in-log",
    severity: "high",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a secret key, seed or password is passed to a log call.",
  },
];

export const RULES_BY_ID = new Map(RULES.map((r) => [r.id, r]));

export function ruleDocUrl(id: string, meta?: RuleMeta): string {
  if (meta?.docUrl) return meta.docUrl;
  return `https://github.com/efforthye/midnight-shield/blob/main/docs/rules/${id}.md`;
}
