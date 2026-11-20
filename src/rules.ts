// Rule catalog. Detection logic lives in analyzer.ts; this file is the single
// source of truth for IDs, names, severities and descriptions.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface RuleMeta {
  id: string;
  name: string;
  severity: Severity;
  summary: string;
}

export const RULES: RuleMeta[] = [
  {
    id: "MS000",
    name: "parse-error",
    severity: "info",
    summary: "Part of the file could not be parsed, so analysis of that part was skipped.",
  },
  {
    id: "MS001",
    name: "own-public-key-auth",
    severity: "critical",
    summary: "ownPublicKey() is supplied by the prover, so comparing it to a stored key does not authenticate the caller.",
  },
  {
    id: "MS002",
    name: "unconstrained-witness",
    severity: "medium",
    summary: "A witness result reaches public state without any assert that constrains it.",
  },
  {
    id: "MS003",
    name: "low-entropy-hash",
    severity: "high",
    summary: "A hash of only low-entropy private values is made public and can be reversed by brute force.",
  },
  {
    id: "MS004",
    name: "weak-commitment-randomness",
    severity: "high",
    summary: "A commitment uses constant, public, or reused randomness, so it does not hide the committed value.",
  },
  {
    id: "MS005",
    name: "missing-domain-separation",
    severity: "low",
    summary: "A hash has no constant domain tag, so the same input hashed for different purposes gives linkable outputs.",
  },
  {
    id: "MS007",
    name: "disclosed-secret",
    severity: "high",
    summary: "The raw value of a secret-named witness or parameter (secret key, seed, password) is made public.",
  },
  {
    id: "MS008",
    name: "missing-nullifier",
    severity: "medium",
    summary: "A circuit authorizes with an anonymous Merkle membership proof and changes state without a nullifier check, so the action can be repeated.",
  },
  {
    id: "MS009",
    name: "unbound-merkle-path",
    severity: "high",
    summary: "A Merkle path's root is checked, but the path's leaf is never tied to the caller, so anyone can reuse a public path.",
  },
  {
    id: "MS006",
    name: "missing-pragma",
    severity: "info",
    summary: "No `pragma language_version` is declared.",
  },
];

export const RULES_BY_ID = new Map(RULES.map((r) => [r.id, r]));

export function ruleDocUrl(id: string): string {
  return `https://github.com/efforthye/midnight-shield/blob/main/docs/rules/${id}.md`;
}
