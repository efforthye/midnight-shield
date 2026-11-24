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

/** Compact language versions the parser is tested against (the corpus and the examples). */
export const SUPPORTED_LANGUAGE = { min: "0.16", max: "0.28" } as const;

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
    id: "MS011",
    name: "unguarded-auth-update",
    severity: "high",
    confidence: "medium",
    summary: "An exported circuit changes a ledger field used to authorize callers (an owner key, an admin set) without checking who is calling, so anyone can take it over.",
  },
  {
    id: "MS012",
    name: "transient-hash-in-state",
    severity: "medium",
    confidence: "high",
    summary: "A transientHash or transientCommit result is stored in the ledger, but transient hashes are not guaranteed to stay the same across upgrades.",
  },
  {
    id: "MS013",
    name: "witness-controlled-assert",
    severity: "high",
    confidence: "high",
    summary: "An assert checks only a Boolean witness, which the prover chooses, so it enforces nothing.",
  },
  {
    id: "MS014",
    name: "commitment-randomness-disclosed",
    severity: "high",
    confidence: "medium",
    summary: "The randomness of a commitment is made public, so anyone can open the commitment by trying candidate values.",
  },
  {
    id: "MS015",
    name: "unused-witness",
    severity: "info",
    confidence: "high",
    summary: "A witness is declared but never called; often a sign of a missing check.",
  },
  {
    id: "MS016",
    name: "unused-circuit",
    severity: "info",
    confidence: "high",
    summary: "A circuit that is not exported is never called, so it is dead code.",
  },
  {
    id: "MS017",
    name: "tautological-assert",
    severity: "medium",
    confidence: "high",
    summary: "An assert can never fail (assert(true), x == x, an unsigned value >= 0), so it checks nothing.",
  },
  {
    id: "MS018",
    name: "nullifier-not-checked",
    severity: "high",
    confidence: "medium",
    summary: "A value is added to a nullifier set without first checking that it is not already there, so it can be used again.",
  },
  {
    id: "MS019",
    name: "unguarded-token-send",
    severity: "high",
    confidence: "medium",
    summary: "An exported circuit sends tokens and checks nothing, so anyone can move the contract's funds.",
  },
  {
    id: "MS020",
    name: "unguarded-mint",
    severity: "high",
    confidence: "medium",
    summary: "An exported circuit mints tokens and checks nothing, so anyone can mint any amount.",
  },
  {
    id: "MS021",
    name: "nullifier-matches-leaf",
    severity: "high",
    confidence: "medium",
    summary: "A nullifier is built from the same tag and inputs as a Merkle leaf, so it reveals which member acted.",
  },
  {
    id: "MS022",
    name: "shadowed-ledger-field",
    severity: "low",
    confidence: "high",
    summary: "A parameter or local constant has the same name as a ledger field and hides it.",
  },
  {
    id: "MS023",
    name: "secret-key-as-randomness",
    severity: "high",
    confidence: "medium",
    summary: "A long-term secret key is used as commitment randomness, so opening the commitment reveals the key.",
  },
  {
    id: "MS024",
    name: "constant-condition",
    severity: "medium",
    confidence: "high",
    summary: "An if on a constant, or assert(false): one branch is dead or the circuit always fails.",
  },
  {
    id: "MS025",
    name: "write-after-write",
    severity: "medium",
    confidence: "high",
    summary: "A ledger field is written twice in a row with no read in between, so the first write has no effect.",
  },
  {
    id: "MS026",
    name: "shadowed-builtin",
    severity: "low",
    confidence: "high",
    summary: "A circuit, witness, parameter or local hides a standard-library name such as disclose or persistentHash.",
  },
  {
    id: "MS027",
    name: "ignored-check-result",
    severity: "high",
    confidence: "high",
    summary: "A Boolean check (a member test, a helper returning Boolean) is called but its result is thrown away.",
  },
  {
    id: "MS028",
    name: "locked-tokens",
    severity: "medium",
    confidence: "medium",
    summary: "The contract receives tokens but no circuit sends any out, so deposits are locked.",
  },
  {
    id: "MS029",
    name: "no-effect-statement",
    severity: "low",
    confidence: "high",
    summary: "A statement computes a value and does nothing with it.",
  },
  {
    id: "MS030",
    name: "bidi-control-character",
    severity: "high",
    confidence: "high",
    summary: "Compact and TypeScript: an invisible text-direction character can make code read differently from how it runs (Trojan Source).",
  },
  {
    id: "MS031",
    name: "field-arithmetic-overflow",
    severity: "high",
    confidence: "medium",
    summary: "Arithmetic on a Field ledger value wraps around silently instead of failing.",
  },
  {
    id: "MS032",
    name: "unused-local",
    severity: "info",
    confidence: "high",
    summary: "A local constant is computed but never used.",
  },
  {
    id: "MS033",
    name: "unsupported-language-version",
    severity: "low",
    confidence: "high",
    summary: "The pragma asks for a Compact language version outside the range Midnight Shield is tested with, so new syntax may be misread.",
  },
  {
    id: "MS034",
    name: "untrusted-state-dependency",
    severity: "high",
    confidence: "medium",
    summary: "A ledger field that any caller can set is trusted by another circuit in a check or a token transfer.",
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
  {
    id: "MS103",
    name: "hardcoded-secret",
    severity: "critical",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a seed, secret key or recovery phrase is written into the source as a literal.",
  },
  {
    id: "MS104",
    name: "private-state-in-browser-storage",
    severity: "high",
    confidence: "medium",
    summary: "TypeScript/JavaScript: private state or a secret is saved to localStorage or sessionStorage, unencrypted and readable by any script on the page.",
  },
  {
    id: "MS105",
    name: "insecure-randomness",
    severity: "high",
    confidence: "medium",
    summary: "TypeScript/JavaScript: Math.random() is used to make a secret, seed, nonce, salt or commitment randomness.",
  },
  {
    id: "MS106",
    name: "secret-sent-over-network",
    severity: "high",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a secret key, seed or password is sent in a network request.",
  },
  {
    id: "MS107",
    name: "tls-verification-disabled",
    severity: "high",
    confidence: "high",
    summary: "TypeScript/JavaScript: TLS certificate checks are turned off.",
  },
  {
    id: "MS108",
    name: "dynamic-code-execution",
    severity: "high",
    confidence: "medium",
    summary: "TypeScript/JavaScript: eval, new Function or a string passed to setTimeout runs a string as code.",
  },
  {
    id: "MS109",
    name: "insecure-transport",
    severity: "medium",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a remote indexer or node is reached over unencrypted http:// or ws://.",
  },
  {
    id: "MS110",
    name: "secret-in-error",
    severity: "medium",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a secret key, seed or password is put into an error message.",
  },
  {
    id: "MS111",
    name: "secret-written-to-file",
    severity: "medium",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a secret key, seed or password is written to a file unencrypted.",
  },
  {
    id: "MS112",
    name: "postmessage-wildcard",
    severity: "medium",
    confidence: "high",
    summary: "TypeScript/JavaScript: postMessage sends data to any origin (\"*\").",
  },
  {
    id: "MS113",
    name: "weak-witness-randomness",
    severity: "critical",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a witness implementation returns zero bytes or a clock value where the contract expects secret randomness.",
  },
  {
    id: "MS114",
    name: "secret-in-url",
    severity: "high",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a secret is put into the page URL, query string or browser history.",
  },
  {
    id: "MS115",
    name: "hardcoded-password",
    severity: "high",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a password or passphrase (for example for the private state store) is written into the source.",
  },
  {
    id: "MS116",
    name: "secret-rendered-in-ui",
    severity: "medium",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a secret is rendered on screen in JSX.",
  },
  {
    id: "MS117",
    name: "secret-sent-to-analytics",
    severity: "high",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a secret is passed to an analytics or error-tracking call.",
  },
  {
    id: "MS118",
    name: "unsafe-html",
    severity: "medium",
    confidence: "medium",
    summary: "TypeScript/JavaScript: HTML from a variable is written into the page (innerHTML, dangerouslySetInnerHTML, document.write).",
  },
  {
    id: "MS119",
    name: "secret-in-public-env",
    severity: "critical",
    confidence: "high",
    summary: "TypeScript/JavaScript: a secret is read from a VITE_/NEXT_PUBLIC_/REACT_APP_ variable, which the bundler ships to every visitor.",
  },
  {
    id: "MS120",
    name: "secret-from-public-data",
    severity: "high",
    confidence: "medium",
    summary: "TypeScript/JavaScript: a secret is computed only from public values such as an address or a public key, so anyone can recompute it.",
  },
  {
    id: "MS121",
    name: "weak-witness-implementation",
    severity: "critical",
    confidence: "high",
    summary: "Contract and DApp together: a witness the contract uses as commitment randomness or a secret key is implemented with zeros, a clock, Math.random() or a constant.",
  },
];

export const RULES_BY_ID = new Map(RULES.map((r) => [r.id, r]));

export function ruleDocUrl(id: string, meta?: RuleMeta): string {
  if (meta?.docUrl) return meta.docUrl;
  return `https://github.com/efforthye/midnight-shield/blob/main/docs/rules/${id}.md`;
}
