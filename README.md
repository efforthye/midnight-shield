# Midnight Shield

A static analyzer for [Compact](https://docs.midnight.network) smart contracts on Midnight.
It finds security and privacy issues before you deploy, and runs locally, in CI, and with AI coding agents.

> **Status: Work in progress (v0.1 in development).** Features marked _planned_ are not implemented yet.
> Built as part of KR NightForce Cohort 2 (Builder track).

## Why

The Compact compiler already rejects undeclared disclosure of witness data. But a contract can compile and still be unsafe:

- A caller is "authorized" with a value the prover controls.
- A hash of a low-entropy secret (a vote, a flag, an age) is made public and can be brute-forced.
- A commitment salt is reused, so users can be linked across transactions.
- A witness is used without any constraint, so the prover can return anything.

Other ecosystems have linters for this (Slither for Solidity, aztec-lint for Noir). Midnight Shield aims to fill that gap for Midnight, with a focus on privacy rules that are specific to Midnight.

## Features

| Feature | Status |
| --- | --- |
| Parser-based analysis with data flow across circuits | planned (v0.1) |
| CLI (`npx midnight-shield`) | planned (v0.1) |
| GitHub Action with SARIF output (results in the GitHub Security tab) | planned (v0.1) |
| Per-rule config and inline ignore comments | planned (v0.1) |
| Rule docs: why it matters and how to fix it | planned (v0.1) |
| JSON output and agent skill for AI coding agents (lint, fix, re-lint) | planned (v0.2) |

## Rules (v0.1 draft)

| ID | Rule | Severity |
| --- | --- | --- |
| MS001 | `own-public-key-auth`: `ownPublicKey()` used to authorize the caller | Critical |
| MS002 | `missing-nullifier`: a one-time action can be repeated (no nullifier or spent set) | High |
| MS003 | `unconstrained-witness`: witness result used without a constraining `assert` | Medium |
| MS004 | `disclosed-witness-hash`: a bare hash of witness data is disclosed | Medium |
| MS005 | `low-entropy-hash`: a small-domain value (`Boolean`, small `Uint`, enum) is hashed instead of committed with fresh randomness | Medium |
| MS006 | `commitment-salt-reuse`: the same salt or randomness is used in more than one commitment | Medium |
| MS007 | `witness-to-ledger-flow`: witness-derived data reaches public ledger state through another circuit | Medium |
| MS008 | `missing-domain-separation`: hash or commitment without a domain prefix | Low |
| MS009 | `assert-message-leak`: ledger or witness values interpolated into an assert message | Low |
| MS010 | `missing-pragma`: no `pragma language_version` | Info |

Rules will be validated against real code ([OpenZeppelin Contracts for Compact](https://docs.openzeppelin.com/contracts-compact), [midnight-examples](https://github.com/midnightntwrk/midnight-examples)) and tuned to keep false positives low.

## Usage (planned)

```bash
# Lint a contract
npx midnight-shield contracts/

# SARIF output for CI
npx midnight-shield contracts/ --format sarif > results.sarif
```

```yaml
# .github/workflows/midnight-shield.yml
- uses: efforthye/midnight-shield@v0
  with:
    path: contracts/
```

```compact
// Ignore a rule on the next line
// shield-disable-next-line MS008
const h = persistentHash<Bytes<32>>(x);
```

## Roadmap

- [ ] v0.1 (Dec 2026): parser, 10 rules, CLI, GitHub Action, SARIF, rule docs
- [ ] v0.2: agent skill and JSON output for AI-assisted fixing
- [ ] Later: TypeScript/SDK checks (remote proof server, secrets in logs), more rules from community feedback

## Acknowledgements

Several initial rule ideas come from [Night Check](https://github.com/CjDabrow/night-check) (MIT), a web-based Midnight code reviewer. Midnight Shield focuses on a different use case: a parser-based linter for local development and CI.

## License

MIT
