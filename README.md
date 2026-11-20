# Midnight Shield

A static analyzer for [Compact](https://docs.midnight.network) smart contracts on Midnight.
It finds security and privacy issues before you deploy, and runs locally, in CI, and with AI coding agents.

> **Status: v0.1 (early).** 6 rules, CLI, GitHub Action and SARIF output work today. Expect rule changes while false positives are tuned.
> Built as part of KR NightForce Cohort 2 (Builder track).

## Why

The Compact compiler already rejects undeclared disclosure of witness data. But a contract can compile and still be unsafe:

- A caller is "authorized" with a value the prover controls.
- A hash of a low-entropy secret (a vote, a flag, an age) is made public and can be brute-forced.
- A commitment uses public or reused randomness, so it hides nothing or links users.
- A witness is used without any constraint, so the prover can return anything.

Midnight Shield is to Midnight what Slither is to Solidity and aztec-lint is to Noir: a static analyzer that catches issues before deploy, with rules built around Midnight's privacy model.

## Quick start

Requires Node.js 20 or later.

```bash
# Run directly from GitHub (npm release coming soon)
npx github:efforthye/midnight-shield contracts/
```

Example output:

```text
examples/vulnerable.compact
  22:25    CRITICAL MS001 own-public-key-auth
           ownPublicKey() is used to authorize the caller. It is supplied by the prover, ...
  27:13    HIGH     MS003 low-entropy-hash
           This hash only covers low-entropy private values (about 1 bit of entropy), and it is made public. ...
  33:13    MEDIUM   MS002 unconstrained-witness
           Witness 'myBalance()' reaches public state here, but no assert anywhere constrains its value. ...

5 findings in 2 files (1 critical, 2 high, 1 medium, 1 low)
```

Try it on the bundled examples: [`examples/vulnerable.compact`](examples/vulnerable.compact) triggers every rule, and [`examples/safe.compact`](examples/safe.compact) is the same logic written safely.

## Rules

| ID | Rule | Severity | Finds |
| --- | --- | --- | --- |
| [MS001](docs/rules/MS001.md) | `own-public-key-auth` | Critical | `ownPublicKey()` compared to a key to authorize the caller, including through helper circuits |
| [MS002](docs/rules/MS002.md) | `unconstrained-witness` | Medium | A witness value reaches public state with no `assert` that checks it |
| [MS003](docs/rules/MS003.md) | `low-entropy-hash` | High | A hash of only low-entropy private values (vote, age, PIN) made public |
| [MS004](docs/rules/MS004.md) | `weak-commitment-randomness` | High | A commitment with constant, public, short, or reused randomness |
| [MS005](docs/rules/MS005.md) | `missing-domain-separation` | Low | A hash of private data with no constant domain tag |
| [MS006](docs/rules/MS006.md) | `missing-pragma` | Info | No `pragma language_version` |

Each rule page explains why it matters, shows a vulnerable and a fixed example, and lists what is deliberately not flagged.

## How it works

Midnight Shield parses Compact into a syntax tree (it does not use regular expressions on lines) and runs a data-flow analysis over every circuit:

- Each value is tracked by where it comes from: witnesses, private parameters, public ledger state, or constants.
- Secret entropy is estimated from types (`Boolean` = 1 bit, `Uint<16>` = 16 bits, `Bytes<32>` = 256 bits). Public and constant inputs add nothing.
- Calls to circuits in the same file are followed with the caller's arguments, so a check hidden in a helper circuit is still found, and a tag passed in by the caller is still seen.

Tested against all 146 `.compact` files in [midnight-examples](https://github.com/midnightntwrk/midnight-examples) and [OpenZeppelin Contracts for Compact](https://github.com/OpenZeppelin/compact-contracts): every file parses, and no critical, high, or medium findings are reported on that code.

## CLI options

```text
midnight-shield [paths...] [options]

  -f, --format <text|json|sarif>   Output format (default: text)
  -o, --output <file>              Write the report to a file
      --fail-on <severity>         Exit 1 if a finding is at or above this severity
                                   (default: high; "none" to never fail)
      --min-severity <severity>    Hide findings below this severity
      --disable <MS001,MS005>      Skip rules
      --list-rules                 Print all rules
```

Exit codes: `0` no blocking findings, `1` findings at or above `--fail-on`, `2` usage error.

## GitHub Action

```yaml
# .github/workflows/midnight-shield.yml
name: Midnight Shield
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # to show results in the Security tab
    steps:
      - uses: actions/checkout@v4
      - uses: efforthye/midnight-shield@main
        with:
          path: contracts
          fail-on: high
```

Results appear in the repository's **Security > Code scanning** tab and as annotations on pull requests.

## Suppressing findings

```compact
// shield-disable-next-line MS005
const h = persistentHash<Bytes<32>>(x);

const y = persistentHash<Bytes<32>>(z); // shield-disable-line MS005

// shield-disable-file MS006   (anywhere in the file)
```

Leave out the rule ID to suppress every rule on that line.

## Using it from code

```ts
import { lintSource } from "midnight-shield";

const findings = lintSource(source, "counter.compact");
```

JSON output (`--format json`) is stable and meant for AI coding agents: run the scan, read the findings, fix, and run again.

## Development

```bash
npm install
npm test        # build + 25 rule tests
npm run demo    # scan examples/
```

## Roadmap

- [x] v0.1: parser, data-flow analysis, 6 rules, CLI, GitHub Action, SARIF, rule docs
- [ ] v0.2: agent skill for AI-assisted fixing, npm release
- [ ] More rules: missing nullifier (double use), linkable ledger updates
- [ ] TypeScript/SDK checks: remote proof server, secrets in logs
- [ ] Cross-file analysis for imported modules

## Acknowledgements

Several initial rule ideas come from [Night Check](https://github.com/CjDabrow/night-check) (MIT), a web-based Midnight code reviewer. Midnight Shield focuses on a different use case: a parser-based analyzer for local development and CI.

## License

MIT
