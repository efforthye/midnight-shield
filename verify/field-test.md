# Field test: third-party code

The labeled benchmark ([bench/](../bench/RESULTS.md)) measures each rule on cases written for it. This field test measures the tool on code nobody wrote for it: **36 public Midnight projects** found through GitHub search (hackathon entries, tutorials, templates and libraries), scanned with default settings. Every finding of medium severity or above was read against the source and marked as a real issue or a false positive.

Projects are listed by name only where the maintainers have been told (MeshJS) or the code is the official examples. The others are counted without names until their maintainers have been contacted.

## First pass (before any changes for this test)

| | Findings (medium and up) | Real issues | False positives | Precision |
| --- | ---: | ---: | ---: | ---: |
| First scan | 134 | 121 | 13 | **90%** |

This is the number to quote: the tool had not been tuned on this code.

The 13 false positives, and what changed so they do not recur:

| Rule | Count | What it was | Fix |
| --- | ---: | --- | --- |
| MS113 | 3 | Zero-byte witness stubs in deploy and end-to-end scripts that never run the circuits | MS113 skips `deploy*`, `e2e*` scripts |
| MS105 | 2 | `Math.random()` only in the `else` branch of a `crypto.getRandomValues` check | Fallback branches are skipped |
| MS105 | 2 | Reported a secret derived from a public address as weak randomness | New rule MS120 reports the real cause |
| MS105 | 1 | `randomHex` for a mock contract address | "random" on its own no longer counts as a secret name |
| MS103 | 1 | A placeholder key (`a1b2c3d4…` repeated) | Repeated and sequential placeholders are skipped |
| MS007 | 1 | `seedTreasury`, a starting balance (a number), read as a seed | MS007 now needs a key-like type (bytes or field), not `Uint` |
| MS028 | 1 | Funds sent with `sendImmediateShielded`, which the rule did not know | All standard-library send and mint circuits added |
| MS004 | 1 | Two calls of the same randomness witness taken as reused randomness | Separate witness calls count as separate values |
| MS002 | 1 | A file that is not valid Compact (no parentheses around `assert`) | None: the file does not compile |

Also changed: an `assertOnlyOwner()` helper called from twelve circuits was reported twelve times (all correct, but one bug); MS001 now reports it once with the number of call sites.

## Now (same code, current version)

| | Findings (medium and up) | Real issues | False positives |
| --- | ---: | ---: | ---: |
| After the fixes above | 129 | 128 | 1 (the invalid file) |

This second number is measured on the same code the fixes came from, so it shows the fixes work, not how the tool does on new code. The next field test, on projects not in this set, will say that.

By rule (current): MS102 15 · MS103 14 · MS120 13 · MS009 12 · MS104 12 · MS013 11 · MS113 8 · MS002 7 · MS118 7 · MS001 6 · MS101 6 · MS007 4 · MS008 4 · MS034 4 · MS019 3 · MS020 3.

Real issues were found in 25 of the 36 projects. The ones that matter most:

- Lending, oracle and staking checks that any caller can pass (MeshJS contracts wizard, [reported](https://github.com/MeshJS/midnight-contracts-wizard/issues/1)): MS009, MS013.
- Dividend, payout and yield claims that anyone can repeat, and role keys derived from public coin keys (report pending): MS009, MS120.
- A token ledger that publishes raw secret keys as balance keys (report pending): MS007.
- Allowlist roots and pause flags that any caller can overwrite (reports pending): MS034.
- Wallet seeds and private state written to logs and `localStorage`, hardcoded seeds in scripts, zero-byte fallbacks for secrets: MS102, MS103, MS104, MS113.

## Why the official code has no high findings

The corpus run (official examples and OpenZeppelin Contracts for Compact, 1,052 files) finds nothing above medium except reviewed demo code. That is partly because the code is careful, and partly because some patterns barely occur in it. How often each core rule had something to decide on, across the 146 Compact files:

| Pattern the rule decides on | Places in the corpus |
| --- | ---: |
| MS001 ownPublicKey() used | 7 |
| MS002 witness calls | 111 |
| MS004/MS014 commitments | 8 |
| MS007 secret-typed witnesses | 29 |
| MS008/MS009 Merkle root checks | 3 |
| MS009 leaves bound to the caller | 3 |
| MS011/MS034 exported circuits that write state | 208 |
| MS013 Boolean witnesses | 0 |
| MS018 nullifier-style set checks | 70 |
| MS019/MS020 token sends and mints | 44 |


So the official corpus says a lot about false positives for authorization, token and nullifier rules (hundreds of places, no false alarms), but little about MS013 (no Boolean witnesses at all) or MS009 (three Merkle root checks). Those rules are measured on third-party code above and on the benchmark.

Reproduce the counts with `node scripts/corpus-sites.mjs` after `npm run verify`.
