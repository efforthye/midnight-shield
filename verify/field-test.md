# Field test: third-party code

The labeled benchmark ([bench/](../bench/RESULTS.md)) measures each rule on cases written for it. This field test measures the tool on code nobody wrote for it: **36 public Midnight projects** found through GitHub search (hackathon entries, tutorials, templates and libraries), scanned with default settings. Every finding of medium severity or above was read against the source and marked as a real issue or a false positive.

Projects are listed by name only where the maintainers have been told (MeshJS) or the code is the official examples. The others are counted without names until their maintainers have been contacted.

## First pass (before any changes for this test)

| | Findings (medium and up) | Real issues |
| --- | ---: | ---: |
| After the changes above | 129 | 128 |
| With the access map rules (MS035, MS036) | 131 | 130 |
| With the witness constraint rule (MS037) | 147 | 146 |
| After the first blind test | 139 | 138 |
| After the second blind test (seed prefixes and seeds printed for the user to save are now low) | 136 | 135 |
| Current version (an unchecked membership proof is now medium: supply positions that can never be withdrawn) | 137 | 136 |

The [blind tests](blind-test.md) check the tool on projects it had never seen. Every verdict above is listed in [field-verdicts.md](field-verdicts.md).

By rule (current): MS037 16 · MS102 15 · MS103 14 · MS120 13 · MS009 12 · MS104 12 · MS013 11 · MS113 8 · MS002 7 · MS118 7 · MS001 6 · MS101 6 · MS007 4 · MS008 4 · MS034 4 · MS019 3 · MS020 3 · MS036 2.

Real issues were found in 25 of the 36 projects. The ones that matter most:

- Lending, oracle and staking checks that any caller can pass (MeshJS contracts wizard, [reported](https://github.com/MeshJS/midnight-contracts-wizard/issues/1)): MS009, MS013.
- Dividend, payout and yield claims that anyone can repeat, and role keys derived from public coin keys (report pending): MS009, MS120.
- A token ledger that publishes raw secret keys as balance keys (report pending): MS007.
- Allowlist roots and pause flags that any caller can overwrite (reports pending): MS034.
- Wallet seeds and private state written to logs and `localStorage`, hardcoded seeds in scripts, zero-byte fallbacks for secrets: MS102, MS103, MS104, MS113.

## Access map on the same projects

`--print access` classifies every exported circuit by who can call it. Across the 36 projects (426 exported circuits outside modules) and the official corpus (582, test mocks included):

| | Third-party projects | Official examples and OpenZeppelin |
| --- | ---: | ---: |
| Checks the caller | 117 | 73 |
| Only checks that anyone can pass (BYPASSABLE) | 23 | 0 |
| Calls imported code that could not be read | 0 | 39 |
| Open to anyone | 286 | 470 |

Every BYPASSABLE circuit was checked against the source: all 23 are real (ownPublicKey() owner checks behind an imported Ownable module, witness results, unbound Merkle paths, and two "owner only" checks that compare the public owner id with a parameter, now MS036). Reading imported modules matters here: eight of the 23 call an `assertOnlyOwner()` whose weakness is only visible inside the module.


## Witness constraint report on the same projects

`--print witnesses` follows every witness result into the ledger, transfers and checks. Of the 226 witness values in the 36 projects (74 in the official corpus):

| Status | Third-party projects | Official examples and OpenZeppelin |
| --- | ---: | ---: |
| anchored (tied to ledger, hash, signature, membership) | 150 | 66 |
| secret (only used hashed) | 25 | 3 |
| bounded by a constant | 3 | 4 |
| CIRCULAR (only compared with other prover values) | 28 | 0 |
| FREE (reaches state or a transfer unchecked) | 20 | 1 |

The 28 circular values are the 16 new MS037 findings (all real: "prove your rating is at least the threshold" with the rating from a witness, a salary band and a jurisdiction checked only against parameters, a membership secret compared with a parameter) and the Boolean witness asserts MS013 already reports. MS037 was the first rule to see the first group: no other rule looks at a check whose inputs never touch state.


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
