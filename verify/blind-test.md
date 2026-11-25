# Blind test

The field test ([field-test.md](field-test.md)) shows how the tool does on 36 projects. The blind test checks it on projects it had never been run on, picked by a rule fixed before looking.

## How the projects were picked

1. GitHub repository search (sorted by last update) for: `midnight compact language:TypeScript`, `midnight compact contract`, `midnightntwrk`, `midnight network zk dapp`, `compact midnight privacy`, `midnight hackathon compact`.
2. Removed: Midnight Foundation and OpenZeppelin repositories (they are the corpus), tools without contracts (editors, linters, SDKs, docs), and the 36 field-test projects.
3. Shuffled with the fixed seed `20261125` (Python `random.Random`), and kept the first 30 that contain at least one `.compact` file.

The list of repositories and commits is committed to by hash (`projectsCommitment` in [blind-verdicts.json](blind-verdicts.json)) and published once the projects have been told.

## What it surfaced, and what changed

Each change has a look-alike case in the regression suite, so it stays in place.

| Pattern | Now |
| --- | --- |
| Minified bundles and webpack/Next.js chunks | are no longer scanned |
| HTML written with innerHTML | MS118 is a low-severity hygiene note |
| Scripts named test-*.js / test_*.js | are treated as tests |
| Witnesses used as map keys, fields named …Revealed, numeric fields of records | are no longer taken for secrets (MS007) |
| Masks and plain-word or non-ASCII UI labels | are no longer taken for passwords (MS115) |
| The same finding twice on one line | is reported once |
| Read-only queries that compare an argument with the admin | are not access checks (MS036) |
| Counter updates (x = x + 1) | are not overwrites (MS035) |
| Names like MIN_PASSPHRASE_LENGTH | are rules about a secret, not secrets (MS110, MS102) |
| process.env.SEED ? … : … | is a presence check, not a logged value (MS102) |
| …IdSeed names and await service.method() results | are not secrets made from public data (MS120) |
| A parameter that shares a name with a Math.random() value | is no longer followed (MS105) |
| Midnight's privateStateProvider | is not browser storage (MS104) |
| Tags that mix in a varying public input (a case id, an app id) | do not link actions (MS010) |
| Copies of the Compact standard library | are skipped |

Real issues were found in 17 of the 30 projects, among them owner checks that compare the public owner id with a parameter (MS036), Merkle paths not tied to the caller (MS009), and witness values written to state unchecked (MS002).

## Second blind test

The second sample was fixed before the first changes were made: the remaining candidates of the same shuffled list, committed to by hash (`nextSampleCommitment` in [blind-verdicts.json](blind-verdicts.json)). The first 30 of them that contain Compact code were scanned once, with the version of 2026-11-25, and every medium-or-worse finding was checked against the source. Each verdict is committed to in [blind2-verdicts.json](blind2-verdicts.json).

Real issues were found in 18 of the 30 projects, among them escrow circuits anyone could release or refund (MS036), a vault total and payout root any caller could set (MS034), private state keys made from a public key (MS120), and a category commitment whose randomness is public (MS004).

What it surfaced, and what changed (each with look-alike regression cases, including the variants that must still be reported):

| Pattern | Now |
| --- | --- |
| Public keys read from an object of secret keys, seed file paths | are not secrets (MS102) |
| A short prefix of a seed in a log | is reported as low |
| A new seed printed for the user to save | is reported as low, also when the note is printed just before it |
| Deployment-only stand-in witnesses (`deploymentWitnesses`) | are not weak implementations (MS113, MS121) |
| A helper circuit that binds the leaf to its own parameter | is left to the caller (MS009) |
| A membership query that gates nothing | is not reported; used in an assert elsewhere, it is (MS009) |
| A key derived from the caller's secret and passed through `disclose()` | still makes a repeated write idempotent (MS008) |
| A Boolean witness asserted after the caller proved its identity against the ledger | is that party's statement (MS013); an `if`, a one-branch check or a check against a parameter is still reported |
| A commitment to a 32-byte secret with public randomness | is a keyed binding (MS014); small values are still reported |
| An in-memory `Map` | is not browser storage (MS104) |
| `Math.random()` as a sort comparator | makes no value (MS105) |
| `SECRET_BYTES` in an error message | is a size (MS110) |

The next blind sample will be drawn and fixed by hash before it is run, in the same way.

## Checking the verdicts

[blind-verdicts.json](blind-verdicts.json) and [blind2-verdicts.json](blind2-verdicts.json) hold a SHA-256 commitment for each finding of each scan (the full row: repository, commit, file, line, rule, verdict, reason, and a salt). Rows are revealed once the projects have been told, and `node scripts/check-verdict.mjs` recomputes them.
