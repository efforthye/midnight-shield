# Blind test

The field test ([field-test.md](field-test.md)) measured precision on the same projects its false positives were then fixed on. That says the fixes work, not how the tool does on code it has never seen. This test is the second measurement: new projects, picked by a rule fixed in advance, scanned once with the version that existed before looking at them.

## How the projects were picked

1. GitHub repository search (sorted by last update) for: `midnight compact language:TypeScript`, `midnight compact contract`, `midnightntwrk`, `midnight network zk dapp`, `compact midnight privacy`, `midnight hackathon compact`.
2. Removed: Midnight Foundation and OpenZeppelin repositories (they are the corpus), tools without contracts (editors, linters, SDKs, docs), and the 36 field-test projects.
3. Shuffled with the fixed seed `20261125` (Python `random.Random`), and kept the first 30 that contain at least one `.compact` file. Two candidates had none and were skipped.

The 30 repositories and the exact commits scanned are listed in [blind-verdicts.json](blind-verdicts.json) under `projects`.

## First scan (before any change)

| | Findings (medium and up) | Real | False positives | Precision |
| --- | ---: | ---: | ---: | ---: |
| All 30 projects | 244 | 151 | 93 | **62%** |
| Without one minified bundle file | 216 | 151 | 65 | 70% |

This is lower than the field test's 90%, and it is the more honest number. 17 of the 30 projects had at least one real issue. One project accounts for 64 of the real findings: an "admin only" check that compares the public admin address with a parameter, repeated in every contract of the project (MS036).

By rule (first scan):

| Rule | Findings | False positives | Precision |
| --- | ---: | ---: | ---: |
| MS002 | 9 | 0 | 100% |
| MS004 | 1 | 1 | 0% |
| MS007 | 13 | 13 | 0% |
| MS008 | 8 | 1 | 88% |
| MS009 | 13 | 0 | 100% |
| MS010 | 3 | 3 | 0% |
| MS012 | 6 | 0 | 100% |
| MS013 | 3 | 0 | 100% |
| MS018 | 8 | 0 | 100% |
| MS019 | 3 | 1 | 67% |
| MS020 | 2 | 0 | 100% |
| MS028 | 3 | 0 | 100% |
| MS031 | 1 | 0 | 100% |
| MS034 | 1 | 0 | 100% |
| MS035 | 3 | 3 | 0% |
| MS036 | 68 | 4 | 94% |
| MS037 | 1 | 0 | 100% |
| MS101 | 4 | 0 | 100% |
| MS102 | 15 | 5 | 67% |
| MS104 | 10 | 8 | 20% |
| MS105 | 2 | 2 | 0% |
| MS106 | 18 | 16 | 11% |
| MS107 | 3 | 1 | 67% |
| MS109 | 1 | 1 | 0% |
| MS110 | 2 | 2 | 0% |
| MS111 | 1 | 0 | 100% |
| MS114 | 5 | 5 | 0% |
| MS115 | 8 | 6 | 25% |
| MS118 | 17 | 17 | 0% |
| MS119 | 8 | 2 | 75% |
| MS120 | 4 | 2 | 50% |

## What the false positives were, and what changed

| Cause | Rules | Fix |
| --- | --- | --- |
| duplicate of the same finding on the same line (20) | MS102, MS104, MS106, MS114, MS118, MS119 | Identical findings on one line are reported once |
| HTML built from the app's own values, not attacker-controlled (14) | MS118 | MS118 is now low severity: a hygiene warning, not a vulnerability report |
| not key material: an account id, a deliberate reveal, a public seed input, or a numeric field (13) | MS007 | MS007 reads the engine: a witness used as a map key is an identifier, a field named `…Revealed` is a deliberate opening, a numeric field of a record is an amount. A parameter named like a seed and published on purpose is still reported (one case) |
| minified build output, not source (10) | MS102, MS104, MS106, MS109, MS114, MS118 | Minified bundles and webpack/Next.js chunks are skipped |
| a test script (8) | MS106, MS107 | Scripts named `test-*.js` / `test_*.js` are treated as tests, like `*.test.ts` |
| a UI label or a mask, not a password (6) | MS115 | MS115 ignores masks and plain-word or non-ASCII labels |
| a read-only permission query, not an access check (3) | MS036 | MS036 ignores circuits that change nothing |
| a counter update (x = x + 1), not an overwrite (3) | MS035 | MS035 compares only writes that replace the value |
| the message names a length rule, not the secret (2) | MS110 | Names like `MIN_PASSPHRASE_LENGTH` are rules about a secret, not secrets |
| an id seed / a service-derived value, not a secret from public data (2) | MS120 | `…IdSeed` names and `await service.method()` results are not treated as secrets made from public data |
| the tag includes the case id, so it is per case by design (2) | MS010 | MS010 ignores tags that mix in a varying public input |
| Midnight's own private state provider, not browser storage (2) | MS104 | Values stored through `privateStateProvider` are not browser storage |
| wrong cause: a parameter that shares a name with a Math.random() value (2) | MS105 | MS105 no longer follows a tainted name into a parameter or an object key |
| a copy of the Compact standard library (2) | MS004, MS019 | Copies of the standard library are skipped |
| an 'admin only' read of a value that is public on the ledger anyway (1) | MS036 | Same fix: a query guards nothing |
| logs whether an env var is set, not its value (1) | MS102 | `process.env.SEED ? … : …` is a presence check |
| revoking a credential twice is harmless (1) | MS008 | Not fixed: a judgment call the rule cannot make (one case) |
| a per-app, per-epoch nullifier: linkable within one app by design (1) | MS010 | Same MS010 fix |

Each fix has a look-alike case in the benchmark, so it stays fixed.

## After the fixes

The same 30 projects scanned with the fixed version: **153 findings, 151 real, 2 false positives**. Like the field test's second number, this is measured on the code the fixes came from, so it is not a blind number. The next blind test, on another fixed-seed sample, will say how much of it carries over.

## Checking the verdicts

[blind-verdicts.json](blind-verdicts.json) holds every first-scan finding: 113 in full (low-risk DApp findings and every false positive, with repository, commit, file and line), and 131 exploitable contract and key-handling findings as SHA-256 commitments that are revealed once the projects have been told. `node scripts/check-verdict.mjs` recomputes the revealed ones.
