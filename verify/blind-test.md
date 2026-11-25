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

## Next blind test

The next sample is already fixed: the remaining 55 candidates of the same shuffled list, in order, are committed to by hash (`nextSampleCommitment`). The next run takes the first 30 of them that contain Compact code, scans them once with the current version, and publishes the result the same way.

## Checking the verdicts

[blind-verdicts.json](blind-verdicts.json) holds a SHA-256 commitment for each finding of the scan (the full row: repository, commit, file, line, rule, verdict, reason, and a salt). Rows are revealed once the projects have been told, and `node scripts/check-verdict.mjs` recomputes them.
