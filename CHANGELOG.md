# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **MS121 weak-witness-implementation**: the contract and the DApp are read together. A witness the contract uses as commitment randomness or as a secret key, implemented in the DApp with zeros, a clock, `Math.random()` or a constant, is reported whatever its name.
- **MS034 untrusted-state-dependency**: a ledger field that any caller can set in one circuit, trusted by another circuit in a check or a token transfer (the oracle-price pattern).
- **Suppression reasons.** `// shield-disable-next-line MS005 -- why` keeps the reason with the finding: `--show-suppressed` prints it, JSON has `suppressionReason`, SARIF has the suppression's `justification`. `--require-suppression-reason` (or `"requireSuppressionReason": true`) ignores comments without one.
- **Presets.** `--preset recommended` (medium confidence and up, fail on high) for adopting in CI, `--preset strict` (everything, fail on medium, suppressions need a reason) for audits; also `"preset"` in the config file.
- **Field test** on 36 third-party Midnight projects: 90% precision on the first scan (121 of 134 medium-or-worse findings were real issues), every finding checked by hand. Results, the false positives and their fixes in `verify/field-test.md`; `scripts/corpus-sites.mjs` shows how often each core rule meets its pattern in the official code.
- Rules recognize secrets, nullifier sets and owner fields by role, not only by name: MS007 by type and use (a neutral `Bytes<32>` witness published raw), MS018 by a set that receives hashes of the caller's secret and is never checked, MS011 by comparisons in an `if`.
- Informational findings (unused code, a missing pragma) are hidden by default in the CLI and the playground, with a count of what was hidden; `--min-severity info` shows them.

### Fixed

- False positives found in the field test: MS007 on numbers named like seeds (`seedTreasury`), MS105 on `Math.random()` fallbacks and on adjectives (`randomHex`), MS103 on placeholder keys, MS113 on deploy and end-to-end script stubs, MS028 when funds leave with `sendImmediateShielded`, MS004 on two calls of the same randomness witness, MS008 on writes keyed by the caller's secret.
- MS001 reports a helper such as `assertOnlyOwner()` once, with the number of call sites, instead of once per call.
- MS102 reports a console line that asks the user to save a new seed as low severity; `logger` calls stay high.
- The GitHub Pages workflow builds and deploys in separate jobs, with `upload-pages-artifact` v4.
- The README listed MS120 in the "Why" table instead of the DApp rules table.

## [0.6.1] - 2026-11-20

### Added

- **MS120 secret-from-public-data**: a secret computed only from public values (a wallet address, a public key), so anyone can recompute it. Found in a public project, where every role's secret key was derived from the user's public coin key.
- **MS033 unsupported-language-version** and a CLI warning: files whose `pragma language_version` lies outside the tested range (Compact 0.16–0.28), and files with parts the parser skipped (MS000), are reported on stderr so a clean result is never silently partial. The README lists the supported versions.
- DApp secrets are now tracked by where the value comes from, not only by name: a variable assigned from `privateState.secretKey`, a seed or mnemonic generator, or a re-encoded secret counts as a secret in MS102, MS104, MS106, MS110, MS111, MS114, MS116 and MS117.
- The benchmark has more evasion variants and look-alike safe code for the ten core rules (MS001–MS004, MS007–MS009, MS011, MS013, MS014), with their own precision and recall table, and minimal reproductions of the real bugs found in public projects (`bench/known`). CI compiles every Compact benchmark file with the real compiler.

### Fixed

- MS009 now counts a Merkle path as bound only when its leaf is compared with a value derived from a witness; comparing it with a caller-supplied parameter does not tie it to the caller.
- MS105 no longer follows `Math.random()` through a `let` that is reassigned elsewhere (a mock value in a fallback branch), which reported the wrong cause in a public project.

## [0.6.0] - 2026-11-20

### Added

- **Privacy diff on pull requests.** `midnight-shield snapshot` saves findings and the disclosure map; `midnight-shield diff base.json head.json` shows what a change newly makes public, protections that got weaker, and new and fixed findings (`--format text|markdown|json`, `--fail-on` for new findings only). The GitHub Action comments it on every pull request and updates the same comment as you push (`pr-comment`, on by default).
- **Status badge.** `--badge <file>` writes a shields.io endpoint badge with the logo: green `verified` when the scan is clean, otherwise the most severe counts in red (critical, high), orange (medium) or yellow (low). The GitHub Action publishes it on pushes to the default branch with `badge: true`.
- **Suggested fixes.** Each finding comes with the flagged line rewritten, shown as a diff in the terminal, the Markdown report, JSON and the playground (with a Copy fix button). `--no-suggestions` hides them.
- **MS011 unguarded-auth-update**: an exported circuit changes an owner key or an admin allow-list without checking the caller. Opening a commitment (commit-reveal) is not taken as a caller check.
- **MS103 hardcoded-secret**: a seed, secret key or recovery phrase written into DApp source.
- **MS104 private-state-in-browser-storage**: private state or a secret saved to `localStorage` or `sessionStorage`.
- **MS012 transient-hash-in-state**: a `transientHash` / `transientCommit` result stored in the ledger, which Midnight does not guarantee to stay the same across upgrades.
- **MS013 witness-controlled-assert**: an `assert` that only checks a `Boolean` returned by a witness.
- **MS014 commitment-randomness-disclosed**: the randomness of a commitment made public outside a commit-reveal opening.
- **MS105 insecure-randomness**: a secret, seed, nonce or salt made with `Math.random()`.
- **MS106 secret-sent-over-network**: a seed or secret key sent with `fetch`, `axios` or another HTTP client.
- **31 more rules (51 in total).**
  - Compact, bug classes that other chains' analyzers cover: MS015 unused-witness, MS016 unused-circuit, MS017 tautological-assert, MS019 unguarded-token-send, MS020 unguarded-mint, MS022 shadowed-ledger-field, MS024 constant-condition, MS025 write-after-write, MS026 shadowed-builtin, MS027 ignored-check-result, MS028 locked-tokens, MS029 no-effect-statement, MS030 bidi-control-character (also TypeScript), MS031 field-arithmetic-overflow, MS032 unused-local.
  - Compact, Midnight privacy: MS018 nullifier-not-checked (no membership check before the insert, or a check with no insert), MS021 nullifier-matches-leaf, MS023 secret-key-as-randomness.
  - DApp: MS107 tls-verification-disabled, MS108 dynamic-code-execution, MS109 insecure-transport, MS110 secret-in-error, MS111 secret-written-to-file, MS112 postmessage-wildcard, MS113 weak-witness-randomness (a witness implementation that returns zero bytes or a clock value), MS114 secret-in-url, MS115 hardcoded-password, MS116 secret-rendered-in-ui, MS117 secret-sent-to-analytics, MS118 unsafe-html, MS119 secret-in-public-env.
- **Accuracy benchmark.** `npm run bench` reports precision and recall per rule on 123 labeled files (vulnerable, evasive variants, look-alike safe code) and lists every known miss in `bench/RESULTS.md`. The same cases run in `npm test`.
- Every heuristic rule's page has a **Known limits** section.
- Corpus verification accepts findings confirmed by hand in `verify/reviewed.json`. The first one: the official leaderboard example keeps the player's secret key in `localStorage` (MS104).

### Fixed

- Found by external reviews: MS013 now also checks `if (witness())` and witnesses passed through a helper circuit; MS014 catches randomness taken from a circuit parameter; MS007 recognizes `privKey`, `signingKey` and `spendingKey`; MS104 checks IndexedDB-style stores and `idb-keyval`; MS105 follows `Math.random()` through variables and wrappers; MS106 checks WebSocket and socket `send`; MS102 no longer reports `typeof seed`.
- MS011 also reports owner or admin fields that nothing compares yet (low confidence), so a contract whose only owner logic is `owner = disclose(k)` is no longer silent.
- MS019/MS020 no longer count an assert on parameters alone (`assert(amount <= 100)`) as a caller check.
- The parser read `default<Bytes<32>> as T` as comparisons.
- Fewer false positives found on a real project: `disclose()` only allows a value to become public, so MS007 now reports a raw secret where it is actually written to the ledger or returned, and a secret or randomness passed through `disclose()` straight into a hash or commitment is no longer reported by MS007, MS004 or MS014.

## [0.5.0] - 2026-11-20

### Added

- Playground: scan a public GitHub repository by URL (`github.com/owner/repo` or a `/tree/<branch>/<folder>` link), or open local files and folders. All files are analyzed together with imports resolved, and results are grouped by file. A repository scan can be shared as `#repo=owner/repo`.
- Library: `lintFileMap`, `memoryImportResolver`, `parseRepoUrl` and `isScannableFile` for analyzing files held in memory.
- Project logo, also used as the playground favicon and the VS Code extension icon.
- Releases are also published to GitHub Packages as `@efforthye/midnight-shield`, so the package shows on the repository page.
- Pitch deck and speaker script in `presentation/`.

### Fixed

- CI: `compact update` uses the workflow token, so the compile job no longer fails on GitHub's anonymous API rate limit.
- Playground: themed thin scrollbars, and the page no longer scrolls as a whole.

## [0.4.1] - 2026-11-20

### Changed

- Releases are published from GitHub Actions with npm Trusted Publishing (OIDC) and provenance. No npm token is stored in the repository.
- Playground: cleaner finding cards, Pretendard for text and JetBrains Mono (without ligatures) for code.
- README: install options and a web playground section with screenshots.

## [0.4.0] - 2026-11-20

### Added

- **Disclosure map** (`--print disclosures`): every point where data becomes public (`disclose()`, ledger writes, exported return values), the private inputs that flow there, and whether they are raw, hashed or committed.
- **Confidence** for every finding (high, medium, low), separate from severity. `--min-confidence` filters by it. Name-based rules report low confidence.
- **Baselines**: `--write-baseline` records current findings; `--baseline` reports only new ones. Fingerprints survive code moving to other lines.
- `--show-suppressed`, and SARIF `suppressions` for findings hidden by comments or a baseline.
- `--format markdown` report for audits and pull requests.
- `midnight-shield explain <RULE>`.
- `--fix` / `--fix-dry-run` for fixes that cannot change contract behavior (MS006).
- **Custom rules** via plugins (`--plugin`, `"plugins"` in config) with an AST visitor API. See `docs/custom-rules.md`.
- MS010 `linkable-ledger-update`: in contracts with anonymous Merkle membership, the same secret-derived identifier is published by several circuits.
- **TypeScript/JavaScript checks**: MS101 `remote-proof-server`, MS102 `secret-in-log`. Test files are skipped. `--no-sdk` turns them off.
- **Web playground** (`playground/`, published with GitHub Pages): paste a contract and see findings and the disclosure map in the browser.
- **VS Code extension** (`vscode/`): diagnostics as you type, rule links, workspace scan, disclosure map command.
- **npm package** ready to publish (`npx midnight-shield`), with a release workflow.
- Corpus verification now also scans the TypeScript/JavaScript files of both corpora (1,052 files).

### Changed

- The analysis core no longer depends on Node.js, so it runs in the browser. File-system helpers moved to `node.ts`.
- `pin` is no longer treated as a secret name (it was mostly version pins).

## [0.3.0] - 2026-11-20

### Added

- MS007 `disclosed-secret`: the raw value of a secret-named witness or parameter is made public.
- MS008 `missing-nullifier`: Merkle-authorized state change without a nullifier check.
- MS009 `unbound-merkle-path`: Merkle root checked without tying the path's leaf to the caller.
- Corpus verification (`npm run verify`): scans midnight-examples and OpenZeppelin Contracts for Compact at pinned commits and compares with a reviewed baseline.
- CI compiles the example contracts with the real Compact compiler.
- Test suite split into lexer, parser, rules, reporters, CLI, examples and fuzz tests (89 tests, about 97% line coverage). `npm run coverage` prints a coverage report.

### Changed

- Circuits are followed up to 8 calls deep (was 4).

## [0.2.0] - 2026-11-20

### Added

- Follows `import "path" prefix X_;` into other files.
- Code frames and rule links in text output.
- `midnight-shield.config.json` (`--init`, `--config`), `--ignore`, `--no-code-frame`.
- Claude Code skill in `skills/midnight-shield`.

## [0.1.0] - 2026-11-20

### Added

- Compact lexer and parser with error recovery.
- Data-flow analyzer and rules MS000 to MS006.
- CLI with text, JSON and SARIF output.
- GitHub Action with SARIF upload.
