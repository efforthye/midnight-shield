# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Privacy diff on pull requests.** `midnight-shield snapshot` saves findings and the disclosure map; `midnight-shield diff base.json head.json` shows what a change newly makes public, protections that got weaker, and new and fixed findings (`--format text|markdown|json`, `--fail-on` for new findings only). The GitHub Action comments it on every pull request and updates the same comment as you push (`pr-comment`, on by default).
- **Status badge.** `--badge <file>` writes a shields.io endpoint badge (`no issues`, or the most severe counts, colored by severity, with the logo). The GitHub Action publishes it on pushes to the default branch with `badge: true`.
- **Suggested fixes.** Each finding comes with the flagged line rewritten, shown as a diff in the terminal, the Markdown report, JSON and the playground (with a Copy fix button). `--no-suggestions` hides them.
- **MS011 unguarded-auth-update**: an exported circuit changes an owner key or an admin allow-list without checking the caller.
- **MS103 hardcoded-secret**: a seed, secret key or recovery phrase written into DApp source.
- **MS104 private-state-in-browser-storage**: private state or a secret saved to `localStorage` or `sessionStorage`.
- Corpus verification accepts findings confirmed by hand in `verify/reviewed.json`. The first one: the official leaderboard example keeps the player's secret key in `localStorage` (MS104).

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
