# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

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
