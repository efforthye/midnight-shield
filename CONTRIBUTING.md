# Contributing

Thanks for helping make Midnight contracts safer.

## Reporting a false positive or a missed bug

Open an issue with:

- a minimal `.compact` snippet,
- what Midnight Shield reported (or did not report),
- what you expected and why.

False positives are treated as bugs.

## Development

```bash
npm install
npm test          # build and run all tests
npm run coverage  # tests with a coverage report
npm run verify    # scan real Compact code and compare with the baseline
npm run demo      # scan examples/
```

## Adding or changing a rule

1. Add the rule to `src/rules.ts` (ID, name, severity, summary).
2. Implement detection in `src/analyzer.ts`.
3. Add tests to `test/rules.test.ts`: at least one case that must be flagged and one that must not.
4. Add a case to `examples/vulnerable.compact`, and make sure `examples/safe.compact` stays clean.
5. Write `docs/rules/MSxxx.md`: what it finds, why it matters, an example, the fix, and what is not flagged.
6. Run `npm run verify`. If counts change, check every new finding by hand. Only then update the baseline with `npm run verify -- --update`, and explain the change in the pull request.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/), e.g. `feat(analyzer): ...`, `fix(parser): ...`, `docs(rules): ...`.

## Releasing

1. Add the changes under `## [Unreleased]` in `CHANGELOG.md` as you go.
2. Release with two commands:

   ```bash
   npm version patch      # or minor for new features
   git push --follow-tags
   ```

`npm version` updates `package.json`, the version in `src/reporters.ts` and the changelog heading, then commits and tags. Pushing the tag runs the Release workflow, which tests, publishes to npm (Trusted Publishing, with provenance), creates the GitHub release with that version's changelog notes, and publishes to GitHub Packages.
