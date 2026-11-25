---
name: midnight-shield
description: Scan Midnight Compact contracts for security and privacy bugs with Midnight Shield, then fix the findings and re-scan until clean. Use when writing, reviewing, or changing .compact files, or when the user asks to audit or check a Midnight contract.
---

# Midnight Shield: scan, fix, re-scan

Midnight Shield is a static analyzer for Compact. It finds bugs that compile but are unsafe: fake authorization with `ownPublicKey()`, unchecked witnesses, brute-forceable hashes, weak commitments, hashes without domain tags, owner changes without a caller check, and, in DApp code, remote proof servers and leaked seeds.

## When to run it

- After you write or edit any `.compact` file.
- Before you tell the user a contract is done or safe.
- When the user asks for a security or privacy review of Midnight code.

## Step 1: Scan

Run from the project root and read the JSON report:

```bash
npx midnight-shield <contracts-dir> --format json --fail-on none
```

Each finding has `ruleId`, `severity`, `confidence`, `message`, `file`, `line`, `col`, `snippet`, `docUrl` and, for most rules, a `suggestion` (`before` and `after` lines and a `note`). Treat `low` confidence findings as questions to check, not certain bugs.

To see everything the contract makes public, run `--print disclosures`. Any `RAW` row is private data published as is: check that it is meant to be public.

For an audit-style review, also run:

- `--print access`: who can call each exported circuit, what it changes and how its checks hold up. A `BYPASSABLE` circuit has only checks the prover controls.
- `--print witnesses`: every prover-chosen value, where it goes and what constrains it. `CIRCULAR` and `FREE` values are the ones to fix.
- `midnight-shield upgrade old/ new/` before changing a deployed contract: ledger fields are stored by position, so inserting, removing or reordering one breaks the existing state.

## Step 2: Fix, most severe first

Work through findings in order: critical, high, medium, low, info. For each one, start from `suggestion`: it rewrites the flagged line, with placeholders such as `myapp` for names you must choose from the project (a domain tag, a witness). Adapt it to the code, and open the rule page at `docUrl` if the fix is not obvious.

| Rule | Fix |
| --- | --- |
| MS001 `own-public-key-auth` | Never authorize with `ownPublicKey()`. Store `persistentHash([pad(32, "<app>:owner:"), sk])` on the ledger and recompute it from a secret-key witness. |
| MS002 `unconstrained-witness` | Add an `assert` that bounds or checks the witness value (range, set or Merkle membership, relation to ledger state) before it is disclosed or stored. |
| MS003 `low-entropy-hash` | Replace the hash with `persistentCommit(value, randomness)` using fresh `Bytes<32>` randomness from a witness, or mix a 32-byte secret into the hash. |
| MS004 `weak-commitment-randomness` | Use fresh 32-byte randomness from a witness for every commitment. Never use constants, ledger values, or the same salt twice. |
| MS005 `missing-domain-separation` | Add a constant tag as the first hash input, e.g. `pad(32, "<app>:<purpose>:")`, unique per purpose. |
| MS007 `disclosed-secret` | Never disclose a secret key, seed, or password. Publish `persistentHash([pad(32, "<app>:id:"), sk])` instead. |
| MS008 `missing-nullifier` | Derive a nullifier `persistentHash([pad(32, "<app>:<action>:"), sk])`, `assert(!used.member(n))`, then `used.insert(n)`. |
| MS009 `unbound-merkle-path` | Add `assert(disclose(path.leaf == deriveLeaf(secretKey())), "...")` next to the `checkRoot` call. |
| MS010 `linkable-ledger-update` | Give each circuit's published identifier its own domain tag (and a per-action value if needed). |
| MS101 `remote-proof-server` | Point the proof server at `http://localhost:6300` (or an env variable that defaults to it). |
| MS102 `secret-in-log` | Remove the secret from the log call, or log a derived public value. |
| MS006 `missing-pragma` | Run `--fix`, or add `pragma language_version >= 0.28.0;` at the top. |
| MS000 `parse-error` | Not a bug in the contract. Tell the user the analyzer skipped that part. |

Keep each fix minimal and keep the circuit's behavior the same. If a fix changes the contract's interface (new witness, new ledger field), say so to the user, because the TypeScript side must be updated too.

## Step 3: Re-scan

Run the scan again. Repeat until there are no critical, high, or medium findings, then report what changed.

## Suppressing a finding

Only suppress when the code is intentionally that way, and say why in the same comment:

```compact
// shield-disable-next-line MS005 -- tag is supplied by every caller
return persistentHash<Vector<2, Bytes<32>>>([tag, sk]);
```

Never suppress MS001, MS003, MS007 or MS009 to make a scan pass. Report them to the user instead if you cannot fix them.

## Report to the user

Summarize: how many findings before and after, what you fixed (rule, file, line), and anything left with the reason.
