---
name: midnight-shield
description: Scan Midnight Compact contracts for security and privacy bugs with Midnight Shield, then fix the findings and re-scan until clean. Use when writing, reviewing, or changing .compact files, or when the user asks to audit or check a Midnight contract.
---

# Midnight Shield: scan, fix, re-scan

Midnight Shield is a static analyzer for Compact. It finds bugs that compile but are unsafe: fake authorization with `ownPublicKey()`, unchecked witnesses, brute-forceable hashes, weak commitments, and hashes without domain tags.

## When to run it

- After you write or edit any `.compact` file.
- Before you tell the user a contract is done or safe.
- When the user asks for a security or privacy review of Midnight code.

## Step 1: Scan

Run from the project root and read the JSON report:

```bash
npx github:efforthye/midnight-shield <contracts-dir> --format json --fail-on none
```

Each finding has `ruleId`, `severity`, `message`, `file`, `line`, `col`, `snippet`, and `docUrl`.

## Step 2: Fix, most severe first

Work through findings in order: critical, high, medium, low, info. For each one, open the rule page at `docUrl` if the fix is not obvious.

| Rule | Fix |
| --- | --- |
| MS001 `own-public-key-auth` | Never authorize with `ownPublicKey()`. Store `persistentHash([pad(32, "<app>:owner:"), sk])` on the ledger and recompute it from a secret-key witness. |
| MS002 `unconstrained-witness` | Add an `assert` that bounds or checks the witness value (range, set or Merkle membership, relation to ledger state) before it is disclosed or stored. |
| MS003 `low-entropy-hash` | Replace the hash with `persistentCommit(value, randomness)` using fresh `Bytes<32>` randomness from a witness, or mix a 32-byte secret into the hash. |
| MS004 `weak-commitment-randomness` | Use fresh 32-byte randomness from a witness for every commitment. Never use constants, ledger values, or the same salt twice. |
| MS005 `missing-domain-separation` | Add a constant tag as the first hash input, e.g. `pad(32, "<app>:<purpose>:")`, unique per purpose. |
| MS006 `missing-pragma` | Add `pragma language_version >= 0.28.0;` (or the version the project uses) at the top. |
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

Never suppress MS001 or MS003 to make a scan pass. Report them to the user instead if you cannot fix them.

## Report to the user

Summarize: how many findings before and after, what you fixed (rule, file, line), and anything left with the reason.
