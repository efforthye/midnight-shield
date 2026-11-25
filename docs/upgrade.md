# Upgrade check

```bash
npx midnight-shield upgrade v1/contract.compact v2/contract.compact
npx midnight-shield upgrade release-1.0/contracts contracts      # folders: files paired by path
```

Compares two versions of a contract and reports the changes that break the deployed contract's state, the DApps that call it, or who can call what. It is the Compact counterpart of `slither-check-upgradeability`.

## Why it matters on Midnight

A deployed contract keeps its ledger state. Its contract maintenance authority can only add, remove or replace circuit verifier keys. So "upgrading" means running circuits compiled from new source against the old state.

The compiled contract reads and writes ledger fields **by position in declaration order**, not by name. You can see this in compiler output: the generated `ledger()` accessors and circuit code address field 0, field 1, and so on. New circuits therefore see the old state through the new declaration order. Enum values are stored as their member index, so the order of enum members matters in the same way.

## What it reports

| Change | Severity | Why |
| --- | --- | --- |
| Ledger field removed | critical | The state still holds it, and every later field moves one position |
| Field inserted before existing ones | critical | Every later field reads its neighbour's old value |
| Fields reordered | critical | Each moved field reads another field's value |
| Field type changed | critical | The stored value is read as a different type |
| Enum stored in the ledger: members inserted or reordered | critical | Stored values now mean a different member |
| Struct stored in the ledger changed | critical | Stored values keep the old layout |
| Field added at the end | high | The deployed state has no value there. Verifier keys cannot add state, so this needs a new deployment and a migration |
| A circuit that checked the caller checks less (from the [access map](../README.md#access-map)) | high if it changes state or moves tokens | A guard removed by accident is the costliest upgrade bug |
| Exported circuit removed | medium | It stays callable on the deployed contract until its verifier key is removed |
| Exported circuit parameters or return type changed | medium | The verifier key and every DApp must change together |
| Witness signature changed | medium | The DApp's implementation must change with it |
| Field became sealed or unsealed | medium | Changes what circuits may do with a value fixed at deployment |
| Field renamed in place (same position and type) | low | State is fine; DApps that read it by name break |
| New witness | low | Every DApp must implement it |
| Enum members appended | low | Stored values keep their meaning |
| New exported circuit | info | Needs its verifier key inserted |
| Language version changed | info | Recompile everything with one compiler; see MS012 for `transientHash` in state |

Fields from imported modules are followed where the `import` appears, since they take positions too.

`--format markdown|json` for reports and CI. The command exits with code 1 when a change is at or above `--fail-on` (default `high`).

## Checked on real history

Comparing OpenZeppelin Contracts for Compact `v0.4.0-alpha.1` with `v0.5.0-alpha.2` reports 10 critical changes, among them `_grantedRoleNullifiers` inserted before the sealed `_instanceSalt` in `ShieldedAccessControl`, a removed `_isInitialized` in `Signer`, and a changed `Proposal` struct in `ProposalManager`. Each was confirmed in the source. These are library modules in alpha, not deployed contracts, so the changes are expected there. The point is that a contract built on them could not take the new version as a verifier-key update.

## Limits

- It compares source, not the deployed state, so it cannot tell whether a contract was deployed with a maintenance authority at all.
- A field renamed *and* moved is reported as one removal and one addition.
- Generic modules are compared by the type text as written (`Set<T>`), not by the type they are instantiated with.
