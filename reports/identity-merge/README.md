# Component identity merge

This directory holds the acceptance artifacts for the identity-merge capability: the rules that
decide when two package records describe the same component, the merged output, and a
self-describing report of every decision.

## Why

The same component is routinely discovered more than once — from a system package database, from a
language manifest, and from a binary fingerprint. When the version spellings differ (`4.2.0` vs
`v4.2`), the records were treated as different components: the SBOM listed the same component
several times, and when they *were* folded, one source's license, checksum or location silently
disappeared. The rules below replace that content-ID equality with an explicit, reported identity.

## What changed

- **New engine:** `syft/pkg/identity` — normalization, equivalence rules, merge, and a report.
- **New application layer:** `internal/identitymerge` — folds an `sbom.SBOM` in place, remapping
  relationships to the surviving entry.
- **New task:** `internal/task` `identity-merge`, ordered after relationships and before unknowns.
- **Config:** `identity-merge` (off by default) with `enabled`, `conflict-threshold`, and
  `fail-on-conflict`.
- **Serialization:** an optional `mergeInfo` on each package and an optional `identityMerge` block on
  the document. Both are omitted when merging did not run, so existing consumers and existing
  documents are unchanged. The syft-json schema was bumped `16.1.13` → `16.1.14` (an additive change).

## Identity rules

Two records are the same component when **all** of these hold:

1. **Type is equal.** Different package types are never merged. If the same name appears under two
   types, the entries are cross-referenced (`crossReferences`) instead.
2. **Name normalizes to the same value.** Normalization applies, and the report cites the rule that
   was actually needed for the pair:
   - `name.case-fold` — `Django` = `django`
   - `name.separator-fold` — `foo_bar` = `foo-bar` = `foo.bar` (runs of `-_.` collapse to `-`)
   - `name.namespace-fold` — `@angular/core` = `angular/core`
   - `name.exact` — no change was needed
3. **Version is in the same class.**
   - `version.exact` — identical strings
   - `version.semver-canonical` — `v1.2` = `1.2.0` (a spelling difference, not a conflict)
   - `version.revision-variant` — for OS package types only (`deb`, `rpm`, `apk`, `alpm`,
     `portage`), `1.2.3-1` and `1.2.3` are the same upstream component and **merge with a conflict
     mark**, retaining both values.

Any other version difference is a different component and stays independent.

## Evidence retention

A merged entry keeps the union, sorted and de-duplicated:

- every location (path, access path, layer, evidence annotation)
- every license, with its own locations and URLs
- every checksum, with the source clue that supplied it
- every external identifier (purls and CPEs)
- every source cataloger
- every member metadata payload (`metadataPayloads`), so the representative `metadata` field is not
  the only surviving description

## Conflicts are never silent

A conflict is a field whose values disagree across merged records. Every conflict is written to
`mergeInfo.conflicts` and to the report; its `resolution` is one of:

- `kept-both` — every value is retained (version revisions, checksum disagreements)
- `unresolved` — the entry is kept independent and marked `needs-confirmation`

When the conflict count exceeds `conflict-threshold`, the report sets `thresholdExceeded` and a
`warning`, and with `fail-on-conflict` the scan fails. The merged result is produced either way;
the threshold governs review, not data loss.

## Conservative non-merges

- **Missing version** → the record cannot be confirmed equivalent to anything; it stays independent
  and is marked `needs-confirmation`.
- **Contradictory purl** (the purl names a different component than the record's own fields) → two
  identity rules disagree; every member of that name is kept independent and marked
  `needs-confirmation`.
- **Different types** → never merged, but cross-referenced by component ID.

## Accounting

The report proves the arithmetic and is stable under input order:

```
inputCount - mergePairCount = outputCount      (reconciliation.balanced == true)
```

`mergePairCount` is exactly the sum of `len(group.members) - 1` over all groups. Every input record
appears in exactly one output entry.

## Reproducing

```bash
reports/identity-merge/run.sh
```

This builds syft, regenerates `output/scenarios.json` (the twelve shapes), and scans a small fixture
that contains a real duplicate (`requests` from a `dist-info/METADATA` and from a
`requirements.txt`) with merging off and on, writing `output/scan-before.json`,
`output/scan-after.json`, and `output/summary.json`.

The twelve scenarios are defined once in `syft/pkg/identity/scenarios.go`; the unit test
`TestMerge_TwelveScenarios` asserts against the same definitions that produce the report, so the two
cannot drift.

## Files

- `output/scenarios.json` — all twelve shapes: input records, merged components, and the full report
- `output/scan-before.json` — the real scan with merging off (three packages: `requests` twice, `urllib3` once)
- `output/scan-after.json` — the same scan with merging on (two packages: one merged `requests`, one unique `urllib3`)
- `output/summary.json` — before/after counts and the merge report from the real scan
