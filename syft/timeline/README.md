# SBOM timeline

The `timeline` package records successive SBOM generations and derives a change history from them.
It answers the recurring question "when did this dependency enter the artifact?" without making
anyone read a dozen date-named inventory files by hand.

The timeline is a **side channel**. It is fully opt-in, it never changes the SBOM a scan produces,
and using it does not change the scan's exit code.

## Recording

```console
$ syft scan dir:./app -o syft-json=app.syft.json --timeline-dir ./history
```

Each scan appends one immutable snapshot record to `./history/timeline.jsonl`. The same setting can
be used from a configuration file:

```yaml
timeline:
  dir: ./history
```

With no `timeline.dir` (or no `--timeline-dir`) nothing is written and no directory is created.

## Reading

```console
# every component, with its first appearance and each state change
$ syft timeline --dir ./history

# one component (identity key, name, <type>/<name>, namespace-qualified name, or purl)
$ syft timeline --dir ./history --component lodash
$ syft timeline --dir ./history --component npm/lodash
$ syft timeline --dir ./history --component pkg:npm/lodash

# what changed inside a time window
$ syft timeline --dir ./history --since 2026-01-01 --until 2026-06-01

# two views of the same history
$ syft timeline --dir ./history -o timeline-components   # per component
$ syft timeline --dir ./history -o timeline-timepoints   # per point in time
$ syft timeline --dir ./history -o timeline-json         # both, plus problems
```

Both views are rendered from the same list of `Change` values, so they always agree.

## Backfilling history

Existing SBOMs can be imported in any format syft can decode:

```console
$ syft timeline --dir ./history \
    --import 2026-01-15.syft.json \
    --import 2026-02-15.spdx.json \
    --import 2026-03-15.cdx.json
```

* The import order does not matter: the journal is kept sorted by timestamp and the timeline is
  derived from record timestamps.
* Importing the same document twice is a no-op: a snapshot's identity is a hash of its timestamp,
  source, and component state.
* When two **different** snapshots share a timestamp, the read reports a conflict and names the
  authoritative snapshot (the smallest snapshot identity) and the ones it superseded.
* `--import-at 2026-01-15` sets the timestamp explicitly; otherwise each file's modification time
  is used.

## What counts as a change

Component identity is defined once (`timeline.IdentityKey`) and used for deduplication, imports, and
transition detection. A component is identified by its purl type, namespace, and name (falling back
to the syft package type and name when there is no purl). Version and source are **not** part of the
identity, so:

| event | recorded as |
| --- | --- |
| component appears for the first time | `added` |
| component disappears | `removed` |
| component reappears after an absence | `added` (with the previous version) |
| version changes | `changed` |
| repository/registry changes | `changed`, with `fromSource`/`toSource` |
| artifact is rebuilt with identical contents | nothing |

The last row is what keeps a rebuild from looking like a full removal and re-addition: the
timeline only records state changes, and a snapshot with the same component state produces no
`Change` at all.

The `source` of a component is a repository or registry, normalized to one string:

* cataloger metadata (`Resolved`, `Source`, `Repository`, direct-URL origin, ...) is used first;
* otherwise familiar purl qualifiers (`repository_url`, `vcs_url`, `hosted_url`);
* an artifact URL (a `.tgz`, `.whl`, `.jar`, ... download link) is reduced to its registry, and a
  VCS pin (`git+https://host/repo@<ref>`) is reduced to the repository, so a version bump does not
  look like a repository change.

## Guarantees

* **One key.** Identity and diffing share `Component.Key`; there is no second notion of "the same
  package".
* **Atomic appends.** A record is written as a single newline-terminated line on an `O_APPEND`
  handle and synced. A process killed mid-write leaves at most an unterminated tail; readers ignore
  it and report it as an interrupted write, and the next append repairs it. A reader therefore sees
  either the previous complete record or the new complete record. Writers serialize on an advisory
  file lock, and the two checks an append needs (newest timestamp, whether this snapshot exists)
  read only the tail of the journal, so recording a scan does not get slower as history grows.
* **One timestamp format.** All timestamps are UTC with millisecond precision
  (`2006-01-02T15:04:05.000Z`). Inputs in other common forms are normalized on the way in.
* **No extra output by default.** The existing SBOM formats, the scan exit code, and the absence of
  extra files when the feature is off are unchanged.
* **Streaming reads.** Reading walks the journal one line at a time and keeps compact per-component
  state; `--limit` and `--until` stop work early rather than loading everything.
* **Damaged history is contained.** A corrupt line is reported with its line number and impact,
  and the rest of the timeline is still produced. A new snapshot older than the newest recorded one
  is rejected with an explanation (`ErrOutOfOrder`).
* **Unwritable history does not fail a scan.** A failure to update the history is logged as a
  warning (visible with `-v`; it does not pollute the normal output) after the SBOM has been
  written; the scan succeeds.

### Live timestamps vs. imported timestamps

A live scan (`syft scan --timeline-dir ...`) takes its timestamp while it holds the append lock, so
concurrent scans are ordered the way they actually finish. If two scans land in the same
millisecond, the second is advanced by one millisecond rather than being reported as a conflict.

Imported snapshots (`syft timeline --import ...`) keep the timestamp they were given, and the
journal is kept sorted by timestamp. Import order therefore does not matter. Only a **different**
snapshot at the **same** timestamp is a conflict, and that is the case in which the read names the
authoritative record and lists the ones it superseded.

## Example: a two-component timeline

Three daily snapshots of an application: `lodash` is bumped once, `react` once, and the middle
snapshot is a rebuild of the first with identical contents.

```console
$ syft timeline --dir ./history --import 2026-03-15.syft.json \
      --import 2026-01-15.syft.json --import 2026-02-15.syft.json
history: 3 snapshot(s), 2026-01-15T00:00:00.000Z .. 2026-03-15T00:00:00.000Z
components: 2

lodash (npm/lodash)
  first seen: 2026-01-15T00:00:00.000Z
  last seen:  2026-03-15T00:00:00.000Z (present)
  current:    4.17.21 from https://registry.npmjs.org
  2026-01-15T00:00:00.000Z  added at 4.17.20 from https://registry.npmjs.org
  2026-02-15T00:00:00.000Z  changed: 4.17.20 -> 4.17.21

react (npm/react)
  first seen: 2026-01-15T00:00:00.000Z
  last seen:  2026-03-15T00:00:00.000Z (present)
  current:    18.3.0 from https://registry.npmjs.org
  2026-01-15T00:00:00.000Z  added at 18.2.0 from https://registry.npmjs.org
  2026-03-15T00:00:00.000Z  changed: 18.2.0 -> 18.3.0
```

The imports were given in reverse order on purpose; the timeline is still chronological. The second
snapshot has no line at all for either component, because nothing changed.

Marking first appearances and version-change points on the sample:

```text
lodash  first appearance ── 2026-01-15 (4.17.20)
        version change  ── 2026-02-15 (4.17.20 -> 4.17.21)
react   first appearance ── 2026-01-15 (18.2.0)
        version change  ── 2026-03-15 (18.2.0 -> 18.3.0)
```

The same history through the time-oriented view:

```console
$ syft timeline --dir ./history -o timeline-timepoints
```
```json
{
  "snapshots": 3,
  "range": {"from": "2026-01-15T00:00:00.000Z", "to": "2026-03-15T00:00:00.000Z"},
  "timepoints": [
    {"timestamp": "2026-01-15T00:00:00.000Z", "changes": [ /* lodash added, react added */ ]},
    {"timestamp": "2026-02-15T00:00:00.000Z", "changes": [ /* lodash 4.17.20 -> 4.17.21 */ ]},
    {"timestamp": "2026-03-15T00:00:00.000Z", "changes": [ /* react 18.2.0 -> 18.3.0 */ ]}
  ]
}
```

## On-disk format

`timeline.jsonl` holds one JSON snapshot per line:

```json
{"recordVersion":1,"snapshotID":"sha256:...","timestamp":"2026-01-15T00:00:00.000Z",
 "source":{"type":"directory","id":"...","name":"...","version":""},
 "components":[{"key":"npm/lodash","name":"lodash","type":"npm","version":"4.17.20",
                "purl":"pkg:npm/lodash@4.17.20","source":"https://registry.npmjs.org"}]}
```

`snapshotID` is the content hash of the record, and records are validated against it on read, so a
tampered or truncated record is reported instead of being applied. The journal is an internal
format: read it through `syft timeline`.
