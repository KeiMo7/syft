# Output-only SBOM trimming

Syft can produce a smaller, runtime-focused component list without changing cataloging or the
component model. Trimming happens after `CreateSBOM` and before any output encoder runs. All
trimming is disabled by default.

## Configuration

Use the root-level `trim` section:

```yaml
javascript:
  include-dev-dependencies: true

trim:
  enabled: true
  business-line: payments

  default:
    categories:
      dev: true
      test: true
      build: true
    direct-only: false
    # Omit exclude-paths to use the built-in test/example/fixture path rules.
    # Set exclude-paths: [] to disable path trimming.
    classifiers:
      - category: build
        packages:
          - typescript
      - category: dev
        packages:
          - eslint
          - jest

  business-lines:
    - name: payments
      images:
        - "registry.example.com/payments/*"
      categories:
        dev: true
        test: true
        build: true
      classifiers:
        - category: build
          packages:
            - typescript
    - name: risk
      images:
        - "shared/base-image"
      categories:
        build: true
      direct-only: true
```

`categories` means "remove when true". Valid names are `build`, `dev`, and `test`. Unknown names
fail configuration loading and list the valid options. `business-line` explicitly selects one rule,
which allows the same base image to use different definitions in different deployments. Without an
explicit selection, Syft matches `images` against the source name, tags, repo digests, and user input.
If nothing matches, the `default` policy is used and the report records
`ruleSource: default-no-business-line-match`.

For a single default policy, `categories`, `exclude-paths`, `classifiers`, and `direct-only` may also
be written directly under `trim`; `trim.default` remains available when a file/rule needs to be
spelled out separately.

The built-in path exclusions are:

```text
**/test/**       **/tests/**       **/testdata/**   **/__tests__/**
**/spec/**       **/specs/**       **/example/**    **/examples/**
**/sample/**     **/samples/**     **/fixtures/**
```

Path matching uses doublestar globs against package locations. A package is removed by location only
when every recorded location matches.

`direct-only` removes components proven to be more than one dependency edge from a top-level
package. Components with no usable dependency information are retained and counted as unknown.

## External rule files and reload

Rules may live in a separate YAML file:

```yaml
trim:
  enabled: true
  rule-file: /etc/syft/trim-rules.yaml
```

The file has `default` and `business-lines` keys using the same policy shape. Before every output,
Syft reads the file digest; if it changed, the new rules are parsed, validated, and used for that
output. The report records `rulesSource`, `rulesDigest`, and `rulesReloadedAtApply`. Embedded users
can also call `Config.ReloadRules()` for an explicit synchronous reload. No process restart is
required.

## Audit metadata

Trim results are added only to the output SBOM at
`descriptor.configuration.trim` (syft-json). The scan's in-memory component model is untouched.
The report includes:

- selected business line and rule source
- policy, rule file source, and SHA-256 rule digest
- before/after/removed component counts and relationship counts
- `byCategory` and primary `byRule` distributions
- unknown category/depth counts
- warnings and fallback state

Each component is assigned at most one primary reason for counting, in category, path, depth order,
so overlapping rules never double-count the same component.

If every component would be removed, Syft retains the original component list, sets `fallback: true`,
and emits an explicit warning instead of writing an empty SBOM.

## Incomplete output

File outputs are encoded to `<path>.incomplete` and atomically renamed to `<path>` only after a
complete successful encode. If the process is interrupted, any partial artifact remains visibly
marked `.incomplete` and cannot be mistaken for a complete manifest. A previous complete file is
left untouched when a new write fails.

## Acceptance

Run:

```bash
./test/trim-acceptance/run.sh
```

The script builds a real local OCI Node image, scans it with development dependencies enabled,
produces full and trimmed syft-json SBOMs, and writes `artifacts/trim-acceptance/summary.json`.
It reports component counts, byte sizes, category/rule distributions, and an OSV comparison showing
which removed vulnerable components no longer produce matches.
