#!/usr/bin/env bash
# Regenerates the identity-merge acceptance artifacts under reports/identity-merge/.
#
# It runs two things:
#   1. the twelve-scenario engine report (scenarios.json), produced by the identity package test
#      with SYFT_UPDATE_IDENTITY_ARTIFACTS=1
#   2. a real end-to-end scan of a small directory that contains a genuine duplicate (the same
#      Python distribution cataloged from its METADATA file and again from a requirements.txt),
#      captured with the merge disabled and enabled so the before/after is visible
#
# Usage: reports/identity-merge/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/reports/identity-merge/output"
BIN="${TMPDIR:-/tmp}/syft-identity-merge"
export PATH="${GO_BIN_DIR:-/home/wll/go-sdk/bin}:$PATH"

cd "$ROOT"
mkdir -p "$OUT"

echo "==> building syft"
go build -o "$BIN" ./cmd/syft

echo "==> generating twelve-scenario report"
SYFT_UPDATE_IDENTITY_ARTIFACTS=1 go test ./syft/pkg/identity/ -run TestGenerateScenarioReport -count=1

echo "==> building the end-to-end fixture"
FIXTURE="${TMPDIR:-/tmp}/syft-identity-merge-fixture"
rm -rf "$FIXTURE"
mkdir -p "$FIXTURE/site-packages/requests-2.22.0.dist-info" "$FIXTURE/vendor"
cat > "$FIXTURE/site-packages/requests-2.22.0.dist-info/METADATA" <<'EOF'
Metadata-Version: 2.1
Name: requests
Version: 2.22.0
Author: Kenneth Reitz
License: Apache-2.0
EOF
cat > "$FIXTURE/vendor/requirements.txt" <<'EOF'
requests==2.22.0
urllib3==1.25.11
EOF

CONFIG="${TMPDIR:-/tmp}/syft-identity-merge.yaml"
cat > "$CONFIG" <<'EOF'
identity-merge:
  enabled: true
  conflict-threshold: 100
EOF

echo "==> scanning without identity merge"
"$BIN" scan "dir:$FIXTURE" -o syft-json -q > "$OUT/scan-before.json"
"$BIN" scan "dir:$FIXTURE" -o syft-json -q -c "$CONFIG" > "$OUT/scan-after.json"

echo "==> writing summary"
python3 - "$OUT" <<'PY'
import json, sys, os

out = sys.argv[1]
before = json.load(open(os.path.join(out, "scan-before.json")))
after = json.load(open(os.path.join(out, "scan-after.json")))

def rows(doc):
    return [
        {"name": a["name"], "version": a["version"], "type": a["type"],
         "foundBy": a["foundBy"], "state": a.get("mergeInfo", {}).get("state")}
        for a in doc["artifacts"]
    ]

summary = {
    "before": {"packageCount": len(before["artifacts"]), "artifacts": rows(before)},
    "after": {"packageCount": len(after["artifacts"]), "artifacts": rows(after),
              "report": after.get("identityMerge")},
}
with open(os.path.join(out, "summary.json"), "w") as f:
    json.dump(summary, f, indent=2)
    f.write("\n")

print(f"before: {summary['before']['packageCount']} packages")
print(f"after:  {summary['after']['packageCount']} packages")
print(f"merge pairs: {summary['after']['report']['mergePairCount']}, "
      f"balanced: {summary['after']['report']['reconciliation']['balanced']}")
PY

echo "==> done: $OUT"
