#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
out_dir=${1:-"$repo_root/artifacts/trim-acceptance"}
work_dir="$out_dir/work"
rootfs="$work_dir/rootfs"
oci_dir="$work_dir/oci"

for command in go node npm jq curl tar gzip sha256sum stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command is missing: $command" >&2
    exit 1
  fi
done

rm -rf "$out_dir"
mkdir -p "$rootfs/app/tests/fixtures" "$rootfs/app/examples/demo" "$oci_dir/blobs/sha256"

cat >"$rootfs/app/package.json" <<'EOF'
{
  "name": "trim-demo-runtime",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.15"
  },
  "devDependencies": {
    "chalk": "2.4.2",
    "minimist": "1.2.0",
    "typescript": "4.9.5"
  }
}
EOF
cat >"$rootfs/app/tests/fixtures/package.json" <<'EOF'
{
  "name": "fixture-only",
  "version": "1.0.0",
  "dependencies": {
    "left-pad": "1.3.0"
  }
}
EOF
cat >"$rootfs/app/examples/demo/package.json" <<'EOF'
{
  "name": "example-only",
  "version": "1.0.0",
  "dependencies": {
    "is-number": "7.0.0"
  }
}
EOF

for dir in "$rootfs/app" "$rootfs/app/tests/fixtures" "$rootfs/app/examples/demo"; do
  (
    cd "$dir"
    npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null
  )
done

# Build a real OCI image layout without a container runtime.
tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$rootfs" -cf "$work_dir/layer.tar" .
gzip -n -c "$work_dir/layer.tar" >"$work_dir/layer.tar.gz"

layer_digest=$(sha256sum "$work_dir/layer.tar.gz" | awk '{print $1}')
layer_size=$(stat -c %s "$work_dir/layer.tar.gz")
diff_id=$(sha256sum "$work_dir/layer.tar" | awk '{print $1}')
cp "$work_dir/layer.tar.gz" "$oci_dir/blobs/sha256/$layer_digest"

cat >"$work_dir/config.json" <<EOF
{"created":"2020-01-01T00:00:00Z","architecture":"amd64","os":"linux","config":{"Labels":{"org.opencontainers.image.title":"trim-demo"}},"rootfs":{"type":"layers","diff_ids":["sha256:$diff_id"]},"history":[{"created":"2020-01-01T00:00:00Z","created_by":"syft trim acceptance"}]}
EOF
config_digest=$(sha256sum "$work_dir/config.json" | awk '{print $1}')
config_size=$(stat -c %s "$work_dir/config.json")
cp "$work_dir/config.json" "$oci_dir/blobs/sha256/$config_digest"

cat >"$work_dir/manifest.json" <<EOF
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:$config_digest","size":$config_size},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:$layer_digest","size":$layer_size}]}
EOF
manifest_digest=$(sha256sum "$work_dir/manifest.json" | awk '{print $1}')
manifest_size=$(stat -c %s "$work_dir/manifest.json")
cp "$work_dir/manifest.json" "$oci_dir/blobs/sha256/$manifest_digest"

cat >"$oci_dir/index.json" <<EOF
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:$manifest_digest","size":$manifest_size,"annotations":{"org.opencontainers.image.ref.name":"trim-demo:latest"}}]}
EOF
printf '{"imageLayoutVersion":"1.0.0"}' >"$oci_dir/oci-layout"

(
  cd "$repo_root"
  go build -o "$work_dir/syft" ./cmd/syft
)

cat >"$work_dir/scan-config.yaml" <<'EOF'
javascript:
  include-dev-dependencies: true
EOF

cat >"$work_dir/trim-off-config.yaml" <<'EOF'
javascript:
  include-dev-dependencies: true
trim:
  enabled: false
EOF

cat >"$work_dir/trim-config.yaml" <<'EOF'
javascript:
  include-dev-dependencies: true
trim:
  enabled: true
  default:
    categories:
      dev: true
      test: true
      build: true
    classifiers:
      - category: build
        packages:
          - typescript
EOF

{
  echo '      - category: dev'
  echo '        packages:'
  jq -r '.packages | to_entries[] | select(.key != "" and .value.dev == true) | .key | sub("^node_modules/";"") | "          - " + .' \
    "$rootfs/app/package-lock.json"
} >>"$work_dir/trim-config.yaml"

scan_args=(
  --override-default-catalogers all
  --select-catalogers=-javascript-package-cataloger
)

"$work_dir/syft" scan "oci-dir:$oci_dir" "${scan_args[@]}" \
  --config "$work_dir/scan-config.yaml" \
  -o "syft-json=$out_dir/before.syft.json" -q

"$work_dir/syft" scan "oci-dir:$oci_dir" "${scan_args[@]}" \
  --config "$work_dir/trim-config.yaml" \
  -o "syft-json=$out_dir/trimmed.syft.json" -q

"$work_dir/syft" scan "oci-dir:$oci_dir" "${scan_args[@]}" \
  --config "$work_dir/trim-off-config.yaml" \
  -o "syft-json=$out_dir/trim-off.syft.json" -q

default_off_identical=false
if cmp -s "$out_dir/before.syft.json" "$out_dir/trim-off.syft.json"; then
  default_off_identical=true
fi

# Query OSV for every unique npm package in the full SBOM, then compare which matches remain.
node - "$out_dir/before.syft.json" "$work_dir/osv-queries.json" <<'NODE'
const fs = require("fs");
const document = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const seen = new Set();
const queries = [];
for (const artifact of document.artifacts || []) {
  const purl = artifact.purl || "";
  if (!purl.startsWith("pkg:npm/")) continue;
  const match = purl.match(/^pkg:npm\/(.+)@([^@]+)$/);
  if (!match) continue;
  const key = `${match[1]}@${match[2]}`;
  if (seen.has(key)) continue;
  seen.add(key);
  queries.push({
    package: { name: decodeURIComponent(match[1]), ecosystem: "npm" },
    version: decodeURIComponent(match[2]),
  });
}
fs.writeFileSync(process.argv[3], JSON.stringify({ queries }));
NODE

curl -sS --fail -m 60 \
  -H 'Content-Type: application/json' \
  -X POST https://api.osv.dev/v1/querybatch \
  --data-binary "@$work_dir/osv-queries.json" \
  >"$work_dir/osv-results.json"

jq -n \
  --slurpfile queries "$work_dir/osv-queries.json" \
  --slurpfile results "$work_dir/osv-results.json" \
  '[range(0; ($queries[0].queries | length)) as $i | {
    name: $queries[0].queries[$i].package.name,
    version: $queries[0].queries[$i].version,
    vulnerabilities: [($results[0].results[$i].vulns // [])[]?.id]
  }]' >"$out_dir/osv-matches.json"

before_bytes=$(stat -c %s "$out_dir/before.syft.json")
after_bytes=$(stat -c %s "$out_dir/trimmed.syft.json")

jq -n \
  --slurpfile before "$out_dir/before.syft.json" \
  --slurpfile after "$out_dir/trimmed.syft.json" \
  --slurpfile matches "$out_dir/osv-matches.json" \
  --argjson beforeBytes "$before_bytes" \
  --argjson afterBytes "$after_bytes" \
  --argjson defaultOffIdentical "$default_off_identical" \
  --arg image "oci-dir:$oci_dir" \
  '
  def component_keys: [.artifacts[] | {name, version}];
  def before_keys: ($before[0] | component_keys);
  def after_keys: ($after[0] | component_keys);
  {
    image: $image,
    defaultOffOutputIdentical: $defaultOffIdentical,
    before: {
      components: ($before[0].artifacts | length),
      bytes: $beforeBytes
    },
    trimmed: {
      components: ($after[0].artifacts | length),
      bytes: $afterBytes,
      reductionPercent: ((1 - ($afterBytes / $beforeBytes)) * 100 | round)
    },
    trimReport: $after[0].descriptor.configuration.trim,
    vulnerabilityComparison: {
      removedComponentsWithMatches: [
        $matches[0][] as $match
        | select(($match.vulnerabilities | length) > 0)
        | select(any(before_keys[]; .name == $match.name and .version == $match.version))
        | select(all(after_keys[]; .name != $match.name or .version != $match.version))
        | $match + {presentInTrimmedSBOM: false}
      ],
      retainedComponentsWithMatches: [
        $matches[0][] as $match
        | select(($match.vulnerabilities | length) > 0)
        | select(any(after_keys[]; .name == $match.name and .version == $match.version))
        | $match + {presentInTrimmedSBOM: true}
      ]
    }
  }' >"$out_dir/summary.json"

rm -f "$work_dir/syft" "$work_dir/layer.tar" "$work_dir/layer.tar.gz"

echo "acceptance artifacts written to $out_dir"
jq '{
  image,
  defaultOffOutputIdentical,
  before,
  trimmed,
  categoryDistribution: .trimReport.byCategory,
  ruleDistribution: .trimReport.byRule,
  unknown: .trimReport.unknown,
  removedComponentsWithMatches: .vulnerabilityComparison.removedComponentsWithMatches,
  retainedComponentsWithMatches: [.vulnerabilityComparison.retainedComponentsWithMatches[] | {name, version, vulnerabilities}]
}' "$out_dir/summary.json"
