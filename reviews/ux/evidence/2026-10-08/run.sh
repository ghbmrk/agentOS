#!/bin/sh
# Read-only synthetic review evidence. Run from any directory.
set -eu

evidence_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$evidence_dir/../../../.." && pwd)
go_binary=${GO_BINARY:-go}
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/agentos-ux-evidence.XXXXXX")
out_dir="$run_dir/output"
mkdir -p "$run_dir/probes" "$run_dir/shims" "$out_dir/setup" "$out_dir/rendered"

for name in setup approvals status render; do
    cp "$evidence_dir/probes/$name.go.txt" "$run_dir/probes/$name.go"
done
for name in sockets localui; do
    cp "$evidence_dir/shims/${name}_darwin.go.txt" "$run_dir/shims/${name}_darwin.go"
done

go_os=$("$go_binary" env GOOS)
case "$go_os" in
    linux|darwin) ;;
    *) printf 'This evidence runner supports native Linux or Darwin, not %s.\n' "$go_os" >&2; exit 1 ;;
esac
python3 - "$repo_dir" "$run_dir" "$go_os" <<'PY'
import json
from pathlib import Path
import sys
repo, run = map(Path, sys.argv[1:3])
replace = {}
if sys.argv[3] == 'darwin':
    for package in ('sockets', 'localui'):
        replace[str(repo/'broker'/package/'ux_evidence_probe_darwin.go')] = str(run/'shims'/f'{package}_darwin.go')
(run/'overlay.json').write_text(json.dumps({'Replace': replace}))
PY

# Keep build artifacts outside the repository and the user's normal cache.
export GOCACHE="$run_dir/go-cache"
export GOTOOLCHAIN=local
cd "$repo_dir/broker"

"$go_binary" run -mod=vendor -overlay "$run_dir/overlay.json" "$run_dir/probes/setup.go" "$out_dir/setup" > "$out_dir/setup.txt"
"$go_binary" run -mod=vendor -overlay "$run_dir/overlay.json" "$run_dir/probes/approvals.go" > "$out_dir/approvals.txt"
"$go_binary" run -mod=vendor -overlay "$run_dir/overlay.json" "$run_dir/probes/status.go" > "$out_dir/status.txt"
"$go_binary" run -mod=vendor -overlay "$run_dir/overlay.json" "$run_dir/probes/render.go" "$out_dir/rendered" > "$out_dir/render.txt"
"$go_binary" test -mod=vendor -overlay "$run_dir/overlay.json" ./localui -run '^(TestSetupMinimumPath|TestDeviceCodeSignInAloneFinishesSetup|TestSetupResumesAfterRestart|TestAllSetText)$' -count=1 -v > "$out_dir/setup-tests.txt"

python3 "$evidence_dir/check-observations.py" "$out_dir" > "$out_dir/checks.txt"
cat "$out_dir/checks.txt"
printf 'Evidence outputs: %s\n' "$out_dir"
printf 'Temporary probes, overlay and cache: %s\n' "$run_dir"
