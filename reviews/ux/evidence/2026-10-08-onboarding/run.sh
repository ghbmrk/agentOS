#!/bin/sh
# Public-interface synthetic flow probe. No runtime or repository mutations.
set -eu
probe_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "${1:?Usage: run.sh PATH_TO_AGENTOS_REPO [OUTPUT_DIR]}" && pwd)
go_binary=${GO_BINARY:-go}
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/agentos-onb-flow.XXXXXX")
out_dir=${2:-"$run_dir/output"}
mkdir -p "$out_dir"
out_dir=$(CDPATH= cd -- "$out_dir" && pwd)
cp "$probe_dir/probe.go.txt" "$run_dir/probe.go"
go_os=$("$go_binary" env GOOS)
case "$go_os" in linux|darwin) ;; *) echo 'Only native Linux and Darwin are supported.' >&2; exit 1;; esac
python3 - "$repo_dir" "$probe_dir" "$run_dir" "$go_os" <<'PY'
import json
from pathlib import Path
import sys
repo, probe, run = map(Path, sys.argv[1:4])
replace = {}
if sys.argv[4] == 'darwin':
    for p in ('sockets', 'localui'):
        replace[str(repo/'broker'/p/'onb_flow_probe_darwin.go')] = str(probe/(p+'_darwin.go.txt'))
(run/'overlay.json').write_text(json.dumps({'Replace': replace}))
PY
export GOCACHE="$run_dir/go-cache"
export GOTOOLCHAIN=local
cd "$repo_dir/broker"
"$go_binary" run -mod=vendor -overlay "$run_dir/overlay.json" "$run_dir/probe.go" "$out_dir" > "$out_dir/probe-output.txt"
"$go_binary" test -mod=vendor -overlay "$run_dir/overlay.json" ./localui -run '^(TestSetupMinimumPath|TestSetupResumesAfterRestart|TestOnlyThePairedPhoneContinuesSetup|TestCardCodePairingIsClaimedWithThePageCode)$' -count=1 -v > "$out_dir/setup-tests.txt"
python3 "$probe_dir/check.py" "$out_dir"
printf 'Outputs: %s\n' "$out_dir"
