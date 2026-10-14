#!/bin/bash
# #809's supervised Codex plan-route measurements (briefs/S8-live.md), in a gVisor machine built
# by guest/codex/build-rootfs.sh. The machine has no network but loopback: the in-machine relay
# carries 127.0.0.1:18432 (where #1014's forwarder listens) to fwd.py on a unix socket, and fwd.py
# relays to the real hosts through the session proxy.
#
# Usage: run.sh setup | tools | plan | clean
#   setup  build the rootfs (managed config on), a copy with /etc/codex removed (managed config
#          off) and the relay. Needs runsc (CI's pinned release) and Go.
#   tools  hosted-tools measurement: one `codex exec` per image against the stub forwarder (no
#          login, nothing leaves the host); prints the tool types each request carries.
#   plan   sign-in and credits measurement with the owner's ChatGPT plan: device sign-in through
#          the forwarder, then one `codex exec` whose model call the forwarder refuses, so nothing
#          is spent. The login lives in the machine's memory overlay and is gone when it exits.
#   clean  stop the forwarder and remove the work directory.
# Logs never hold tokens or bodies: fwd.py writes paths, statuses, x-codex-* headers, tool types
# and key names only.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
W=${S8LIVE_DIR:-/tmp/agentos-s8live}
mkdir -p "$W"

fwd() { # fwd MODE LOG: (re)start the forwarder on the egress socket
	[ -f "$W/fwd.pid" ] && kill "$(cat "$W/fwd.pid")" 2>/dev/null || true
	mkdir -p "$W/sock"
	python3 -I "$here/fwd.py" "$2" "$1" "$W/sock/egress.sock" >"$W/fwd.err" 2>&1 &
	echo $! >"$W/fwd.pid"
	for _ in $(seq 50); do [ -S "$W/sock/egress.sock" ] && return; sleep 0.1; done
	echo "run.sh: forwarder did not start" >&2; exit 1
}

inm() { # inm ROOT CMD...: run CMD in a machine from ROOT with the launch spec's environment
	root=$1; shift
	mkdir -p "$W/work"
	runsc --network=none --host-uds=open --ignore-cgroups do -quiet -root "$root" -cwd / \
		-volume "$W/work:/var/lib/agentos-work" -volume "$W/sock:/run/agentos" -volume "$W/relay:/opt/relay" \
		/bin/bash -c '/opt/relay/relay /run/agentos/egress.sock & cd /var/lib/agentos-work &&
			mkdir -p /var/lib/agentos-codex && chmod 700 /var/lib/agentos-codex &&
			exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/var/lib/agentos-codex \
			CODEX_HOME=/var/lib/agentos-codex GIT_DIR=/dev/null \
			CODEX_REFRESH_TOKEN_URL_OVERRIDE=http://127.0.0.1:18432/oauth/token "$@"' inm "$@"
}

case ${1:-} in
_inm)
	shift; inm "$@"
	;;
setup)
	[ -e "$W/root" ] || sh "$here/../../guest/codex/build-rootfs.sh" "$W/root"
	if [ ! -e "$W/root-off" ]; then
		cp -a "$W/root" "$W/root-off"
		rm -rf "$W/root-off/etc/codex"
	fi
	mkdir -p "$W/relay"
	(cd "$here/relay" && CGO_ENABLED=0 go build -o "$W/relay/relay" .)
	runsc --version | head -1
	;;
tools)
	fwd stub "$W/tools.jsonl"
	for img in root root-off; do
		for ws in default live; do
			: >"$W/tools.jsonl"
			extra=()
			[ $ws = live ] && extra=(-c 'web_search="live"')
			echo "Reply ok." | timeout 90 "$0" _inm "$W/$img" codex exec "${extra[@]}" --json \
				--skip-git-repo-check --cd /var/lib/agentos-work - >"$W/exec-$img-$ws.out" 2>&1 || true
			echo "== $img web_search=$ws"
			head -1 "$W/tools.jsonl" | jq -c '{model, tool_choice, tools, input_tools}'
		done
	done
	;;
plan)
	fwd relay "$W/plan.jsonl"
	mkdir -p "$W/work"
	cat >"$W/work/session.sh" <<'EOF'
codex login --experimental_issuer http://127.0.0.1:18432 --device-auth || exit 1
echo "Reply ok." | codex exec --json --skip-git-repo-check --cd /var/lib/agentos-work - >/var/lib/agentos-work/exec-plan.out 2>&1
echo "== session done"
EOF
	echo "Sign-in page for the owner: https://auth.openai.com/codex/device (the CLI prints the forwarder's address)"
	inm "$W/root" /bin/bash /var/lib/agentos-work/session.sh
	jq -c 'del(.t, .req_headers, .body_keys, .resp_keys)' "$W/plan.jsonl"
	;;
clean)
	[ -f "$W/fwd.pid" ] && kill "$(cat "$W/fwd.pid")" 2>/dev/null || true
	rm -rf "$W"
	;;
*)
	sed -n '2,17p' "$0"; exit 2
	;;
esac
