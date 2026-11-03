#!/bin/sh
# CI only (enforcer-image.yml): throwaway keys for a stand-in agentOS feed and an enforcer feed, made
# with the maintainers' own tool (broker/cmd/agentos-release), so finish_image.py is tested on real
# TUF metadata. Then the key separation on that metadata (ENF-m acceptance 2): the enforcer feed
# passes, and an enforcer feed with one agentOS key in it is refused, by --check-root (the image's
# root) and by --check-feed (a release signed with that key). Nothing here is ever a release key.
# Usage: throwaway_feeds.sh DIR. Writes DIR/core/{root.json,*.pub} and DIR/enforcer/repo (the feed).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); D=$(realpath -m "$1"); mkdir -p "$D"
export GOWORK=off
(cd "$HERE/../../broker" && CGO_ENABLED=0 go build -trimpath -o "$D/agentos-release" ./cmd/agentos-release)
rel() { "$D/agentos-release" "$@" >/dev/null; }
# feed NAME ROOT1 ROOT2 TARGETS1 TARGETS2 SNAPSHOT TIMESTAMP: a published feed in DIR/NAME/repo,
# from the key bases given (each BASE.key and BASE.pub).
feed() {
	n=$1; shift
	rel init -repo "$D/$n/repo" -root "$1.pub,$2.pub" -targets "$3.pub,$4.pub" -snapshot "$5.pub" -timestamp "$6.pub"
	rel sign -repo "$D/$n/repo" -role root -key "$1.key"; rel sign -repo "$D/$n/repo" -role root -key "$2.key"
	rel sign -repo "$D/$n/repo" -role targets -key "$3.key"; rel sign -repo "$D/$n/repo" -role targets -key "$4.key"
	rel publish -repo "$D/$n/repo" -snapshot-key "$5.key" -timestamp-key "$6.key"
}
mkdir -p "$D/keys"
for k in core-r1 core-r2 core-t1 core-t2 core-s core-ts enf-r1 enf-r2 enf-t1 enf-t2 enf-s enf-ts; do
	rel keygen "$D/keys/$k"
done
K=$D/keys
feed core "$K/core-r1" "$K/core-r2" "$K/core-t1" "$K/core-t2" "$K/core-s" "$K/core-ts"
feed enforcer "$K/enf-r1" "$K/enf-r2" "$K/enf-t1" "$K/enf-t2" "$K/enf-s" "$K/enf-ts"
# The same enforcer feed, but its second targets key is the agentOS targets key.
feed shared "$K/enf-r1" "$K/enf-r2" "$K/enf-t1" "$K/core-t1" "$K/enf-s" "$K/enf-ts"
cp "$D/core/repo/metadata/1.root.json" "$D/core/root.json"
cp "$K"/core-*.pub "$D/core/"
rm -f "$K"/*.key

F="python3 $HERE/finish_image.py"
CORE="--agentos-key $D/core/root.json"
fail=0
$F --check-root --root "$D/enforcer/repo/metadata/1.root.json" $CORE && echo "ok   enforcer root accepted" ||
	{ echo "MISS enforcer root accepted"; fail=1; }
$F --check-feed "$D/enforcer/repo" --root "$D/enforcer/repo/metadata/1.root.json" $CORE && echo "ok   enforcer feed accepted" ||
	{ echo "MISS enforcer feed accepted"; fail=1; }
for mode in --check-root "--check-feed $D/shared/repo"; do
	# shellcheck disable=SC2086 # $mode and $CORE are lists of arguments without spaces.
	if $F $mode --root "$D/shared/repo/metadata/1.root.json" $CORE; then
		echo "MISS $mode refuses a feed holding the agentOS targets key"; fail=1
	else
		echo "ok   $mode refuses a feed holding the agentOS targets key"
	fi
done
# A PEM agentOS key alone is enough to refuse it too.
if $F --check-root --root "$D/shared/repo/metadata/1.root.json" --agentos-key "$D/core/core-t1.pub"; then
	echo "MISS the PEM agentOS key refuses it"; fail=1
else
	echo "ok   the PEM agentOS key refuses it"
fi
[ $fail = 0 ]
