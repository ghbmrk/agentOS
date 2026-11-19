#!/bin/sh
# The trust roots of every mmdebstrap and mkosi run (IMG-keyring-pin, #5578; IMG-keyring-minimal,
# #5954). The image's apt sources name, as each stanza's Signed-By, a keyring holding only the key
# that signs it: the pinned snapshot (trixie, trixie-updates) /usr/share/keyrings/
# debian-archive-bookworm-automatic.gpg, the security archive debian-archive-bookworm-security-
# automatic.gpg. Both come from the runner's own debian-archive-keyring package; its whole
# debian-archive-keyring.gpg (buster and bullseye keys included) is named by no build, the test kit's
# committed sources included (IMG-keyring-spikes, #5983), so it is not listed. This check fails
# unless each file below holds exactly the keys listed under it: every primary key and subkey, by
# full fingerprint, none missing and none extra.
# Callers: image/build.sh, image/guest-base.sh, image/enforcer/build.sh and
# spikes/S1S2-testkit/build.sh run it before they install anything, and each CI step that runs
# mmdebstrap itself runs it right after installing the keyring. Every mkosi tree also runs it as its
# configure script (its mkosi.configure links here; IMG-keyring-spikes, #5983): mkosi v24.3 runs that
# as /work/configure, config JSON on stdin, before any archive is read, for every build of the tree,
# whoever calls mkosi, so no call can skip it. Run that way it passes the config back on stdout,
# writes its report to stderr, and also refuses a build that is not Debian, turns off apt's
# signature check or names no package manager tree (whose sources name the keyrings below). The checks job alters a copy of
# this file to show each kind of mismatch fails (ci.yml).
#
# Usage: debian-archive-keyring.sh [DIR]   (default /usr/share/keyrings; as configure, none)
#
# A new keyring (a new Debian release's keys, a runner image update) is taken by a PR that edits
# this list, each line checked against https://ftp-master.debian.org/keys.html; see image/ASSUMPTIONS.md.
set -eu
dir=${1:-/usr/share/keyrings}
fix="if the change is expected, edit the list in image/debian-archive-keyring.sh, each fingerprint checked against https://ftp-master.debian.org/keys.html (image/ASSUMPTIONS.md IMG-keyring-pin-1)"
# A keyring file's name, then one key per line: its fingerprint, then the user ID it carries;
# each signing subkey follows its primary key.
want() {
	cat <<'EOF'
debian-archive-bookworm-automatic.gpg
B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8  Debian Archive Automatic Signing Key (12/bookworm)
4CB50190207B4758A3F73A796ED0E7B82643E131  subkey of the 12/bookworm archive key
debian-archive-bookworm-security-automatic.gpg
05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0  Debian Security Archive Automatic Signing Key (12/bookworm)
B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8  subkey of the 12/bookworm security key
EOF
}
home=$(mktemp -d); trap 'rm -rf "$home"' EXIT
# check: each listed file holds exactly its keys; the report on stdout, each mismatch on stderr.
check() {
	files=$(want | awk '!/^[0-9A-F]{40}  /')
	fail=0
	for name in $files; do
		keyring=$dir/$name
		if [ ! -f "$keyring" ]; then
			echo "debian-archive-keyring.sh: no keyring at $keyring; install the debian-archive-keyring package (apt-get install debian-archive-keyring)" >&2
			fail=1; continue
		fi
		# Every fpr record: one per primary key and one per subkey.
		listing=$(GNUPGHOME=$home gpg --batch --quiet --no-options --with-colons --show-keys "$keyring")
		got=$(printf '%s\n' "$listing" | awk -F: '$1 == "fpr" { print $10 }' | sort)
		expected=$(want | awk -v f="$name" '!/^[0-9A-F]{40}  / { on = ($0 == f); next } on { print $1 }' | sort)
		# Each primary key with its first user ID, its subkeys indented below it.
		shown=$(printf '%s\n' "$listing" | awk -F: '
			$1 == "pub" { t = "pub"; named = 0 }
			$1 == "sub" { t = "sub" }
			$1 == "fpr" { if (t == "pub") p = $10; else print "  subkey " $10 }
			$1 == "uid" && !named { print p "  " $10; named = 1 }')
		if [ "$got" != "$expected" ]; then
			echo "debian-archive-keyring.sh: $keyring does not hold exactly the pinned keys" >&2
			printf '%s\n' "$expected" >"$home/want"; printf '%s\n' "$got" >"$home/got"
			echo "(- pinned but missing, + present but not pinned)" >&2
			diff "$home/want" "$home/got" | grep '^[<>]' | sed 's/^</-/; s/^>/+/' >&2 || true
			echo "the keyring's keys:" >&2
			printf '%s\n' "$shown" >&2
			echo "$fix" >&2
			fail=1; continue
		fi
		echo "debian-archive-keyring.sh: $keyring holds exactly the $(printf '%s\n' "$got" | wc -l) pinned keys:"
		printf '%s\n' "$shown"
	done
	return "$fail"
}
if [ "${0##*/}" != configure ]; then
	check
	exit
fi
# Run by mkosi as /work/configure: the config JSON comes on stdin and goes back on stdout, the
# report to stderr; every reason to refuse is named before the build stops.
config=$(cat)
bad=0
if ! check >&2; then bad=1; fi
printf '%s\n' "$config" | python3 -c 'import json, sys
c = json.load(sys.stdin)
why = [w for ok, w in ((c["Distribution"] == "debian", "its distribution is %s, not debian" % c["Distribution"]),
                       (c["RepositoryKeyCheck"] is True, "it sets RepositoryKeyCheck=no"),
                       (bool(c["PackageManagerTrees"]), "it names no package manager tree")) if not ok]
for w in why:
    print("debian-archive-keyring.sh: this mkosi build is refused: " + w, file=sys.stderr)
sys.exit(1 if why else 0)' || bad=1
[ "$bad" != 0 ] || printf '%s\n' "$config"
exit "$bad"
