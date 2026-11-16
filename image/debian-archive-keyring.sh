#!/bin/sh
# The trust root of every mmdebstrap and mkosi run (IMG-keyring-pin, #5578). The image's apt sources
# name /usr/share/keyrings/debian-archive-keyring.gpg as Signed-By, and that file comes from the
# runner's own package archive, so a change there would change which keys every image and guest
# build accepts. This check fails unless KEYRING holds exactly the keys listed below: every primary
# key and subkey, by full fingerprint, none missing and none extra. image/build.sh and
# image/guest-base.sh run it before they install anything, and each CI step that runs mmdebstrap
# itself runs it right after installing the keyring. The checks job alters a copy of this file to
# show each kind of mismatch fails (ci.yml).
#
# Usage: debian-archive-keyring.sh [KEYRING]   (default /usr/share/keyrings/debian-archive-keyring.gpg)
#
# A new keyring (a new Debian release's keys, a runner image update) is taken by a PR that edits
# this list, each line checked against https://ftp-master.debian.org/keys.html; see image/ASSUMPTIONS.md.
set -eu
keyring=${1:-/usr/share/keyrings/debian-archive-keyring.gpg}
# One key per line: its fingerprint, then the user ID it carries.
want() {
	cat <<'EOF'
80D15823B7FD1561F9F7BCDDDC30D7C23CBBABEE  Debian Archive Automatic Signing Key (10/buster)
5E61B217265DA9807A23C5FF4DFAB270CAA96DFA  Debian Security Archive Automatic Signing Key (10/buster)
6D33866EDD8FFA41C0143AEDDCC9EFBF77E11517  Debian Stable Release Key (10/buster)
1F89983E0081FDE018F3CC9673A4F27B8DD47936  Debian Archive Automatic Signing Key (11/bullseye)
AC530D520F2F3269F5E98313A48449044AAD5C5D  Debian Security Archive Automatic Signing Key (11/bullseye)
A4285295FC7B1A81600062A9605C66F00D6C9793  Debian Stable Release Key (11/bullseye)
B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8  Debian Archive Automatic Signing Key (12/bookworm)
05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0  Debian Security Archive Automatic Signing Key (12/bookworm)
4D64FEC119C2029067D6E791F8D2585B8783D481  Debian Stable Release Key (12/bookworm)
EOF
}
[ -f "$keyring" ] || { echo "debian-archive-keyring.sh: no keyring at $keyring" >&2; exit 1; }
home=$(mktemp -d); trap 'rm -rf "$home"' EXIT
# Every fpr record: one per primary key and one per subkey.
listing=$(GNUPGHOME=$home gpg --batch --quiet --no-options --with-colons --show-keys "$keyring")
got=$(printf '%s\n' "$listing" | awk -F: '$1 == "fpr" { print $10 }' | sort)
expected=$(want | awk '{ print $1 }' | sort)
if [ "$got" != "$expected" ]; then
	echo "debian-archive-keyring.sh: $keyring does not hold exactly the pinned keys" >&2
	printf '%s\n' "$expected" >"$home/want"; printf '%s\n' "$got" >"$home/got"
	echo "(- pinned but missing, + present but not pinned)" >&2
	diff "$home/want" "$home/got" | grep '^[<>]' | sed 's/^</-/; s/^>/+/' >&2 || true
	echo "the keyring's keys:" >&2
	printf '%s\n' "$listing" | awk -F: '$1 == "fpr" { f = $10 } $1 == "uid" { print f "  " $10 }' >&2
	exit 1
fi
echo "debian-archive-keyring.sh: $keyring holds exactly the $(printf '%s\n' "$got" | wc -l) pinned keys"
