#!/bin/sh
# Copies programs, and every library they load, into a guest root from BASE, the Debian root
# image/guest-base.sh installs from the image's pinned apt sources, never from the build host
# (IMG-reproduce-pcre2, #5570): two builds of one commit on different runner images must put the
# same bytes in the guest (IMG-2).
#
# Usage: guest-userland.sh BASE OUT PATH...
# Each PATH is a path in the guest. A program already in OUT (a pinned download, such as Node)
# stays as it is and only its libraries are copied; any other is copied from BASE, at the same path.
# BASE's own loader resolves the libraries, from BASE's library directory only (no host cache);
# it goes to /lib64, where every x86-64 program asks for it. A library found anywhere else, a
# missing one, another loader, or a link that leaves BASE fails the build.
set -eu
[ $# -ge 3 ] || { echo "usage: guest-userland.sh BASE OUT PATH..." >&2; exit 2; }
base=$(cd "$1" && pwd -P)
out=$2
shift 2
lib=$base/usr/lib/x86_64-linux-gnu
ld=$lib/ld-linux-x86-64.so.2
interp=/lib64/ld-linux-x86-64.so.2
fail() { echo "guest-userland.sh: $*" >&2; exit 1; }
# put SRC DST: SRC, every link in it resolved, must stay inside BASE.
put() {
	r=$(readlink -f "$1") || fail "$1: unresolvable"
	case $r in "$base"/*) ;; *) fail "$1 resolves to $r, outside $base" ;; esac
	[ -f "$r" ] || fail "$1: not a file"
	mkdir -p "$out$(dirname "$2")"
	cp "$r" "$out$2"
}
[ -x "$ld" ] || fail "no loader at $ld"
put "$ld" "$interp"
for p in "$@"; do
	case $p in /*) ;; *) fail "$p: not an absolute path" ;; esac
	[ -e "$out$p" ] || put "$base$p" "$p"
	deps=$("$ld" --inhibit-cache --library-path "$lib" --list "$out$p") || fail "$p: the loader cannot list it"
	while read -r name _ path _; do
		case $name in
		linux-vdso.so.*) continue ;;
		/*) [ "$name" = "$interp" ] || fail "$p asks for loader $name" ; continue ;;
		esac
		case $path in "$lib"/*) ;; *) fail "$p: $name not found in $lib (got $path)" ;; esac
		put "$path" "/usr/lib/x86_64-linux-gnu/${path#"$lib"/}"
	done <<EOT
$deps
EOT
done
