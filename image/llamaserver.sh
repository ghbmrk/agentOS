#!/bin/sh
# Build llama-server, the local inference service's model runtime (INFER-image, #3655; INFER-SVC E2),
# from the pinned llama.cpp release's source (llama_src_* in broker/cmd/agentos-infer/llama.pins):
# the tarball checked by hash, CPU only, static, with no network client in it. The image ships this
# build (image/infer.sh) and the infer-real workflow runs the real test on it, so the server tested is
# the server shipped. See NOTICE.
#
# Usage: llamaserver.sh DEST    (as root, with GUEST_BASE and LINKED_SHIPPED set)
# Writes DEST/llama-server and DEST/LICENSE (llama.cpp's MIT text). LLAMA_TARBALL=<file> uses a local
# copy (still hash-checked). The host gives only the download and its checks: curl (unless
# LLAMA_TARBALL is set), sha256sum, gzip, git (get-tar-commit-id) and chroot.
#
# The build runs inside GUEST_BASE, a root from image/guest-base.sh, at a fixed path (reproducibility:
# the source path is mapped out of the binary) removed after, by chroot with a clean environment
# (VULN-static-elf, #5885), as image/camdecode.sh builds the camera decoder: tar, cmake, make, the C and
# C++ compilers, libstdc++.a, libc.a and binutils are the base's, from the image's pinned apt sources,
# never the build host's. The binary carries the code of every archive and object its static link
# read (libstdc++-14-dev's libstdc++.a, libc6-dev's libc.a, libgcc's), so the link writes a map and
# each input it loads from outside the build directory is recorded with image/guest-shipped.sh into
# the file LINKED_SHIPPED names: the main tree's list, not the guests' (image/build.sh writes its
# status to OUT/linked, which tools/vulncheck.py image scans as part of the main tree). The build
# stops on an input no Debian package owns, or a map that loads nothing from the base or not both
# libstdc++.a and libc.a.
#
# The instruction set is fixed, never the build machine's (GGML_NATIVE off): x86-64 with SSE4.2, AVX,
# AVX2, FMA, F16C and BMI2, which the N95 floor (HW-4) has; no AVX-512 (INFER-A15).
#
# The build fetches nothing (#4454): llama.cpp's default (LLAMA_USE_PREBUILT_UI on) downloads its web
# UI from a Hugging Face bucket at build time, unpinned ("latest" for a source archive, which has no git
# build number) and silently skipped when the fetch fails, so two builds of one commit embedded
# different UIs and the image's reproduce check failed. agentos-infer runs the server with --no-webui,
# so the UI is off here, and the build fails if the generated ui.h still embeds one. The base has no
# network the build could use: nothing in it is started but the build's own tools.
#
# The build info comes from the pins, never from git (#5022): llama.cpp's and ggml's cmake ask git for
# the commit and commit count from the source directory, and from a WORK inside a git checkout git
# found that checkout, so its commit went into the binary and a local rebuild differed from CI's.
# The build number is llama_src_url's release tag, the commit is llama_src_commit, and GIT_DIR names
# no repository for the build (the jail passes it through), so ggml's own commit reads "unknown".
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
PINS=$REPO/broker/cmd/agentos-infer/llama.pins
pin() { sed -n "s/^$1=//p" "$PINS"; }
URL=$(pin llama_src_url); WANT=$(pin llama_src_sha256)
TAG=$(printf '%s\n' "$URL" | sed -n 's|^https://github\.com/ggml-org/llama\.cpp/archive/refs/tags/b\([0-9][0-9]*\)\.tar\.gz$|\1|p')
[ -n "$TAG" ] || { echo "llama.cpp source: llama_src_url in $PINS is not a https://github.com/ggml-org/llama.cpp/archive/refs/tags/bNNNN.tar.gz URL: '$URL'" >&2; exit 1; }
[ $# -eq 1 ] || { echo "usage: llamaserver.sh DEST" >&2; exit 2; }
DEST=$(realpath -m "$1")
base=${GUEST_BASE:?set GUEST_BASE to a root from image/guest-base.sh}
linked=${LINKED_SHIPPED:?set LINKED_SHIPPED to the file that records the packages llama-server links (#5885)}
# The build's fixed path inside the base; every path the jail sees is under it.
lib=/tmp/agentos-llama
WORK=$base$lib

# jail CMD...: CMD in the base's build directory, by chroot with only these variables.
jail() {
	chroot "$base" /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent TMPDIR="$lib/tmp" \
		GIT_DIR="$GIT_DIR" sh -c 'cd "$0" && exec "$@"' "$lib" "$@"
}

rm -rf "${WORK:?}"; mkdir -p "$WORK/tmp" "$DEST"
trap 'rm -rf "${WORK:?}"' EXIT
if [ -n "${LLAMA_TARBALL:-}" ]; then
	cp "$LLAMA_TARBALL" "$WORK/src.tar.gz"
else
	curl -fsSL --retry 3 --retry-delay 5 -o "$WORK/src.tar.gz" "$URL"
fi
# The archive names the commit it was made from (git archive's pax header); it must be the pinned
# one, which infer-real also checks against the release tag over git, a second path to the source.
GOT=$(sha256sum "$WORK/src.tar.gz" | cut -d' ' -f1)
COMMIT=$(gzip -dc "$WORK/src.tar.gz" | git get-tar-commit-id) || COMMIT=none
echo "llama.cpp source: $URL sha256 $GOT commit $COMMIT (pinned: $WANT, $(pin llama_src_commit))"
[ "$GOT" = "$WANT" ] || { echo "llama.cpp source: the download does not match llama_src_sha256 in $PINS" >&2; exit 1; }
[ "$COMMIT" = "$(pin llama_src_commit)" ] || { echo "llama.cpp source: the archive's commit is not llama_src_commit in $PINS" >&2; exit 1; }
export GIT_DIR=/dev/null
mkdir "$WORK/src" && jail tar -xzf "$lib/src.tar.gz" -C "$lib/src" --strip-components=1

FLAGS="-ffile-prefix-map=$lib=."
jail cmake -S "$lib/src" -B "$lib/build" -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_FLAGS="$FLAGS" -DCMAKE_CXX_FLAGS="$FLAGS" -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,-Map=$lib/llama-server.map" \
	-DBUILD_SHARED_LIBS=OFF -DGGML_STATIC=ON -DGGML_BACKEND_DL=OFF -DGGML_CPU_ALL_VARIANTS=OFF \
	-DGGML_NATIVE=OFF -DGGML_SSE42=ON -DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_F16C=ON \
	-DGGML_BMI2=ON -DGGML_AVX512=OFF -DGGML_OPENMP=OFF -DGGML_CCACHE=OFF \
	-DLLAMA_CURL=OFF -DLLAMA_OPENSSL=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
	-DLLAMA_BUILD_TOOLS=ON -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_UI=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
	-DLLAMA_BUILD_NUMBER="$TAG" -DLLAMA_BUILD_COMMIT="$(pin llama_src_commit)" >/dev/null
jail sh -c 'cmake --build "$0" --target llama-server -j"$(nproc)"' "$lib/build" >/dev/null
UI_H=$WORK/build/tools/ui/ui.h
[ -f "$UI_H" ] || { echo "llama-server: $UI_H was not generated; the web UI check cannot run" >&2; exit 1; }
! grep -q '^#define LLAMA_UI_HAS_ASSETS' "$UI_H" || { echo "llama-server embeds a web UI (#4454)" >&2; exit 1; }
BIN=$WORK/build/bin/llama-server
! jail readelf -l "${BIN#"$base"}" | grep -q INTERP || { echo "llama-server is not static" >&2; exit 1; }
! jail readelf -d "${BIN#"$base"}" 2>/dev/null | grep -q NEEDED || { echo "llama-server needs shared libraries" >&2; exit 1; }
# The link's inputs (#5885). CMake runs the link from the target's own build directory, the one
# holding CMakeFiles/llama-server.dir, and names its objects and the project's archives relative to
# it; the compiler driver names the base's archives and start-up files by absolute path. Each LOAD
# line's file ("LOAD linker stubs" names no file), a relative one resolved against that directory,
# is recorded unless it is under $lib, so no input from the base goes unrecorded.
MAP=$WORK/llama-server.map
[ -f "$MAP" ] || { echo "llama-server: the link wrote no map ($MAP)" >&2; exit 1; }
LINKDIR=$(cd "$WORK/build" && find . -path '*/CMakeFiles/llama-server.dir' -type d)
[ "$(printf '%s\n' "$LINKDIR" | grep -c .)" -eq 1 ] || { echo "llama-server: not one link directory in $WORK/build: '$LINKDIR'" >&2; exit 1; }
LINKDIR=$lib/build/${LINKDIR#./}/../..
loaded=$(awk '/^LOAD / && $2 != "linker" { print $2 }' "$MAP" | while read -r f; do
	case $f in /*) p=$f ;; *) p=$LINKDIR/$f ;; esac
	p=$(realpath -m -s "$p")
	case $p in "$lib" | "$lib"/*) ;; *) echo "$p" ;; esac
done | sort -u)
[ -n "$loaded" ] || { echo "llama-server: the link map loads nothing from outside $lib" >&2; exit 1; }
for want in libstdc++.a libc.a; do
	printf '%s\n' "$loaded" | grep -q "/$want\$" || { echo "llama-server: the link map loads no $want from the base" >&2; exit 1; }
done
# shellcheck disable=SC2086  # one path per word
GUEST_SHIPPED=$linked sh "$HERE/guest-shipped.sh" "$base" $loaded
jail strip -o "$lib/llama-server.stripped" "$lib/build/bin/llama-server"
install -m 0755 "$WORK/llama-server.stripped" "$DEST/llama-server"
install -m 0644 "$WORK/src/LICENSE" "$DEST/LICENSE"
