#!/bin/sh
# Build llama-server, the local inference service's model runtime (INFER-image, #3655; INFER-SVC E2),
# from the pinned llama.cpp release's source (llama_src_* in broker/cmd/agentos-infer/llama.pins):
# the tarball checked by hash, CPU only, static, with no network client in it. The image ships this
# build (image/infer.sh) and the infer-real workflow runs the real test on it, so the server tested is
# the server shipped. See NOTICE.
#
# Usage: llamaserver.sh DEST WORK
# Writes DEST/llama-server and DEST/LICENSE (llama.cpp's MIT text). Builds in WORK (a fixed path keeps
# the build reproducible: the source path is mapped out of the binary) and removes it after.
# LLAMA_TARBALL=<file> uses a local copy (still hash-checked).
# Needs: curl (unless LLAMA_TARBALL is set), sha256sum, gzip, git, tar, cmake, make, readelf, and a C
# and C++ compiler with static libc and libstdc++.
#
# The instruction set is fixed, never the build machine's (GGML_NATIVE off): x86-64 with SSE4.2, AVX,
# AVX2, FMA, F16C and BMI2, which the N95 floor (HW-4) has; no AVX-512 (INFER-A15).
#
# The build fetches nothing (#4454): llama.cpp's default (LLAMA_USE_PREBUILT_UI on) downloads its web
# UI from a Hugging Face bucket at build time, unpinned ("latest" for a source archive, which has no git
# build number) and silently skipped when the fetch fails, so two builds of one commit embedded
# different UIs and the image's reproduce check failed. agentos-infer runs the server with --no-webui,
# so the UI is off here, and the build fails if the generated ui.h still embeds one.
#
# The build info comes from the pins, never from git (#5022): llama.cpp's and ggml's cmake ask git for
# the commit and commit count from the source directory, and from a WORK inside a git checkout git
# found that checkout, so its commit went into the binary and a local rebuild differed from CI's.
# The build number is llama_src_url's release tag, the commit is llama_src_commit, and GIT_DIR names
# no repository for the build, so ggml's own commit reads "unknown" wherever WORK is.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
PINS=$REPO/broker/cmd/agentos-infer/llama.pins
pin() { sed -n "s/^$1=//p" "$PINS"; }
URL=$(pin llama_src_url); WANT=$(pin llama_src_sha256)
TAG=$(printf '%s\n' "$URL" | sed -n 's|^https://github\.com/ggml-org/llama\.cpp/archive/refs/tags/b\([0-9][0-9]*\)\.tar\.gz$|\1|p')
[ -n "$TAG" ] || { echo "llama.cpp source: llama_src_url is not a bNNNN tag archive" >&2; exit 1; }
DEST=$(realpath -m "$1"); WORK=$(realpath -m "$2")
rm -rf "$WORK"; mkdir -p "$WORK" "$DEST"
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
mkdir "$WORK/src" && tar -xzf "$WORK/src.tar.gz" -C "$WORK/src" --strip-components=1

FLAGS="-ffile-prefix-map=$WORK=."
cmake -S "$WORK/src" -B "$WORK/build" -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_FLAGS="$FLAGS" -DCMAKE_CXX_FLAGS="$FLAGS" -DCMAKE_EXE_LINKER_FLAGS=-static \
	-DBUILD_SHARED_LIBS=OFF -DGGML_STATIC=ON -DGGML_BACKEND_DL=OFF -DGGML_CPU_ALL_VARIANTS=OFF \
	-DGGML_NATIVE=OFF -DGGML_SSE42=ON -DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_F16C=ON \
	-DGGML_BMI2=ON -DGGML_AVX512=OFF -DGGML_OPENMP=OFF -DGGML_CCACHE=OFF \
	-DLLAMA_CURL=OFF -DLLAMA_OPENSSL=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
	-DLLAMA_BUILD_TOOLS=ON -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_UI=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
	-DLLAMA_BUILD_NUMBER="$TAG" -DLLAMA_BUILD_COMMIT="$(pin llama_src_commit)" >/dev/null
cmake --build "$WORK/build" --target llama-server -j"$(nproc)" >/dev/null
UI_H=$WORK/build/tools/ui/ui.h
[ -f "$UI_H" ] || { echo "llama-server: $UI_H was not generated; the web UI check cannot run" >&2; exit 1; }
! grep -q '^#define LLAMA_UI_HAS_ASSETS' "$UI_H" || { echo "llama-server embeds a web UI (#4454)" >&2; exit 1; }
BIN=$WORK/build/bin/llama-server
! readelf -l "$BIN" | grep -q INTERP || { echo "llama-server is not static" >&2; exit 1; }
! readelf -d "$BIN" 2>/dev/null | grep -q NEEDED || { echo "llama-server needs shared libraries" >&2; exit 1; }
install -m 0755 -s "$BIN" "$DEST/llama-server"
install -m 0644 "$WORK/src/LICENSE" "$DEST/LICENSE"
rm -rf "$WORK"
