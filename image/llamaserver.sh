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
# Needs: curl (unless LLAMA_TARBALL is set), sha256sum, tar, cmake, make, readelf, and a C and C++
# compiler with static libc and libstdc++.
#
# The instruction set is fixed, never the build machine's (GGML_NATIVE off): x86-64 with SSE4.2, AVX,
# AVX2, FMA, F16C and BMI2, which the N95 floor (HW-4) has; no AVX-512 (INFER-A15).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
PINS=$REPO/broker/cmd/agentos-infer/llama.pins
pin() { sed -n "s/^$1=//p" "$PINS"; }
URL=$(pin llama_src_url); WANT=$(pin llama_src_sha256)
DEST=$(realpath -m "$1"); WORK=$(realpath -m "$2")
rm -rf "$WORK"; mkdir -p "$WORK" "$DEST"
if [ -n "${LLAMA_TARBALL:-}" ]; then
	cp "$LLAMA_TARBALL" "$WORK/src.tar.gz"
else
	curl -fsSL --retry 3 --retry-delay 5 -o "$WORK/src.tar.gz" "$URL"
fi
GOT=$(sha256sum "$WORK/src.tar.gz" | cut -d' ' -f1)
echo "llama.cpp source: $URL sha256 $GOT (pinned: $WANT)"
[ "$GOT" = "$WANT" ] || { echo "llama.cpp source: the download does not match llama_src_sha256 in $PINS" >&2; exit 1; }
mkdir "$WORK/src" && tar -xzf "$WORK/src.tar.gz" -C "$WORK/src" --strip-components=1

FLAGS="-ffile-prefix-map=$WORK=."
cmake -S "$WORK/src" -B "$WORK/build" -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_FLAGS="$FLAGS" -DCMAKE_CXX_FLAGS="$FLAGS" -DCMAKE_EXE_LINKER_FLAGS=-static \
	-DBUILD_SHARED_LIBS=OFF -DGGML_STATIC=ON -DGGML_BACKEND_DL=OFF -DGGML_CPU_ALL_VARIANTS=OFF \
	-DGGML_NATIVE=OFF -DGGML_SSE42=ON -DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_F16C=ON \
	-DGGML_BMI2=ON -DGGML_AVX512=OFF -DGGML_OPENMP=OFF -DGGML_CCACHE=OFF \
	-DLLAMA_CURL=OFF -DLLAMA_OPENSSL=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
	-DLLAMA_BUILD_TOOLS=ON -DLLAMA_BUILD_SERVER=ON >/dev/null
cmake --build "$WORK/build" --target llama-server -j"$(nproc)" >/dev/null
BIN=$WORK/build/bin/llama-server
! readelf -l "$BIN" | grep -q INTERP || { echo "llama-server is not static" >&2; exit 1; }
! readelf -d "$BIN" 2>/dev/null | grep -q NEEDED || { echo "llama-server needs shared libraries" >&2; exit 1; }
install -m 0755 -s "$BIN" "$DEST/llama-server"
install -m 0644 "$WORK/src/LICENSE" "$DEST/LICENSE"
rm -rf "$WORK"
