#!/bin/sh
# Stage the local inference service (INFER-image, #3655; INFER-SVC E2): agentos-infer with the
# llama.cpp adapter, the pinned llama-server built from source (image/llamaserver.sh), the pinned
# embedding model, and both licence texts. agentosd.service names the model and its hash, and leaves
# -infer off until a retrieve row consumes the service (D-230). Its own script, so image/build.sh
# keeps no build tag: infer_llamacpp applies to this binary alone.
#
# Usage: infer.sh STAGE WORK
# Writes, under STAGE (the image tree):
#   usr/lib/agentos/agentos-infer                      the service (static, CGO_ENABLED=0)
#   usr/lib/agentos/infer/llama-server                 its runtime (static), agentos-infer's -runtime default
#   usr/lib/agentos/infer/Qwen3-Embedding-0.6B-Q8_0.gguf  the model, 0644 under the read-only /usr (INFER-A2)
#   usr/share/licenses/llama.cpp/LICENSE               MIT
#   usr/share/licenses/Qwen3-Embedding-0.6B/LICENSE    Apache-2.0
# Builds and downloads in WORK (a fixed path, for reproducibility) and removes it after.
# INFER_MODEL=<file> uses a local copy of the model (still hash-checked). Needs what llamaserver.sh
# needs, plus Go and python3. Network: the llama.cpp source on github.com and the model on
# huggingface.co (with its CDN).
set -eu
# A go.work in the repo would override broker/go.mod, go.sum and vendor/ (#4007 Security).
export GOWORK=off
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
PINS=$REPO/broker/cmd/agentos-infer/llama.pins
pin() { sed -n "s/^$1=//p" "$PINS"; }
STAGE=$(realpath -m "$1"); WORK=$(realpath -m "$2")
MODEL=Qwen3-Embedding-0.6B-Q8_0.gguf
rm -rf "$WORK"; mkdir -p "$WORK"

(cd "$REPO/broker" && CGO_ENABLED=0 go build -tags infer_llamacpp -trimpath -ldflags=-buildid= \
	-o "$STAGE/usr/lib/agentos/agentos-infer" ./cmd/agentos-infer)
sh "$HERE/llamaserver.sh" "$WORK/server" "$WORK/llama"

if [ -n "${INFER_MODEL:-}" ]; then
	cp "$INFER_MODEL" "$WORK/model.gguf"
else
	curl -fsSL --retry 3 --retry-delay 5 -o "$WORK/model.gguf" "$(pin embed_url)"
fi
GOT=$(sha256sum "$WORK/model.gguf" | cut -d' ' -f1)
[ "$GOT" = "$(pin embed_sha256)" ] || { echo "model: sha256 $GOT; embed_sha256 in $PINS is $(pin embed_sha256)" >&2; exit 1; }
# INFER-A4: the licence the exact file declares, read from its own header, must be Apache-2.0.
LIC=$(python3 -I "$HERE/gguf_licence.py" "$WORK/model.gguf")
[ "$LIC" = apache-2.0 ] || { echo "model: general.license is '$LIC', not apache-2.0 (INFER-A4)" >&2; exit 1; }
echo "model: $MODEL sha256 $GOT, $(stat -c %s "$WORK/model.gguf") bytes, licence $LIC"

install -D -m 0755 "$WORK/server/llama-server" "$STAGE/usr/lib/agentos/infer/llama-server"
install -D -m 0644 "$WORK/model.gguf" "$STAGE/usr/lib/agentos/infer/$MODEL"
install -D -m 0644 "$WORK/server/LICENSE" "$STAGE/usr/share/licenses/llama.cpp/LICENSE"
# The model card names Apache-2.0 and the repository ships no licence file; the text is the
# Apache License 2.0, which is this repository's own LICENSE.
install -D -m 0644 "$REPO/LICENSE" "$STAGE/usr/share/licenses/Qwen3-Embedding-0.6B/LICENSE"
rm -rf "$WORK"
