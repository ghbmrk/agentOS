"""INFER-image (#3655; briefs/INFER-SVC.md E2): the image ships llama-server built from the pinned
llama.cpp source and the pinned Apache-2.0 embedding model, both checked by SHA-256 at build, with
their licence texts, the agentos-infer user, and agentosd's -infer-* flags naming the installed
model and its pin, while -infer itself stays off until a retrieve row consumes the service (D-230).
The booted image runs the real test on the installed files (image/ci_boot.sh, INFER).

Kept apart from tests/test_image.py, which several open PRs edit (D-111)."""
# REQ: CAP-13, RES-2, RES-3
import pathlib
import re
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMG = ROOT / "image"
MK = IMG / "mkosi"
UNIT = MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service"
SYSUSERS = MK / "mkosi.extra/usr/lib/sysusers.d/agentos-setup.conf"
PINS = ROOT / "broker/cmd/agentos-infer/llama.pins"
MODEL = "/usr/lib/agentos/infer/Qwen3-Embedding-0.6B-Q8_0.gguf"
SERVER = "/usr/lib/agentos/infer/llama-server"
HEX = re.compile(r"^[0-9a-f]{64}$")


def pins():
    out = {}
    for line in PINS.read_text().splitlines():
        if line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v
    return out


def exec_words():
    lines, cont = [], False
    for line in UNIT.read_text().splitlines():
        if line.startswith("ExecStart=") or cont:
            lines.append(line[len("ExecStart="):] if not cont else line)
            cont = line.endswith("\\")
    return " ".join(l.rstrip("\\") for l in lines).split()


def gguf(kvs, version=3):
    """A GGUF header with the given (key, type, payload bytes) pairs and no tensors."""
    def s(b):
        return struct.pack("<Q", len(b)) + b
    body = b"".join(s(k) + struct.pack("<I", t) + p for k, t, p in kvs)
    return b"GGUF" + struct.pack("<IQQ", version, 0, len(kvs)) + body


def text(v):
    return struct.pack("<Q", len(v)) + v


def licence(data):
    with tempfile.NamedTemporaryFile(suffix=".gguf") as f:
        f.write(data)
        f.flush()
        return subprocess.run([sys.executable, "-I", str(IMG / "gguf_licence.py"), f.name],
                              capture_output=True, text=True)


class TestInferImage(unittest.TestCase):
    def test_both_pins_are_sha256_values_the_build_checks(self):
        p = pins()
        self.assertRegex(p["llama_src_sha256"], HEX, "take the pin from the infer-real run's download")
        self.assertRegex(p["embed_sha256"], HEX)
        self.assertTrue(p["llama_src_url"].startswith("https://github.com/ggml-org/llama.cpp/"))
        self.assertTrue(p["embed_url"].startswith("https://huggingface.co/"))
        # The model is pinned at a revision (a commit id), never a moving branch.
        self.assertRegex(p["embed_url"], r"/resolve/[0-9a-f]{40}/")
        server = (IMG / "llamaserver.sh").read_text()
        self.assertIn('WANT=$(pin llama_src_sha256)', server)
        self.assertIn('[ "$GOT" = "$WANT" ] || {', server)
        infer = (IMG / "infer.sh").read_text()
        self.assertIn('[ "$GOT" = "$(pin embed_sha256)" ] || {', infer)
        # The prebuilt release asset is gone: the server tested is the one built from the pin.
        self.assertNotIn("llama_url", p)

    def test_the_server_is_static_cpu_only_and_fetches_nothing(self):
        s = (IMG / "llamaserver.sh").read_text()
        for f in ("-DGGML_NATIVE=OFF", "-DCMAKE_EXE_LINKER_FLAGS=-static", "-DBUILD_SHARED_LIBS=OFF",
                  "-DGGML_BACKEND_DL=OFF", "-DLLAMA_CURL=OFF", "-DLLAMA_OPENSSL=OFF", "-DGGML_AVX2=ON"):
            self.assertIn(f, s)
        for gpu in ("CUDA", "VULKAN", "METAL", "HIP", "SYCL", "OPENCL"):
            self.assertNotIn("-DGGML_%s=ON" % gpu, s)
        self.assertIn('! readelf -l "$BIN" | grep -q INTERP ||', s)
        # infer-real runs the real test on this same build (INFER-A13).
        wf = (ROOT / ".github/workflows/infer-real.yml").read_text()
        self.assertIn('sh image/llamaserver.sh "$RUNNER_TEMP/llama/server"', wf)
        self.assertIn('AGENTOS_LLAMA_SERVER=$d/server/llama-server', wf)
        self.assertIn("image/llamaserver.sh", wf.split("workflow_dispatch")[0])

    def test_the_build_installs_the_service_runtime_model_and_licences(self):
        b = (IMG / "build.sh").read_text()
        self.assertIn('sh "$HERE/infer.sh" "$STAGE" "$OUT/infer"', b)
        s = (IMG / "infer.sh").read_text()
        self.assertIn("go build -tags infer_llamacpp", s)
        self.assertIn('"$STAGE/usr/lib/agentos/agentos-infer"', s)
        self.assertIn('install -D -m 0755 "$WORK/server/llama-server" "$STAGE%s"' % SERVER, s)
        self.assertIn('install -D -m 0644 "$WORK/model.gguf" "$STAGE/usr/lib/agentos/infer/$MODEL"', s)
        self.assertEqual("/usr/lib/agentos/infer/" + re.search(r"^MODEL=(\S+)$", s, re.M).group(1), MODEL)
        self.assertIn('"$STAGE/usr/share/licenses/llama.cpp/LICENSE"', s)
        self.assertIn('install -D -m 0644 "$REPO/LICENSE" "$STAGE/usr/share/licenses/Qwen3-Embedding-0.6B/LICENSE"', s)
        lic = (ROOT / "LICENSE").read_text()
        self.assertIn("Apache License\n                           Version 2.0, January 2004", lic)
        self.assertIn("END OF TERMS AND CONDITIONS", lic)
        notice = (ROOT / "NOTICE").read_text()
        for n in ("llama.cpp release b11900", "Qwen3-Embedding-0.6B", "/usr/share/licenses/llama.cpp/LICENSE",
                  "/usr/share/licenses/Qwen3-Embedding-0.6B/LICENSE"):
            self.assertIn(n, notice)

    def test_the_service_finds_its_runtime_where_the_image_puts_it(self):
        main = (ROOT / "broker/cmd/agentos-infer/main.go").read_text()
        self.assertIn('flag.StringVar(&runtime, "runtime", "%s",' % SERVER, main)

    def test_the_build_refuses_a_model_not_under_apache_2(self):
        s = (IMG / "infer.sh").read_text()
        self.assertIn('LIC=$(python3 -I "$HERE/gguf_licence.py" "$WORK/model.gguf")', s)
        self.assertIn('[ "$LIC" = apache-2.0 ] || {', s)

    def test_the_licence_is_read_from_the_files_own_header(self):
        arch = (b"general.architecture", 8, text(b"qwen3"))
        vocab = (b"tokenizer.ggml.tokens", 9, struct.pack("<IQ", 8, 2) + text(b"a") + text(b"b"))
        scores = (b"tokenizer.ggml.scores", 9, struct.pack("<IQ", 6, 3) + struct.pack("<3f", 0, 1, 2))
        dim = (b"qwen3.embedding_length", 4, struct.pack("<I", 1024))
        for lic in ("apache-2.0", "mit"):
            r = licence(gguf([arch, vocab, scores, dim, (b"general.license", 8, text(lic.encode()))]))
            self.assertEqual((r.returncode, r.stdout.strip()), (0, lic))
        for name, data in (("no licence key", gguf([arch, dim])),
                           ("not GGUF", b"GGML" + gguf([arch])[4:]),
                           ("version 1", gguf([arch], version=1)),
                           ("licence not a string", gguf([(b"general.license", 4, struct.pack("<I", 2))])),
                           ("truncated", gguf([(b"general.license", 8, text(b"apache-2.0"))])[:-3]),
                           ("string past the bound", gguf([(b"general.license", 8, struct.pack("<Q", 1 << 40))])),
                           ("unknown type", gguf([(b"x", 99, b""), (b"general.license", 8, text(b"apache-2.0"))]))):
            r = licence(data)
            self.assertEqual(r.returncode, 1, name)
            self.assertEqual(r.stdout, "", name)

    def test_the_unit_names_the_pinned_model_and_leaves_infer_off(self):
        w = exec_words()
        arg = {w[i]: w[i + 1] for i in range(len(w) - 1) if w[i].startswith("-infer-")}
        self.assertEqual(arg.get("-infer-uid"), "@uid:agentos-infer")
        self.assertEqual(arg.get("-infer-model"), MODEL)
        self.assertEqual(arg.get("-infer-model-sha256"), pins()["embed_sha256"])
        # Off until a retrieve row consumes it (D-230): no spelling of -infer is passed.
        for x in w:
            self.assertFalse(re.match(r"^--?infer(=|$)", x), x)
        users = [l.split()[1] for l in SYSUSERS.read_text().splitlines() if l.startswith("u ")]
        self.assertIn("agentos-infer", users)

    def test_the_booted_image_runs_the_real_test_on_the_installed_files(self):
        boot = (IMG / "ci_boot.sh").read_text()
        self.assertIn("AGENTOS_LLAMA_SERVER=%s AGENTOS_LLAMA_EMBED_MODEL=%s" % (SERVER, MODEL), boot)
        self.assertIn("PIN=$(sed -n 's/^embed_sha256=//p' \"$HERE/../broker/cmd/agentos-infer/llama.pins\")", boot)
        self.assertIn("User=agentos-infer", boot)
        self.assertIn('has "$W/console-infer.log" "PASS: TestRealRuntimeEmbed"', boot)
        wf = (ROOT / ".github/workflows/image.yml").read_text()
        self.assertIn("go test -c -tags infer_real,infer_llamacpp", wf)
        self.assertIn('INFER="$RUNNER_TEMP/infer" image/ci_boot.sh', wf)


if __name__ == "__main__":
    unittest.main()
