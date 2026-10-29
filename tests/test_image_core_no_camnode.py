"""CAM-node part (c) (#3513, briefs/CAM-node.md, "Split", part c): the core image must not contain
the camera node's binary. The core links camwire through CAM-clerk to read a node's stream; it must
never carry the node's server (broker/camnode), its element driver or its capture, nor the
agentos-camnode command, which belongs to the camera node image alone (image/camnode/).

The core image's manifest of Go binaries is what image/build.sh stages: each `go build` names a
./cmd/ directory. This test reads that list from the build script, checks no entry is the node's,
and asks Go for every package each one links (`go list -deps`), so a core binary that came to
import the node's server through another package fails here, not on a camera.
"""
# REQ: NET-2, DEV-3
import pathlib
import re
import shutil
import subprocess
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
BUILD = REPO / "image" / "build.sh"
MODULE = "github.com/ghbmrk/agentos/broker"
NODE_ONLY = (MODULE + "/camnode", MODULE + "/cmd/agentos-camnode")


def staged_commands(text):
    """The ./cmd/ directories image/build.sh builds into the core image: the `for cmd in ...` loop
    and every literal ./cmd/NAME."""
    cmds = set(re.findall(r"\./cmd/([A-Za-z0-9_.-]+)", text))
    loop = re.search(r"for cmd in (.*?); do", text, re.S)
    if loop:
        cmds |= set(loop.group(1).replace("\\\n", " ").split())
    return sorted(cmds)


def node_only(pkg):
    return any(pkg == p or pkg.startswith(p + "/") for p in NODE_ONLY)


class CoreImageHasNoCameraNode(unittest.TestCase):
    def test_staged_commands_are_read(self):
        cmds = staged_commands(BUILD.read_text())
        # The control: the parse finds the broker and the photo decoder, which the core ships.
        self.assertIn("agentosd", cmds)
        self.assertIn("agentos-photo", cmds)

    def test_core_build_names_no_node_binary(self):
        text = BUILD.read_text()
        self.assertNotIn("agentos-camnode", staged_commands(text))
        self.assertNotIn("camnode", text)
        for p in sorted((REPO / "image" / "mkosi").rglob("*")):
            if p.is_file():
                self.assertNotIn(b"camnode", p.read_bytes(), str(p.relative_to(REPO)))

    def test_parse_would_catch_the_node(self):
        planted = BUILD.read_text().replace("for cmd in agentosd ", "for cmd in agentosd agentos-camnode ", 1)
        self.assertIn("agentos-camnode", staged_commands(planted))
        self.assertTrue(node_only(MODULE + "/camnode/se"))
        self.assertFalse(node_only(MODULE + "/camwire"))
        self.assertFalse(node_only(MODULE + "/camnodex"))

    @unittest.skipUnless(shutil.which("go"), "go is not installed")
    def test_core_binaries_link_no_node_package(self):
        cmds = ["./cmd/" + c for c in staged_commands(BUILD.read_text())]
        p = subprocess.run(["go", "list", "-deps", "-f", "{{.ImportPath}}", *cmds], cwd=REPO / "broker",
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        found = set(p.stdout.split())
        self.assertTrue(any(f.startswith(MODULE + "/") for f in found), "go list read no broker package")
        self.assertEqual(sorted(f for f in found if node_only(f)), [])


if __name__ == "__main__":
    unittest.main()
