# HW-3t supported-host text and test (#1003): the owner's guide says which PCs can run agentOS and
# which cannot, and the image stays UEFI-only and x86-64. REQ: HW-3, HW-7
#
# The guide half reads docs/owners-guide.md's <!-- host: ... --> items. The image half reads
# image/mkosi/mkosi.conf and .github/workflows/image.yml and changes neither (image/ is tier A);
# each check takes a path, so the mutant cases below feed it a planted one-line copy.
import pathlib
import re
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "owners-guide.md"
MKOSI = ROOT / "image" / "mkosi" / "mkosi.conf"
WORKFLOW = ROOT / ".github" / "workflows" / "image.yml"
HOSTS_HEADING = "Which PCs can run agentOS"
START_HEADING = "Starting agentOS on your PC"
UNSUPPORTED = ("windows-on-arm", "pre-uefi", "mac")
REFUSES = re.compile(r"does not support|do not support|not supported|cannot run|can't run", re.I)


def section(text, title):
    _, sep, rest = text.partition("\n## " + title + "\n")
    if not sep:
        raise AssertionError(f"guide has no section {title!r}")
    return rest.split("\n## ", 1)[0]


def host_items(text):
    """Maps each host class to the list items carrying its marker."""
    items = {}
    for m in re.finditer(r"^- <!-- host: ([a-z0-9 -]+?) -->(.*)$", text, re.M):
        items.setdefault(m.group(1), []).append(m.group(2).strip())
    return items


def markers(text):
    return re.findall(r"<!-- host: ([a-z0-9 -]+?) -->", text)


class GuideTest(unittest.TestCase):
    def setUp(self):
        self.guide = GUIDE.read_text()
        self.items = host_items(self.guide)

    def one(self, key):
        self.assertEqual(markers(self.guide).count(key), 1, f"guide must mark {key!r} exactly once")
        self.assertEqual(len(self.items.get(key, [])), 1, f"{key!r} marker must start a list item")
        return self.items[key][0]

    def test_supported_class_named(self):
        item = self.one("supported")
        self.assertRegex(item, r"Intel|AMD")
        self.assertIn("UEFI", item)

    def test_unsupported_classes_named(self):
        for cls in UNSUPPORTED:
            with self.subTest(cls=cls):
                item = self.one("unsupported " + cls)
                self.assertTrue(item, f"{cls} item is empty")
                self.assertRegex(item, REFUSES)

    def test_mac_not_supported_and_no_vm_promise(self):
        mac = self.one("unsupported mac")
        self.assertRegex(mac, re.compile(r"not support|not supported", re.I))
        for claim in ("cannot start", "can't start", "won't start", "will not start", "does not start"):
            self.assertNotIn(claim, mac.lower())
        for items in self.items.values():
            for item in items:
                self.assertNotRegex(item, re.compile(r"virtual machine|\bVM\b|Parallels|VirtualBox|UTM", re.I))

    def test_items_sit_in_their_section(self):
        # Every host item is in the list, after the start-up section, so the pointer lands on it.
        hosts = section(self.guide, HOSTS_HEADING)
        self.assertEqual(sorted(markers(hosts)), sorted(markers(self.guide)))
        order = [h for h in re.findall(r"^## (.+)$", self.guide, re.M)]
        self.assertEqual(order.index(HOSTS_HEADING), order.index(START_HEADING) + 1)

    def test_did_not_start_points_to_list(self):
        self.assertIn("\n## " + HOSTS_HEADING + "\n", self.guide)
        start = section(self.guide, START_HEADING)
        paras = [p for p in start.split("\n\n") if "did not start from the drive" in p]
        self.assertEqual(len(paras), 1, "one paragraph says the PC did not start from the drive")
        self.assertIn(HOSTS_HEADING, paras[0])


def mkosi_settings(path):
    """Maps each key=value setting in an mkosi.conf to its values, comments and continuations skipped."""
    out = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if not line or line[0] in "#[ \t":
            continue
        key, sep, value = line.partition("=")
        if sep:
            out.setdefault(key.strip(), []).append(value.strip())
    return out


def uefi_only_problems(path):
    s = mkosi_settings(path)
    problems = [f"{k} must be {v}" for k, v in
                (("BiosBootloader", "none"), ("Bootloader", "systemd-boot"), ("ShimBootloader", "signed"))
                if s.get(k) != [v]]
    problems += [f"Architecture={a} is not x86-64" for a in s.get("Architecture", []) if a != "x86-64"]
    return problems


def runner_problems(path):
    """Each job under jobs: names a runs-on, with no ARM label or expression that could pick one."""
    lines = pathlib.Path(path).read_text().splitlines()
    start = lines.index("jobs:")
    jobs, problems = {}, []
    job = None
    for line in lines[start + 1:]:
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            job = m.group(1)
            jobs[job] = []
        elif re.match(r"^\S", line):
            break
        elif job:
            r = re.match(r"^    runs-on:\s*(.*)$", line)
            if r:
                jobs[job].append(r.group(1).strip())
    if not jobs:
        problems.append("no jobs")
    for job, runs in jobs.items():
        if len(runs) != 1:
            problems.append(f"{job}: needs one runs-on, has {runs}")
        for r in runs:
            if re.search(r"arm|aarch64|\$\{\{|^\s*$", r, re.I):
                problems.append(f"{job}: runs-on {r!r} is not a plain x86-64 runner")
    return problems


def mutant(path, old, new):
    text = pathlib.Path(path).read_text()
    assert old in text, f"{old!r} not in {path}"
    d = tempfile.mkdtemp()
    p = pathlib.Path(d) / pathlib.Path(path).name
    p.write_text(text.replace(old, new, 1))
    return p


class ImageTest(unittest.TestCase):
    def test_uefi_only(self):
        self.assertEqual(uefi_only_problems(MKOSI), [])

    def test_uefi_only_catches_mutants(self):
        for old, new in (("BiosBootloader=none", "BiosBootloader=grub"),
                         ("Bootloader=systemd-boot", "Bootloader=grub"),
                         ("ShimBootloader=signed", "ShimBootloader=none"),
                         ("[Content]\n", "[Content]\nArchitecture=arm64\n"),
                         ("BiosBootloader=none\n", "")):
            with self.subTest(mutant=new):
                self.assertNotEqual(uefi_only_problems(mutant(MKOSI, old, new)), [])
        self.assertEqual(uefi_only_problems(mutant(MKOSI, "[Content]\n", "[Content]\nArchitecture=x86-64\n")), [])

    def test_image_built_on_x86_64(self):
        self.assertEqual(runner_problems(WORKFLOW), [])

    def test_image_built_on_x86_64_catches_mutants(self):
        for old, new in (("runs-on: ubuntu-24.04", "runs-on: ubuntu-24.04-arm"),
                         ("runs-on: ubuntu-latest", "runs-on: ${{ matrix.runner }}"),
                         ("runs-on: ubuntu-24.04", "runs-on: [self-hosted, ARM64]")):
            with self.subTest(mutant=new):
                self.assertNotEqual(runner_problems(mutant(WORKFLOW, old, new)), [])


if __name__ == "__main__":
    unittest.main()
