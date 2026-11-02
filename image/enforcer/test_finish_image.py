"""image/enforcer/finish_image.py's key separation (ENF-m acceptance test 2) and enforcer entry names.

REQ: NET-2
Run: python3 -m pytest image/enforcer/test_finish_image.py (no root, no network, no image build).
Keys here are random bytes standing in for Ed25519 public keys: the checks compare key bytes and ids,
never signatures, so no signing library is needed."""
import base64
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("enforcer_finish", HERE / "finish_image.py")
fi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fi)


def key():
    return os.urandom(32)


def pem(raw):
    b = base64.b64encode(fi.SPKI_ED25519 + raw).decode()
    return "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % b


def root_doc(roles, signers=None):
    """A TUF root: roles maps role -> list of raw keys; signers: raw keys whose ids sign it."""
    keys, rs = {}, {}
    for role, raws in roles.items():
        rs[role] = {"keyids": [fi.keyid(r) for r in raws], "threshold": 1}
        for r in raws:
            keys[fi.keyid(r)] = {"keytype": "ed25519", "keyval": {"public": r.hex()}, "scheme": "ed25519"}
    sigs = [{"keyid": fi.keyid(r), "sig": "00"} for r in (signers if signers is not None else roles["root"])]
    return {"signatures": sigs, "signed": {"_type": "root", "keys": keys, "roles": rs, "version": 1}}


def all_roles(raws):
    return {"root": raws[0:2], "targets": raws[2:4], "snapshot": raws[4:5], "timestamp": raws[5:6]}


class KeySeparation(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self.core = [key() for _ in range(6)]
        self.enf = [key() for _ in range(6)]
        (self.d / "core-root.json").write_text(json.dumps(root_doc(all_roles(self.core))))
        (self.d / "core-r1.pub").write_text(pem(self.core[0]))
        self.banned = fi.agentos_keys([str(self.d / "core-root.json")])

    def write(self, name, doc):
        p = self.d / name
        p.write_text(json.dumps(doc))
        return str(p)

    def test_own_root_passes(self):
        root = self.write("root.json", root_doc(all_roles(self.enf)))
        self.assertEqual(fi.root_violations(root, self.banned), [])

    def test_root_holding_any_core_key_refused(self):
        # One core key in any role of the enforcer root is a shared update source.
        for role, i in (("root", 0), ("targets", 2), ("snapshot", 4), ("timestamp", 5)):
            roles = all_roles(self.enf)
            roles[role] = roles[role][:-1] + [self.core[i]]
            root = self.write("root.json", root_doc(roles))
            bad = fi.root_violations(root, self.banned)
            self.assertTrue(any("is an agentOS release key" in b for b in bad), (role, bad))

    def test_core_root_itself_refused(self):
        self.assertTrue(fi.root_violations(str(self.d / "core-root.json"), self.banned))

    def test_pem_key_counts(self):
        banned = fi.agentos_keys([str(self.d / "core-r1.pub")])
        roles = all_roles(self.enf)
        roles["targets"] = [self.core[0]]
        bad = fi.root_violations(self.write("root.json", root_doc(roles)), banned)
        self.assertTrue(any("is an agentOS release key" in b for b in bad), bad)

    def test_no_agentos_key_given_refused(self):
        with self.assertRaises(ValueError):
            fi.agentos_keys([])

    def test_role_naming_undeclared_key_refused(self):
        doc = root_doc(all_roles(self.enf))
        doc["signed"]["roles"]["targets"]["keyids"].append(fi.keyid(key()))
        self.assertTrue(fi.root_violations(self.write("root.json", doc), self.banned))

    def test_non_root_refused(self):
        self.assertTrue(fi.root_violations(self.write("root.json", {"signed": {"_type": "targets"}}), self.banned))


class DiskScan(unittest.TestCase):
    def setUp(self):
        self.core = key()
        self.banned = {fi.keyid(self.core): self.core}
        self.d = pathlib.Path(tempfile.mkdtemp())

    def disk(self, payload, at=5 << 20):
        p = self.d / "disk.raw"
        with open(p, "wb") as f:
            f.truncate(64 << 20)  # sparse: the scan reads data extents only
            f.seek(at)
            f.write(os.urandom(4096) + payload + os.urandom(4096))
        return str(p)

    def test_clean_disk_passes(self):
        self.assertEqual(fi.disk_violations(self.disk(b"nothing to see"), self.banned), [])

    def test_every_form_of_a_core_key_refused(self):
        raw = self.core
        forms = {"raw": raw, "hex": raw.hex().encode(), "HEX": raw.hex().upper().encode(),
                 "base64": base64.b64encode(raw), "pem": pem(raw).encode(),
                 "root.json": json.dumps(root_doc(all_roles([raw] * 6))).encode()}
        for name, payload in forms.items():
            bad = fi.disk_violations(self.disk(payload), self.banned)
            self.assertTrue(bad and "agentOS release key" in bad[0], (name, bad))
            self.assertNotIn(raw.hex(), " ".join(bad))  # names the id, never the key

    def test_key_across_a_chunk_boundary_found(self):
        at = fi.core.SCAN_CHUNK - 10 - 4096
        self.assertTrue(fi.disk_violations(self.disk(self.core.hex().encode(), at=at), self.banned))


class Feed(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self.core = [key() for _ in range(6)]
        self.enf = [key() for _ in range(6)]
        self.banned = {fi.keyid(r): r for r in self.core}
        (self.d / "feed" / "metadata").mkdir(parents=True)
        self.root = root_doc(all_roles(self.enf))
        self.put("1.root.json", self.root)
        self.put("1.targets.json", {"signatures": [{"keyid": fi.keyid(self.enf[2]), "sig": "00"}], "signed": {}})
        self.put("timestamp.json", {"signatures": [{"keyid": fi.keyid(self.enf[5]), "sig": "00"}], "signed": {}})
        self.shipped = self.d / "root.json"
        self.shipped.write_bytes((self.d / "feed" / "metadata" / "1.root.json").read_bytes())

    def put(self, name, doc):
        (self.d / "feed" / "metadata" / name).write_text(json.dumps(doc))

    def check(self):
        return fi.feed_violations(str(self.d / "feed"), str(self.shipped), self.banned)

    def test_own_feed_passes(self):
        self.assertEqual(self.check(), [])

    def test_release_signed_with_core_key_refused(self):
        self.put("1.targets.json", {"signatures": [{"keyid": fi.keyid(self.enf[2]), "sig": "00"},
                                                   {"keyid": fi.keyid(self.core[2]), "sig": "00"}], "signed": {}})
        self.assertTrue(any("signed with agentOS release key" in b for b in self.check()))

    def test_signer_no_root_declares_refused(self):
        self.put("timestamp.json", {"signatures": [{"keyid": fi.keyid(key()), "sig": "00"}], "signed": {}})
        self.assertTrue(any("no enforcer root declares" in b for b in self.check()))

    def test_rotated_root_adding_core_key_refused(self):
        roles = all_roles(self.enf)
        roles["targets"] = [self.enf[2], self.core[3]]
        self.put("2.root.json", root_doc(roles, signers=self.enf[0:2]))
        self.assertTrue(any("2.root.json declares agentOS release key" in b for b in self.check()))

    def test_unsigned_metadata_refused(self):
        self.put("1.snapshot.json", {"signatures": [], "signed": {}})
        self.assertTrue(any("unsigned" in b for b in self.check()))

    def test_shipped_root_must_be_the_feeds(self):
        self.shipped.write_text(json.dumps(root_doc(all_roles([key() for _ in range(6)]))))
        self.assertTrue(any("not the feed's 1.root.json" in b for b in self.check()))


class Entry(unittest.TestCase):
    def test_counted_entry_named_for_the_enforcer(self):
        src = "title Debian\nversion 6.12\nlinux /x/linux\ninitrd /x/initrd\noptions usrhash=%s quiet\n" % ("a" * 64)
        name, text = fi.counted_entry(src, "20261102.1")
        self.assertEqual(name, "enforcer_20261102.1+3.conf")
        self.assertIn("sort-key enforcer\n", text)
        self.assertEqual(fi.esp_violations(["loader/entries/" + name, "x/linux", "x/initrd"], text), [])
        self.assertEqual(fi.esp_violations(["loader/entries/agentos_1+3.conf"], text), ["loader/entries/agentos_1+3.conf"])

    def test_cmdline_is_this_profiles(self):
        words = " ".join(fi.core.config_cmdline(fi.MKOSI_CONF))
        ok = "options usrhash=%s %s\n" % ("b" * 64, words)
        self.assertEqual(fi.core.cmdline_violations(ok, fi.MKOSI_CONF), [])
        self.assertTrue(fi.core.cmdline_violations(ok.rstrip() + " usbcore.authorized_default=1\n", fi.MKOSI_CONF))
        self.assertEqual(fi.core.noexec_violations(ok), [])
        self.assertEqual(fi.core.swap_violations([], ok), [])


if __name__ == "__main__":
    sys.exit(unittest.main())
