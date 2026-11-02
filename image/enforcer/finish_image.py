#!/usr/bin/env python3
"""Finish a built enforcer image, and check an enforcer release feed (ENF-m, NET-2 Hardening and Channel).

The enforcer shares no update source with agentOS (NET-2 Channel, D-229): its image trusts only the
enforcer's own release root, and no key that signs agentOS releases may sign, or ship in, an enforcer
release. This is the core's finish step (image/finish_image.py, imported, never copied) with the
enforcer's names, plus that key separation:

  finish_image.py OUT VERSION --root ROOT --agentos-key K [--agentos-key K ...]
      After mkosi: one counted boot entry enforcer_VERSION+3.conf, the ESP allowlist, the kernel
      command line allowlist (against this profile's mkosi.conf), no swap, root noexec, no private
      key outside /usr slot A, /usr verified against usrhash=, the /usr list, and the release
      manifest. Then: ROOT (the enforcer feed's root.json, which the image ships) holds no agentOS
      key, and no byte range of the disk, /usr included, holds one.
  finish_image.py --check-root --root ROOT --agentos-key K [--agentos-key K ...]
      ROOT alone, before a build: build.sh runs this first.
  finish_image.py --check-feed FEED --root ROOT --agentos-key K [--agentos-key K ...]
      Before a release is published: every metadata file in FEED/metadata is signed only by keys
      the enforcer's roots name, none of them an agentOS key, and ROOT is the feed's first root.

K is a PEM public key (agentos-release keygen's BASE.pub) or a TUF root.json, whose every key
counts. At least one is required: a build that names none would check nothing. A refusal names the
key's id and where it was found, never key bytes."""
import base64
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("core_finish", HERE.parent / "finish_image.py")
core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core)

MKOSI_CONF = HERE / "mkosi" / "mkosi.conf"
PREFIX = "enforcer_"
TRIES = core.TRIES
ESP_ALLOWED = (r"EFI/BOOT/[^/]+", r"EFI/systemd/[^/]+", r"loader/loader\.conf", r"loader/entries\.srel",
               r"loader/entries/enforcer_[^/]+\.conf")
# The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): a PEM public key is this plus the
# 32 key bytes, base64-encoded.
SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")
TUF_ROLES = ("root", "targets", "snapshot", "timestamp")


def keyid(raw):
    """The TUF key id go-tuf gives an Ed25519 key: sha256 of its canonical key object."""
    obj = {"keytype": "ed25519", "keyval": {"public": raw.hex()}, "scheme": "ed25519"}
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def root_keys(doc):
    """{keyid: raw 32 bytes} of every Ed25519 key a TUF root document declares. Raises ValueError on
    a key of another type: the enforcer's tooling makes only Ed25519, so anything else is unread."""
    signed = doc.get("signed") if isinstance(doc, dict) else None
    if not isinstance(signed, dict) or signed.get("_type") != "root" or not isinstance(signed.get("keys"), dict):
        raise ValueError("not a TUF root document")
    out = {}
    for kid, k in signed["keys"].items():
        pub = k.get("keyval", {}).get("public", "") if isinstance(k, dict) else ""
        if not (isinstance(k, dict) and k.get("keytype") == "ed25519" and re.fullmatch(r"[0-9a-f]{64}", pub or "")):
            raise ValueError("root key %s is not an Ed25519 key in hex" % kid)
        out[kid] = bytes.fromhex(pub)
    return out


def load_keys(path):
    """{keyid: raw} from a PEM Ed25519 public key or a TUF root.json."""
    data = pathlib.Path(path).read_bytes()
    m = re.search(rb"-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PUBLIC KEY-----", data)
    if m:
        der = base64.b64decode(b"".join(m.group(1).split()))
        if len(der) != 44 or not der.startswith(SPKI_ED25519):
            raise ValueError("%s: not an Ed25519 public key" % path)
        return {keyid(der[12:]): der[12:]}
    try:
        doc = json.loads(data)
    except ValueError:
        raise ValueError("%s: neither a PEM public key nor a TUF root.json" % path)
    return {keyid(raw): raw for raw in root_keys(doc).values()}


def agentos_keys(paths):
    if not paths:
        raise ValueError("no agentOS release key given (--agentos-key): the check would pass vacuously")
    out = {}
    for p in paths:
        out.update(load_keys(p))
    return out


def key_patterns(keys):
    """Byte patterns for each key, in every form a key file or binary would hold it: raw, hex (either
    case), base64 of the raw key, and base64 of its SPKI DER (a PEM body). Named by key id."""
    pats = []
    for kid, raw in sorted(keys.items()):
        forms = [raw, raw.hex().encode(), raw.hex().upper().encode(),
                 base64.b64encode(raw).rstrip(b"="), base64.b64encode(SPKI_ED25519 + raw).rstrip(b"=")]
        pats.append(("agentOS release key %s" % kid[:16], re.compile(b"|".join(re.escape(f) for f in forms))))
    return tuple(pats)


def root_violations(root_path, banned):
    """The shipped enforcer root must be a TUF root whose every key is outside the agentOS set, and
    whose roles name only keys it declares."""
    try:
        doc = json.loads(pathlib.Path(root_path).read_bytes())
        keys = root_keys(doc)
    except ValueError as e:
        return ["enforcer root %s: %s" % (root_path, e)]
    raws = {raw for raw in banned.values()}
    out = ["enforcer root key %s is an agentOS release key" % kid[:16]
           for kid, raw in sorted(keys.items()) if raw in raws or kid in banned]
    roles = doc["signed"].get("roles", {})
    for role in TUF_ROLES:
        ids = roles.get(role, {}).get("keyids") if isinstance(roles.get(role), dict) else None
        if not ids:
            out.append("enforcer root names no %s keys" % role)
            continue
        out += ["enforcer root's %s role names key %s it does not declare" % (role, k[:16]) for k in ids if k not in keys]
    return out


def disk_violations(img, banned):
    """Every agentOS key found anywhere on the disk image IMG, /usr slots included."""
    pats = key_patterns(banned)
    with open(img, "rb") as f:
        f.seek(0, 2)
        end = f.tell()
        return sorted({"%s at byte %d" % (what, off) for what, off, _ in core.scan_hits(f, 0, end, pats)})


def feed_violations(feed, root_path, banned):
    """FEED/metadata: every signature's key id is declared by one of the feed's roots and is not an
    agentOS key; the feed's roots declare no agentOS key; ROOT is byte for byte FEED's 1.root.json.
    Signatures are matched by key id only: a signature whose key id lies does not verify on the box
    (the client checks each against the key its root declares), so it cannot pass as the enforcer's."""
    meta = pathlib.Path(feed) / "metadata"
    files = sorted(meta.glob("*.json"))
    if not files:
        return ["feed %s has no metadata" % feed]
    out = []
    first = meta / "1.root.json"
    if not first.exists() or first.read_bytes() != pathlib.Path(root_path).read_bytes():
        out.append("the shipped root is not the feed's 1.root.json")
    raws = set(banned.values())
    declared = {}
    for f in files:
        if re.fullmatch(r"\d+\.root\.json", f.name):
            try:
                keys = root_keys(json.loads(f.read_bytes()))
            except ValueError as e:
                out.append("%s: %s" % (f.name, e))
                continue
            for kid, raw in keys.items():
                if raw in raws or kid in banned:
                    out.append("%s declares agentOS release key %s" % (f.name, kid[:16]))
                declared[kid] = raw
    for f in files:
        try:
            sigs = json.loads(f.read_bytes()).get("signatures")
        except (ValueError, AttributeError):
            out.append("%s: unreadable metadata" % f.name)
            continue
        if not isinstance(sigs, list) or not sigs:
            out.append("%s is unsigned" % f.name)
            continue
        for s in sigs:
            kid = s.get("keyid", "") if isinstance(s, dict) else ""
            if kid in banned:
                out.append("%s is signed with agentOS release key %s" % (f.name, kid[:16]))
            elif kid not in declared:
                out.append("%s is signed with key %s no enforcer root declares" % (f.name, str(kid)[:16]))
    return out


def counted_entry(src, version, tries=TRIES):
    """From mkosi's entry text, (file name, text) of the enforcer's counted entry for VERSION."""
    core.usrhash(src)
    body = [ln for ln in src.splitlines() if not re.match(r"(title|version|sort-key)\b", ln)]
    lines = ["title agentOS enforcer", "sort-key enforcer", "version %s" % version] + body
    return "%s%s+%d.conf" % (PREFIX, version, tries), "\n".join(lines) + "\n"


def esp_violations(paths, entry):
    allowed = set(core.boot_files(entry))
    return sorted(p for p in paths if p not in allowed and not any(re.fullmatch(a, p) for a in ESP_ALLOWED))


def main(out, version, root, agentos):
    banned = agentos_keys(agentos)
    bad = root_violations(root, banned)
    if bad:
        sys.exit("enforcer root is not the enforcer's own (NET-2 Channel): %s" % bad)
    out = pathlib.Path(out)
    img = out / ("enforcer_%s.raw" % version)
    fs = "%s@@%d" % (img, core.esp_offset(str(img)))
    names = subprocess.check_output(["mdir", "-i", fs, "-b", "::/loader/entries"], text=True).split()
    names = [n.rsplit("/", 1)[-1] for n in names if n.endswith(".conf")]
    if len(names) != 1:
        sys.exit("expected one mkosi boot entry, found %s" % names)
    src = subprocess.check_output(["mtype", "-i", fs, "::/loader/entries/" + names[0]], text=True)
    name, text = counted_entry(src, version)
    subprocess.run(["mcopy", "-o", "-i", fs, "-", "::/loader/entries/" + name], input=text.encode(), check=True)
    subprocess.run(["mdel", "-i", fs, "::/loader/entries/" + names[0]], check=True)
    subprocess.run(["mcopy", "-o", "-i", fs, "-", "::/loader/loader.conf"], input=core.LOADER_CONF.encode(), check=True)
    (out / name).write_text(text)
    listing = subprocess.check_output(["mdir", "-i", fs, "-/", "-b", "::/"], text=True).splitlines()
    paths = [p[3:] for p in listing if p.startswith("::/") and not p.endswith("/")]
    print("ESP:\n  " + "\n  ".join(sorted(paths)))
    table = core.partition_table(str(img))
    for what, bad in (
            ("ESP holds files outside the allowlist (HW-1)", esp_violations(paths, text)),
            ("boot entry has a kernel argument outside the allowlist (#1530)", core.cmdline_violations(text, MKOSI_CONF)),
            ("image could swap", core.swap_violations(table["partitions"], text)),
            ("code on the writable root could run (UPD-10)", core.noexec_violations(text)),
            ("disk holds a private key outside /usr (HW-1)", core.secret_violations(str(img), table)),
            ("disk carries an agentOS release key (NET-2 Channel)", disk_violations(str(img), banned))):
        if bad:
            sys.exit("%s: %s" % (what, bad))
    boot = {}
    for p in core.boot_files(text):
        data_ = subprocess.check_output(["mtype", "-i", fs, "::/" + p])
        boot[p] = hashlib.sha256(data_).hexdigest()
        if p in core.initrd_files(text):
            core.check_initrd(p, data_)
    roothash = core.usrhash(text)
    data, tree = out / ("enforcer_%s.usr.raw" % version), out / ("enforcer_%s.usr-verity.raw" % version)
    core.verify_usr(data, tree, roothash)
    bad = core.slot_a_violations(str(img), table, data, tree)
    if bad:
        sys.exit("/usr slot A on the disk is not the verified /usr, or holds a private key (HW-1): %s" % bad)
    print("/usr list: %d entries" % core.write_usr_list(data, out / ("enforcer_%s.usr.list" % version)))
    files = {p.name: core.sha256(p) for p in (data, tree)}
    m = core.manifest(version, roothash, name, text, files, boot)
    m["root_sha256"] = core.sha256(root)
    (out / ("enforcer_%s.release.json" % version)).write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    print(json.dumps(m, indent=2, sort_keys=True))


def parse(argv):
    pos, root, agentos, feed, only_root, i = [], None, [], None, False, 0
    while i < len(argv):
        a = argv[i]
        if a == "--check-root":
            only_root, i = True, i + 1
            continue
        if a in ("--root", "--agentos-key", "--check-feed"):
            if i + 1 >= len(argv):
                raise SystemExit("%s needs a value" % a)
            v = argv[i + 1]
            i += 2
            if a == "--root":
                root = v
            elif a == "--agentos-key":
                agentos.append(v)
            else:
                feed = v
            continue
        pos.append(a)
        i += 1
    if not root:
        raise SystemExit(__doc__)
    return pos, root, agentos, feed, only_root


if __name__ == "__main__":
    pos, root, agentos, feed, only_root = parse(sys.argv[1:])
    try:
        if only_root:
            if pos or feed is not None:
                raise SystemExit(__doc__)
            bad = root_violations(root, agentos_keys(agentos))
            if bad:
                sys.exit("enforcer root refused (NET-2 Channel): %s" % bad)
            print("enforcer root ok")
        elif feed is not None:
            if pos:
                raise SystemExit(__doc__)
            banned = agentos_keys(agentos)
            bad = root_violations(root, banned) + feed_violations(feed, root, banned)
            if bad:
                sys.exit("enforcer feed refused (NET-2 Channel): %s" % bad)
            print("enforcer feed ok: %d agentOS keys absent" % len(banned))
        elif len(pos) == 2:
            main(pos[0], pos[1], root, agentos)
        else:
            raise SystemExit(__doc__)
    except ValueError as e:
        sys.exit("finish_image: %s" % e)
