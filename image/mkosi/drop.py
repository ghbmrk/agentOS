#!/usr/bin/env python3
"""Purge packages the box does not need, then refuse a tree that links a library it lacks (#2919).

mkosi.postinst runs this with the image tree's path, before it copies dpkg's status file out for the
known-vulnerability scan (EVL-5), so the scan and the package manifest see the packages gone. Each
package below is a hard dependency of one the box keeps, so apt would remove the keeper with it;
dpkg purges it with --force-depends instead, and FILES removes what used it. The NEEDED check then
fails the build if any ELF file under usr still names a library a dropped package shipped: a forced
purge must not leave a binary that cannot load. The #! check does the same for an executable script
whose interpreter a dropped package shipped (perl), bar the package tools in PERL_TOOLS.

Source names are Debian's (what the advisories and assurance/vulncheck.json name); a dropped
source has no image record there (tests/test_image_drop.py)."""
import glob
import os
import stat
import struct
import subprocess
import sys

# package: (its Debian source, why the box does not need it)
DROP = {
    "libbluetooth3": ("bluez", "only NetworkManager's Bluetooth device plugin links it; the image ships no Bluetooth (#1415)"),
    "libmm-glib0": ("modemmanager", "only NetworkManager's WWAN plugins link it; the image has no ModemManager"),
    "libnewt0.52": ("newt", "only nmtui links it; the box has no console login"),
    "libslang2": ("slang2", "only libnewt0.52 links it"),
    "initramfs-tools": ("initramfs-tools", "mkosi builds the initrd itself (InitrdInclude=); the kernel package depends on it"),
    "initramfs-tools-core": ("initramfs-tools", "as initramfs-tools"),
    "initramfs-tools-bin": ("initramfs-tools", "as initramfs-tools"),
    "dracut-install": ("dracut", "only initramfs-tools-core needs it"),
    "cpio": ("cpio", "only initramfs-tools-core needs it"),
    "mokutil": ("mokutil", "shim-signed-common depends on it; it edits shim's MOK list from a shell, and the box has none"),
    "libefivar1t64": ("efivar", "only mokutil links it"),
    "tar": ("tar", "Essential, but nothing on the box runs it: build.sh and mkosi unpack on the build host"),
    "diffutils": ("diffutils", "Essential, but nothing on the box runs diff or cmp"),
    "perl-base": ("perl", "Essential, but only package maintainer scripts run perl, and the box runs no package manager"),
    "libsqlite3-0": ("sqlite3", "only liblastlog2-2 links it"),
    "liblastlog2-2": ("util-linux", "only lslogins links it, an account-listing tool for a person at a shell; the box has no login"),
    "libtirpc3t64": ("libtirpc", "only ss links it (RPC service names); nothing on the box runs ss"),
    "libtirpc-common": ("libtirpc", "only libtirpc3t64 reads its /etc/netconfig"),
    "passwd": ("shadow", "useradd and the other account tools; only maintainer scripts run them, and systemd-sysusers makes the box's users"),
    "login.defs": ("shadow", "the account tools' settings; without it systemd-sysusers keeps its built-in id ranges, and the box has no login"),
    "adduser": ("adduser", "a front end to useradd that only maintainer scripts run"),
    "libsemanage2": ("libsemanage", "only useradd, userdel and usermod link it"),
    "libsemanage-common": ("libsemanage", "only libsemanage2 reads it"),
    "libsepol2": ("libsepol", "only libsemanage2 links it"),
    "libbz2-1.0": ("bzip2", "only libsemanage2 and dpkg-deb link it; the box unpacks no package"),
}
# Dropped packages whose source the box still runs other packages of, so the source's image
# records stay (tests/test_image_drop.py).
PARTIAL = ("liblastlog2-2",)
# Essential packages: dpkg removes them only with --force-remove-essential, in a second call after
# the rest, so no other package's removal script finds perl or diff already gone.
ESSENTIAL = ("tar", "diffutils", "perl-base")
# Files a kept package ships that link a dropped one. Each pattern must match: a stale one fails.
FILES = (
    "usr/lib/x86_64-linux-gnu/NetworkManager/*/libnm-device-plugin-bluetooth.so",
    "usr/lib/x86_64-linux-gnu/NetworkManager/*/libnm-device-plugin-wwan.so",
    "usr/lib/x86_64-linux-gnu/NetworkManager/*/libnm-wwan.so",
    "usr/bin/nmtui*",
    "usr/bin/ss",
    "usr/bin/lslogins",
    # dpkg's package unpacker, the last file linking libbz2; the box's dpkg database never changes.
    "usr/bin/dpkg-deb",
    # dpkg's daily database backup runs tar and cmp; the box's dpkg database never changes.
    "usr/lib/systemd/system/dpkg-db-backup.service",
    "usr/lib/systemd/system/dpkg-db-backup.timer",
    "usr/libexec/dpkg/dpkg-db-backup",
)
# Kept packages whose perl scripts stay, unrunnable: package and admin tools that only maintainer
# scripts or a person at a shell would start, and the box runs neither. The #! check refuses a perl
# script from any other package, and a package here that ships none is stale.
PERL_TOOLS = {
    "debconf": "debconf and its frontends, run by maintainer scripts",
    "init-system-helpers": "deb-systemd-helper, deb-systemd-invoke, update-rc.d (maintainer scripts)",
    "libpam-runtime": "pam-auth-update, pam_getenv",
    "linux-base": "the kernel package's install hooks",
    "openssl": "c_rehash, CA.pl, tsget.pl",
    "sgml-base": "SGML catalog tools (maintainer scripts)",
    "xml-core": "XML catalog tools (maintainer scripts)",
}
ET_EXEC, ET_DYN, EM_X86_64 = 2, 3, 62
PT_LOAD, PT_DYNAMIC = 1, 2
DT_NEEDED, DT_STRTAB = 1, 5


def dynamic(data):
    """The NEEDED names of a 64-bit little-endian x86-64 executable or shared object, or None for
    any other file."""
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        return None
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_type not in (ET_EXEC, ET_DYN) or e_machine != EM_X86_64:
        return None
    phoff, = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    loads, dyn = [], None
    for i in range(phnum):
        off = phoff + i * phentsize
        if off + 56 > len(data):
            raise ValueError("program header past the end of the file")
        p_type, _, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<IIQQQQ", data, off)
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == PT_DYNAMIC:
            dyn = (p_offset, p_filesz)
    if dyn is None:
        return []
    tags = []
    for off in range(dyn[0], min(dyn[0] + dyn[1], len(data)) - 15, 16):
        tag, val = struct.unpack_from("<qQ", data, off)
        if tag == 0:
            break
        tags.append((tag, val))
    if not any(t == DT_NEEDED for t, _ in tags):
        return []  # also a separate debug file, whose dynamic section holds no bytes
    strtab = next((v for t, v in tags if t == DT_STRTAB), None)
    if strtab is None:
        raise ValueError("a dynamic section with no string table")
    base = next((o + strtab - va for va, o, sz in loads if va <= strtab < va + sz), None)
    if base is None:
        raise ValueError("string table outside every loaded segment")

    def string(v):
        end = data.find(b"\0", base + v)
        if end < 0:
            raise ValueError("unterminated string")
        return data[base + v:end].decode(errors="surrogateescape")

    return [string(v) for t, v in tags if t == DT_NEEDED]


def needed_violations(root, gone, top="usr"):
    """One line per ELF file under TOP whose NEEDED names a library in GONE, the file names the
    dropped packages shipped. Only those: a gap the stock packages already have is not this check's."""
    out = []
    for d, dirs, files in os.walk(os.path.join(root, top)):
        dirs.sort()
        for n in sorted(files):
            p = os.path.join(d, n)
            rel = os.path.relpath(p, root)
            if not stat.S_ISREG(os.lstat(p).st_mode):
                continue
            with open(p, "rb") as f:
                head = f.read(64)
                if len(head) < 64 or head[:6] != b"\x7fELF\x02\x01":
                    continue
                e_type, e_machine = struct.unpack_from("<HH", head, 16)
                if e_type not in (ET_EXEC, ET_DYN) or e_machine != EM_X86_64:
                    continue
                data = head + f.read()
            try:
                needed = dynamic(data)
            except (ValueError, struct.error) as e:
                out.append("%s: unreadable dynamic section (%s)" % (rel, e))
                continue
            out += ["%s: needs %s, which a dropped package shipped" % (rel, lib) for lib in needed if lib in gone]
    return out


def shipped(paths):
    """The library file names among the paths dpkg-query -L lists."""
    return {os.path.basename(p) for p in paths if ".so" in os.path.basename(p)}


def usr_path(p):
    """P with the merged-/usr /bin and /sbin spelled under /usr."""
    return "/usr" + p if p.startswith(("/bin/", "/sbin/")) else p


def programs(paths):
    """The programs among the paths dpkg-query -L lists, as /usr paths."""
    return {usr_path(p) for p in paths if os.path.dirname(usr_path(p)) in ("/usr/bin", "/usr/sbin")}


def interpreter(line):
    """The program a #! line runs: its interpreter, or the command /usr/bin/env runs. None for a
    line that is not #!."""
    if not line.startswith(b"#!"):
        return None
    words = line[2:].decode(errors="surrogateescape").split()
    if not words:
        return ""
    if usr_path(words[0]) == "/usr/bin/env":
        args = [w for w in words[1:] if not w.startswith("-") and "=" not in w]
        return args[0] if args else ""
    return usr_path(words[0])


def owners(root):
    """Each installed file's package, from dpkg's file lists in the tree: {"/usr/bin/x": "pkg"}."""
    out = {}
    for lst in sorted(glob.glob(os.path.join(root, "var/lib/dpkg/info/*.list"))):
        pkg = os.path.basename(lst)[:-len(".list")].split(":")[0]
        with open(lst, encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                out[usr_path(line.rstrip("\n"))] = pkg
    return out


def interpreter_violations(root, gone, allowed=(), top="usr"):
    """One line per executable script under TOP whose #! runs a program in GONE, the programs the
    dropped packages shipped, unless a package in ALLOWED owns it: a forced purge must not leave a
    script the box could start and that cannot run. A bare name (from env) matches a dropped
    program of that name. Also one line per package in ALLOWED that owns no such script."""
    names = {os.path.basename(g) for g in gone}
    owner = owners(root)
    out, used = [], set()
    for d, dirs, files in os.walk(os.path.join(root, top)):
        dirs.sort()
        for n in sorted(files):
            p = os.path.join(d, n)
            mode = os.lstat(p).st_mode
            if not stat.S_ISREG(mode) or not mode & 0o111:
                continue
            with open(p, "rb") as f:
                prog = interpreter(f.readline(256))
            if not prog or not (prog in gone or ("/" not in prog and prog in names)):
                continue
            rel = os.path.relpath(p, root)
            pkg = owner.get("/" + rel)
            if pkg in allowed:
                used.add(pkg)
            else:
                out.append("%s: runs %s, which a dropped package shipped" % (rel, prog))
    out += ["%s: owns no script a dropped program runs; drop.py's PERL_TOOLS is stale" % p
            for p in sorted(set(allowed) - used)]
    return out


def remove_files(root):
    """Delete FILES from the tree, and the links under etc/systemd that enabled a unit among them;
    one line per pattern that matched nothing."""
    out, units = [], set()
    for pattern in FILES:
        hits = sorted(glob.glob(os.path.join(root, pattern)))
        if not hits:
            out.append("%s: matches nothing; drop.py's FILES is stale" % pattern)
        for h in hits:
            os.unlink(h)
            if "/systemd/system/" in h:
                units.add(os.path.basename(h))
    for d, _, files in os.walk(os.path.join(root, "etc/systemd")):
        for n in files:
            if n in units and os.path.islink(os.path.join(d, n)):
                os.unlink(os.path.join(d, n))
    return out


def main(root):
    listed = subprocess.run(["mkosi-chroot", "dpkg-query", "-L", *DROP], check=True,
                            stdout=subprocess.PIPE, text=True).stdout.splitlines()
    rest = [p for p in DROP if p not in ESSENTIAL]
    subprocess.run(["mkosi-chroot", "dpkg", "--purge", "--force-depends", *rest], check=True)
    subprocess.run(["mkosi-chroot", "dpkg", "--purge", "--force-depends", "--force-remove-essential",
                    *ESSENTIAL], check=True)
    problems = (remove_files(root) + needed_violations(root, shipped(listed))
                + interpreter_violations(root, programs(listed), PERL_TOOLS))
    for p in problems:
        print("drop.py: " + p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
