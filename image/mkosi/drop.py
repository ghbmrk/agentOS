#!/usr/bin/env python3
"""Purge packages the box does not need, then refuse a tree that links a library it lacks (#2919).

mkosi.postinst runs this with the image tree's path, before it copies dpkg's status file out for the
known-vulnerability scan (EVL-5), so the scan and the package manifest see the packages gone. Each
package below is a hard dependency of one the box keeps, so apt would remove the keeper with it;
dpkg purges it with --force-depends instead, and FILES removes what used it. The NEEDED check then
fails the build if any ELF file under usr still names a library a dropped package shipped: a forced
purge must not leave a binary that cannot load.

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
}
# Files a kept package ships that link a dropped one. Each pattern must match: a stale one fails.
FILES = (
    "usr/lib/x86_64-linux-gnu/NetworkManager/*/libnm-device-plugin-bluetooth.so",
    "usr/lib/x86_64-linux-gnu/NetworkManager/*/libnm-device-plugin-wwan.so",
    "usr/lib/x86_64-linux-gnu/NetworkManager/*/libnm-wwan.so",
    "usr/bin/nmtui*",
)
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


def remove_files(root):
    """Delete FILES from the tree; one line per pattern that matched nothing."""
    out = []
    for pattern in FILES:
        hits = sorted(glob.glob(os.path.join(root, pattern)))
        if not hits:
            out.append("%s: matches nothing; drop.py's FILES is stale" % pattern)
        for h in hits:
            os.unlink(h)
    return out


def main(root):
    listed = subprocess.run(["mkosi-chroot", "dpkg-query", "-L", *DROP], check=True,
                            stdout=subprocess.PIPE, text=True).stdout.splitlines()
    subprocess.run(["mkosi-chroot", "dpkg", "--purge", "--force-depends", *DROP], check=True)
    problems = remove_files(root) + needed_violations(root, shipped(listed))
    for p in problems:
        print("drop.py: " + p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
