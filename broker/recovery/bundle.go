package recovery

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

const bundleMagic = "agentos-backup"
const bundleVersion = 2

// chunkSize is the plaintext size of each sealed chunk of a backup.
const chunkSize = 64 << 10

// opaqueXattr is overlayfs's opaque-directory marker, the only xattr kept
// (as in vm/overlay, V17).
const opaqueXattr = "trusted.overlay.opaque"

// prefix is a backup's plaintext preamble: an ephemeral X25519 public key
// and the chunk nonce prefix. Nothing in it relates to the vault's slots,
// so only the recovery key opens a backup (REC-1): not the card's
// passphrase, and not a TPM.
type prefix struct {
	Magic       string    `json:"magic"`
	Version     int       `json:"version"`
	Created     time.Time `json:"created"`
	Ephemeral   []byte    `json:"ephemeral"`
	NoncePrefix []byte    `json:"nonce_prefix"`
}

// Root is one directory a backup carries, by name: the vault process's
// directory (vault and key slots) and the broker's state directory
// (journal, owner state, machine layers).
type Root struct {
	Name, Path string
}

// Layout says where things sit in a restored tree, relative to the
// restore target ("<root name>/<path>").
type Layout struct {
	// Vault and Keys are the sealed vault and its key-slot file. Both sit
	// in one root, the vault process's, which is restored with every file
	// 0600 and every directory 0700, owned by VaultUID and VaultGID when
	// owners are kept.
	Vault, Keys        string
	VaultUID, VaultGID int
	// Owner is the owner channel's state file, whose session unlock the
	// restore ends. Empty when the backup carries none.
	Owner string
	// Layers are the machine-layer directories (overlay uppers, V17).
	// Only beneath them are file owners, setuid and setgid bits, absolute
	// symlinks, and whiteouts restored; elsewhere a symlink must stay
	// inside its own root.
	Layers []string
}

func (l Layout) vaultRoot() (string, error) {
	vr, _, _ := strings.Cut(l.Vault, "/")
	kr, _, _ := strings.Cut(l.Keys, "/")
	if vr == "" || vr != kr || vr == l.Vault || kr == l.Keys {
		return "", errors.New("recovery: the vault and its key slots must sit in one root")
	}
	return vr, nil
}

// inLayer reports whether clean is a machine layer or beneath one.
func (l Layout) inLayer(clean string) bool {
	for _, d := range l.Layers {
		d = path.Clean(d)
		if d != "." && d != "" && (clean == d || strings.HasPrefix(clean, d+"/")) {
			return true
		}
	}
	return false
}

// backupPrivate is the X25519 key backups are sealed to, derived from the
// recovery key; the box stores only its public half (BackupKeyName), so it
// can seal backups it cannot open.
func backupPrivate(rk RecoveryKey) (*ecdh.PrivateKey, error) {
	if !rk.Valid() {
		return nil, errors.New("recovery: no recovery key")
	}
	k := hkdf(rk.b[:], nil, "agentos-backup-x25519-v1", 32)
	defer wipe(k)
	return ecdh.X25519().NewPrivateKey(k)
}

func backupPublic(rk RecoveryKey) ([]byte, error) {
	p, err := backupPrivate(rk)
	if err != nil {
		return nil, err
	}
	return p.PublicKey().Bytes(), nil
}

// Backup writes the roots (everything the broker and the vault process
// keep) to w as one sealed stream that only the recovery key opens. The
// box needs neither the recovery key nor the data key for it: the stream
// is sealed to the backup public key in the vault. The caller pauses
// writers first (STOP, machines paused), as for a snapshot.
//
// Contents are sealed in 64 KiB chunks (AES-256-GCM, each chunk numbered
// and the last one marked), so a reordered, truncated, or modified backup
// fails to restore.
//
// The archive ends with a MAC over every entry, keyed by a vault entry
// (MACKeyName), so a restore accepts only contents this box wrote: the
// backup public key alone, which anyone holding it can seal to, does not
// make a backup restorable.
func Backup(b *Box, roots []Root, w io.Writer, now time.Time) error {
	if _, unfinished := RotationUnfinished(b); unfinished {
		return ErrRotationUnfinished
	}
	pub, err := backupKey(b)
	if err != nil {
		return err
	}
	mk, err := macKey(b.V)
	if err != nil {
		return err
	}
	defer wipe(mk)
	return backupTo(pub, mk, roots, w, now)
}

// macEntry is the archive's last entry: the MAC. Root names cannot start
// with a dot, so it cannot collide with one.
const macEntry = ".agentos-backup-mac"

func backupTo(pub, mk []byte, roots []Root, w io.Writer, now time.Time) error {
	return sealTo(pub, w, now, func(raw *tar.Writer) error {
		tw := &digestTar{tw: raw, h: sha256.New()}
		names := map[string]bool{}
		for _, r := range roots {
			if r.Name == "" || strings.ContainsAny(r.Name, "/.") || names[r.Name] {
				return fmt.Errorf("recovery: bad root name %q", r.Name)
			}
			names[r.Name] = true
			if err := tw.WriteHeader(&tar.Header{Name: r.Name + "/", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: now, Format: tar.FormatPAX}); err != nil {
				return err
			}
			if err := writeTree(tw, r.Path, r.Name+"/"); err != nil {
				return err
			}
		}
		if mk == nil {
			return nil
		}
		sum := backupMAC(mk, tw.h.Sum(nil))
		if err := raw.WriteHeader(&tar.Header{Name: macEntry, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(sum)), ModTime: now, Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := raw.Write(sum)
		return err
	})
}

func backupMAC(mk, digest []byte) []byte {
	m := hmac.New(sha256.New, mk)
	m.Write([]byte("agentos-backup-mac-v1"))
	m.Write(digest)
	return m.Sum(nil)
}

// tarWriter is what writeTree writes to.
type tarWriter interface {
	WriteHeader(*tar.Header) error
	io.Writer
}

// digestTar hashes each entry's restored fields and contents as written.
type digestTar struct {
	tw *tar.Writer
	h  hash.Hash
}

func (d *digestTar) WriteHeader(hd *tar.Header) error {
	d.h.Write(canonHeader(hd))
	return d.tw.WriteHeader(hd)
}

func (d *digestTar) Write(p []byte) (int, error) {
	d.h.Write(p)
	return d.tw.Write(p)
}

// canonHeader is every header field a restore acts on, length-prefixed.
func canonHeader(hd *tar.Header) []byte {
	var b bytes.Buffer
	field := func(v string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		b.Write(n[:])
		b.WriteString(v)
	}
	field("entry")
	field(hd.Name)
	field(string([]byte{hd.Typeflag}))
	field(strconv.FormatInt(hd.Mode, 8))
	field(strconv.Itoa(hd.Uid))
	field(strconv.Itoa(hd.Gid))
	field(hd.Linkname)
	field(strconv.FormatInt(hd.Size, 10))
	opq, has := hd.PAXRecords["SCHILY.xattr."+opaqueXattr]
	field(strconv.FormatBool(has))
	field(opq)
	field(strconv.FormatInt(hd.Devmajor, 10) + ":" + strconv.FormatInt(hd.Devminor, 10))
	return b.Bytes()
}

// sealTo writes the preamble and the archive body writes, sealed to pub.
func sealTo(pub []byte, w io.Writer, now time.Time, body func(*tar.Writer) error) error {
	peer, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		return err
	}
	defer wipe(shared)
	np, err := random(nil, 7)
	if err != nil {
		return err
	}
	pre, err := json.Marshal(prefix{Magic: bundleMagic, Version: bundleVersion, Created: now.UTC(),
		Ephemeral: eph.PublicKey().Bytes(), NoncePrefix: np})
	if err != nil {
		return err
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(pre)))
	if _, err := w.Write(append(n[:], pre...)); err != nil {
		return err
	}
	sw, err := newSealWriter(w, contentKey(shared, eph.PublicKey().Bytes(), pub), np, pre)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(sw)
	if err := body(tw); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return sw.Close()
}

func contentKey(shared, eph, pub []byte) []byte {
	return hkdf(shared, append(append([]byte(nil), eph...), pub...), "agentos-backup-content-v1", 32)
}

// Report says what a restore did.
type Report struct {
	Files int
	Bytes int64
	// DroppedHostSlots counts the TPM slots removed: new hardware is
	// never trusted until the owner adds it (CRED-9).
	DroppedHostSlots int
	// Created is when the backup was made (for the owner's notice).
	Created time.Time
	// Source is "backup" or "drive".
	Source string
}

// Options tune a restore.
type Options struct {
	// KeepOwners restores file owners beneath the machine layers (the
	// broker runs as root on the box; layers need guest owners, V17) and
	// gives the vault root to the vault's user. Off, files belong to the
	// restoring user and no setuid or setgid bit is restored.
	KeepOwners bool
}

// Restore reads a backup with the recovery key into dst, a path that must
// not exist yet (REC-1). The recovery key must also open the restored
// vault, and the archive's MAC must verify under the restored vault's MAC
// key. The restored box loses every TPM slot, its owner session ends, and
// it is restricted until the owner re-confirms its standing grants
// (REC-2). A restore that fails part way leaves nothing at dst.
func Restore(r io.Reader, rk RecoveryKey, dst string, lay Layout, opt Options, now time.Time) (Report, error) {
	return restore(r, rk, dst, lay, opt, now, false)
}

func restore(r io.Reader, rk RecoveryKey, dst string, lay Layout, opt Options, now time.Time, drive bool) (Report, error) {
	rep := Report{Source: "backup"}
	if drive {
		rep.Source = "drive"
	}
	vroot, err := lay.vaultRoot()
	if err != nil {
		return rep, err
	}
	if _, err := os.Lstat(dst); err == nil {
		return rep, errors.New("recovery: restore target already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return rep, err
	}
	priv, err := backupPrivate(rk)
	if err != nil {
		return rep, err
	}
	br := bufio.NewReader(r)
	var n [4]byte
	if _, err := io.ReadFull(br, n[:]); err != nil {
		return rep, errors.New("recovery: not a backup")
	}
	ln := binary.BigEndian.Uint32(n[:])
	if ln > 1<<12 {
		return rep, errors.New("recovery: not a backup")
	}
	pre := make([]byte, ln)
	if _, err := io.ReadFull(br, pre); err != nil {
		return rep, errors.New("recovery: not a backup")
	}
	var p prefix
	d := json.NewDecoder(bytes.NewReader(pre))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil || p.Magic != bundleMagic || p.Version != bundleVersion || len(p.NoncePrefix) != 7 {
		return rep, errors.New("recovery: not a backup this version can read")
	}
	rep.Created = p.Created
	eph, err := ecdh.X25519().NewPublicKey(p.Ephemeral)
	if err != nil {
		return rep, errors.New("recovery: not a backup this version can read")
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return rep, errDamaged
	}
	defer wipe(shared)
	sr, err := newSealReader(br, contentKey(shared, p.Ephemeral, priv.PublicKey().Bytes()), p.NoncePrefix, pre)
	if err != nil {
		return rep, err
	}
	tmp := dst + ".restoring"
	if err := os.RemoveAll(tmp); err != nil {
		return rep, err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	x := &extractor{dst: tmp, opt: opt, lay: lay, vroot: vroot, rep: &rep, h: sha256.New()}
	if err := x.run(tar.NewReader(sr)); err != nil {
		return rep, err
	}
	if err := sr.end(); err != nil {
		return rep, err
	}
	b := &Box{VaultPath: filepath.Join(tmp, filepath.FromSlash(lay.Vault)), KeysPath: filepath.Join(tmp, filepath.FromSlash(lay.Keys))}
	for _, f := range []string{b.VaultPath, b.KeysPath} {
		if fi, err := os.Lstat(f); err != nil || !fi.Mode().IsRegular() {
			return rep, fmt.Errorf("recovery: the backup holds no regular file at %s", strings.TrimPrefix(f, tmp+string(filepath.Separator)))
		}
	}
	raw, err := os.ReadFile(b.KeysPath)
	if err != nil {
		return rep, err
	}
	if err := CheckKeys(raw); err != nil {
		return rep, err
	}
	if b.V, err = vault.OpenSealed(b.VaultPath, b.KeysPath, Factor(rk)); err != nil {
		return rep, fmt.Errorf("recovery: the restored vault does not open with this recovery key: %w", err)
	}
	// A backup is a deliberate rollback: Rebase gives the vault a new
	// rollback identity and drops every TPM slot with it, so new hardware
	// is trusted only when the owner adds it (CRED-9, V6).
	rep.DroppedHostSlots, err = b.V.Rebase(Factor(rk))
	if err == nil {
		err = x.verify(b.V, drive)
	}
	if err == nil {
		// Declines are for good, across restores too.
		prev := LoadState(b.V)
		err = saveState(b.V, State{Restricted: true, RestoredAt: now.UTC(), Source: rep.Source, Unverified: drive, Declined: prev.Declined})
	}
	b.V.Close()
	if err != nil {
		return rep, err
	}
	if lay.Owner != "" {
		if err := endRestoredSession(filepath.Join(tmp, filepath.FromSlash(lay.Owner))); err != nil {
			return rep, err
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		return rep, err
	}
	ok = true
	return rep, syncDir(filepath.Dir(dst))
}

// RestoreDrive restores from the old drive itself (REC-1: "or the drive
// itself") onto dst with the recovery key. It is a backup piped into a
// restore, so both paths share one format and one set of checks. The old
// drive is only read.
//
// Nothing authenticates the old drive's plaintext broker state, so the
// restore is marked unverified (State.Unverified): its owner number and
// grants are the owner's only once re-confirmed.
func RestoreDrive(roots []Root, rk RecoveryKey, dst string, lay Layout, opt Options, now time.Time) (Report, error) {
	pub, err := backupPublic(rk)
	if err != nil {
		return Report{}, err
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(backupTo(pub, nil, roots, pw, now)) }()
	rep, err := restore(pr, rk, dst, lay, opt, now, true)
	pr.CloseWithError(errors.New("restore ended"))
	return rep, err
}

func writeAtomic(path string, raw []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".recovery-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	serr := d.Sync()
	if err := d.Close(); serr == nil {
		serr = err
	}
	return serr
}

// writeTree archives root without following symlinks. It keeps regular
// files, directories, symlinks, and overlayfs whiteouts (0/0 character
// devices) with their modes and owners, and the opaque marker on
// directories; anything else fails with its path named (as vm/overlay V17).
func writeTree(tw tarWriter, root, under string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return err
		}
		rel = under + filepath.ToSlash(rel)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, _ := fi.Sys().(*syscall.Stat_t)
		hd := &tar.Header{Name: rel, Mode: int64(fi.Mode().Perm()) | modeBits(fi.Mode()), ModTime: fi.ModTime(), Format: tar.FormatPAX}
		if st != nil {
			hd.Uid, hd.Gid = int(st.Uid), int(st.Gid)
		}
		m := fi.Mode()
		switch {
		case m.IsRegular():
			hd.Typeflag, hd.Size = tar.TypeReg, fi.Size()
		case m.IsDir():
			hd.Typeflag, hd.Name = tar.TypeDir, rel+"/"
			if v, ok := opaque(p); ok {
				hd.PAXRecords = map[string]string{"SCHILY.xattr." + opaqueXattr: v}
			}
		case m&fs.ModeSymlink != 0:
			hd.Typeflag = tar.TypeSymlink
			if hd.Linkname, err = os.Readlink(p); err != nil {
				return err
			}
		case m&fs.ModeCharDevice != 0 && st != nil && st.Rdev == 0:
			hd.Typeflag = tar.TypeChar
		default:
			return fmt.Errorf("recovery: %s is not a file, directory, symlink, or whiteout", rel)
		}
		if err := tw.WriteHeader(hd); err != nil {
			return err
		}
		if hd.Typeflag != tar.TypeReg {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.CopyN(tw, f, hd.Size); err != nil {
			return fmt.Errorf("recovery: %s changed during backup: %v", rel, err)
		}
		return nil
	})
}

func modeBits(m fs.FileMode) int64 {
	var b int64
	if m&fs.ModeSetuid != 0 {
		b |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		b |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		b |= 0o1000
	}
	return b
}

func opaque(p string) (string, bool) {
	var buf [8]byte
	n, err := syscall.Getxattr(p, opaqueXattr, buf[:])
	if err != nil || n != 1 || buf[0] != 'y' {
		return "", false
	}
	return "y", true
}

// extractor writes a backup's entries under dst. Every entry's parent must
// be a directory this restore created, and files are created exclusively
// without following links, so no entry (a symlink first, a path beneath
// it next) can write outside dst. Outside the machine layers no owner,
// setuid or setgid bit, whiteout, or symlink leaving its root is restored;
// the vault root is forced to the vault's user, 0600 files and 0700
// directories; top-level directories are 0700. It digests what it
// restores for the MAC check.
type extractor struct {
	dst   string
	opt   Options
	lay   Layout
	vroot string
	rep   *Report
	h     hash.Hash
	mac   []byte
}

func (x *extractor) run(tr *tar.Reader) error {
	if err := os.Mkdir(x.dst, 0o700); err != nil {
		return err
	}
	dirs := map[string]bool{".": true}
	type dirMode struct {
		p    string
		mode os.FileMode
	}
	var later []dirMode
	for {
		hd, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("recovery: backup is damaged: %v", err)
		}
		if x.mac != nil {
			return errors.New("recovery: entries after the backup's MAC")
		}
		if hd.Name == macEntry {
			if hd.Typeflag != tar.TypeReg || hd.Size != sha256.Size {
				return errors.New("recovery: malformed backup MAC")
			}
			x.mac = make([]byte, sha256.Size)
			if _, err := io.ReadFull(tr, x.mac); err != nil {
				return errDamaged
			}
			continue
		}
		x.h.Write(canonHeader(hd))
		name := strings.TrimSuffix(hd.Name, "/")
		clean := path.Clean(name)
		if name == "" || clean != name || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || clean == "." {
			return fmt.Errorf("recovery: unsafe path in backup: %q", hd.Name)
		}
		if !dirs[path.Dir(clean)] {
			return fmt.Errorf("recovery: %q is not under a restored directory", clean)
		}
		top, _, _ := strings.Cut(clean, "/")
		layer := x.lay.inLayer(clean)
		inVault := top == x.vroot
		p := filepath.Join(x.dst, filepath.FromSlash(clean))
		mode := os.FileMode(hd.Mode & 0o777)
		var special os.FileMode
		if layer && x.opt.KeepOwners {
			special = fileModeBits(hd.Mode)
			// Never a setuid file of root's, or setgid to root's group.
			if hd.Uid == 0 {
				special &^= os.ModeSetuid
			}
			if hd.Gid == 0 {
				special &^= os.ModeSetgid
			}
		}
		switch hd.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(p, 0o700); err != nil {
				return err
			}
			dirs[clean] = true
			if v, ok := hd.PAXRecords["SCHILY.xattr."+opaqueXattr]; ok {
				if !layer {
					return fmt.Errorf("recovery: opaque marker outside a machine layer: %q", clean)
				}
				if err := syscall.Setxattr(p, opaqueXattr, []byte(v), 0); err != nil {
					return fmt.Errorf("recovery: %s: opaque marker: %v", clean, err)
				}
			}
			if inVault || !strings.Contains(clean, "/") {
				mode, special = 0o700, 0
			}
			later = append(later, dirMode{p, mode | special})
		case tar.TypeReg:
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
			if err != nil {
				return err
			}
			n, err := io.Copy(f, io.TeeReader(tr, x.h))
			if err == nil {
				err = f.Sync()
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			x.rep.Files++
			x.rep.Bytes += n
			if inVault {
				mode, special = 0o600, 0
			}
			if err := os.Chmod(p, mode|special); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if !layer && !staysIn(top, clean, hd.Linkname) {
				return fmt.Errorf("recovery: symlink %q leaves its root", clean)
			}
			if err := os.Symlink(hd.Linkname, p); err != nil {
				return err
			}
		case tar.TypeChar:
			if !layer {
				return fmt.Errorf("recovery: whiteout outside a machine layer: %q", clean)
			}
			if hd.Devmajor != 0 || hd.Devminor != 0 {
				return fmt.Errorf("recovery: device node %q in backup", clean)
			}
			if err := syscall.Mknod(p, syscall.S_IFCHR, 0); err != nil {
				return fmt.Errorf("recovery: whiteout %s: %v", clean, err)
			}
		default:
			return fmt.Errorf("recovery: entry type %q not allowed: %q", hd.Typeflag, clean)
		}
		if x.opt.KeepOwners {
			uid, gid := -1, -1
			switch {
			case layer:
				uid, gid = hd.Uid, hd.Gid
			case inVault:
				uid, gid = x.lay.VaultUID, x.lay.VaultGID
			}
			if uid >= 0 {
				if err := os.Lchown(p, uid, gid); err != nil {
					return err
				}
				if hd.Typeflag == tar.TypeReg && special != 0 {
					// chown clears setuid and setgid; put them back.
					if err := os.Chmod(p, mode|special); err != nil {
						return err
					}
				}
			}
		}
	}
	sort.Slice(later, func(i, j int) bool { return len(later[i].p) > len(later[j].p) })
	for _, d := range later {
		if err := os.Chmod(d.p, d.mode); err != nil {
			return err
		}
	}
	return syncDir(x.dst)
}

// staysIn reports whether a symlink at clean pointing to link resolves,
// lexically, inside the root top.
func staysIn(top, clean, link string) bool {
	if link == "" || path.IsAbs(link) {
		return false
	}
	t := path.Join(path.Dir(clean), link)
	return t == top || strings.HasPrefix(t, top+"/")
}

// verify checks the archive's MAC under the restored vault's MAC key. A
// drive restore carries none: nothing on the old drive authenticates it.
func (x *extractor) verify(v *vault.Vault, drive bool) error {
	if drive {
		if x.mac != nil {
			return errors.New("recovery: unexpected MAC in a drive restore")
		}
		return nil
	}
	if x.mac == nil {
		return errors.New("recovery: the backup is not authenticated (no MAC)")
	}
	mk, err := macKey(v)
	if err != nil {
		return err
	}
	defer wipe(mk)
	if !hmac.Equal(x.mac, backupMAC(mk, x.h.Sum(nil))) {
		return errors.New("recovery: the backup's contents were not written by this box")
	}
	return nil
}

// endRestoredSession ends the restored owner session (UnlockedUntil), so
// chat waits for a fresh code on the new hardware.
func endRestoredSession(p string) error {
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("recovery: the owner state is not a regular file")
	}
	return EndSession(owner.FileStore{Path: p}, false)
}

func fileModeBits(m int64) os.FileMode {
	var b os.FileMode
	if m&0o4000 != 0 {
		b |= os.ModeSetuid
	}
	if m&0o2000 != 0 {
		b |= os.ModeSetgid
	}
	if m&0o1000 != 0 {
		b |= os.ModeSticky
	}
	return b
}

// sealWriter seals a stream in numbered chunks; the last chunk is marked
// final, so truncation at a chunk boundary is detected.
type sealWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	np    []byte
	aad   []byte
	buf   []byte
	count uint32
}

func newSealWriter(w io.Writer, key, np, pre []byte) (*sealWriter, error) {
	defer wipe(key)
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pre)
	return &sealWriter{w: w, aead: aead, np: np, aad: sum[:]}, nil
}

func chunkNonce(np []byte, n uint32, final bool) []byte {
	nonce := make([]byte, 12)
	copy(nonce, np)
	binary.BigEndian.PutUint32(nonce[7:11], n)
	if final {
		nonce[11] = 1
	}
	return nonce
}

func (s *sealWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		k := chunkSize - len(s.buf)
		if k > len(p) {
			k = len(p)
		}
		s.buf = append(s.buf, p[:k]...)
		p = p[k:]
		// A full chunk is flushed only when more data follows, so that the
		// last chunk, full or not, is the one sealed as final by Close.
		if len(s.buf) == chunkSize && len(p) > 0 {
			if err := s.flush(false); err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func (s *sealWriter) flush(final bool) error {
	if s.count == ^uint32(0) {
		return errors.New("recovery: backup too large")
	}
	ct := s.aead.Seal(nil, chunkNonce(s.np, s.count, final), s.buf, s.aad)
	s.count++
	s.buf = s.buf[:0]
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(ct)))
	if _, err := s.w.Write(n[:]); err != nil {
		return err
	}
	_, err := s.w.Write(ct)
	return err
}

func (s *sealWriter) Close() error {
	return s.flush(true)
}

// sealReader opens a sealWriter stream.
type sealReader struct {
	r     io.Reader
	aead  cipher.AEAD
	np    []byte
	aad   []byte
	buf   []byte
	count uint32
	final bool
}

func newSealReader(r io.Reader, key, np, pre []byte) (*sealReader, error) {
	defer wipe(key)
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pre)
	return &sealReader{r: r, aead: aead, np: np, aad: sum[:]}, nil
}

var errDamaged = errors.New("recovery: backup is damaged, truncated, or not for this key")

func (s *sealReader) Read(p []byte) (int, error) {
	for len(s.buf) == 0 {
		if s.final {
			return 0, io.EOF
		}
		var n [4]byte
		if _, err := io.ReadFull(s.r, n[:]); err != nil {
			return 0, errDamaged
		}
		ln := binary.BigEndian.Uint32(n[:])
		if ln < 16 || ln > chunkSize+16 {
			return 0, errDamaged
		}
		ct := make([]byte, ln)
		if _, err := io.ReadFull(s.r, ct); err != nil {
			return 0, errDamaged
		}
		var err error
		s.buf, err = s.aead.Open(nil, chunkNonce(s.np, s.count, false), ct, s.aad)
		if err != nil {
			s.buf, err = s.aead.Open(nil, chunkNonce(s.np, s.count, true), ct, s.aad)
			if err != nil {
				return 0, errDamaged
			}
			s.final = true
		}
		s.count++
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// end confirms the stream reached its final chunk and nothing follows.
func (s *sealReader) end() error {
	if _, err := io.Copy(io.Discard, s); err != nil {
		return err
	}
	if !s.final {
		return errDamaged
	}
	var one [1]byte
	if n, _ := s.r.Read(one[:]); n != 0 {
		return errDamaged
	}
	return nil
}
