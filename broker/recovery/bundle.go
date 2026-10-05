package recovery

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/vault"
)

const bundleMagic = "agentos-backup"
const bundleVersion = 1

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

// Layout says where the vault and its key slots sit in a restored tree,
// relative to the restore target: "<root name>/<file>".
type Layout struct {
	Vault, Keys string
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
func Backup(b *Box, roots []Root, w io.Writer, now time.Time) error {
	s, ok := b.V.Secret(BackupKeyName)
	if !ok {
		return errors.New("recovery: no backup key in the vault; provision the recovery slot first")
	}
	return backupTo([]byte(s.Reveal()), roots, w, now)
}

func backupTo(pub []byte, roots []Root, w io.Writer, now time.Time) error {
	return sealTo(pub, w, now, func(tw *tar.Writer) error {
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
		return nil
	})
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
}

// Options tune a restore.
type Options struct {
	// KeepOwners restores file owners (the broker runs as root on the
	// box; machine layers need guest owners, V17). Off, files belong to
	// the restoring user.
	KeepOwners bool
	// Source is recorded in the restore state: "backup" or "drive".
	Source string
}

// Restore reads a backup with the recovery key into dst, a path that must
// not exist yet (REC-1). The recovery key must also open the restored
// vault. The restored box loses every TPM slot and is restricted until the
// owner re-confirms its standing grants (REC-2). A restore that fails
// part way leaves nothing at dst.
func Restore(r io.Reader, rk RecoveryKey, dst string, lay Layout, opt Options, now time.Time) (Report, error) {
	var rep Report
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
	if err := extract(tar.NewReader(sr), tmp, opt, &rep); err != nil {
		return rep, err
	}
	if err := sr.end(); err != nil {
		return rep, err
	}
	b := &Box{VaultPath: filepath.Join(tmp, filepath.FromSlash(lay.Vault)), KeysPath: filepath.Join(tmp, filepath.FromSlash(lay.Keys))}
	raw, err := os.ReadFile(b.KeysPath)
	if err != nil {
		return rep, fmt.Errorf("recovery: the backup holds no key slots at %s", lay.Keys)
	}
	if err := CheckKeys(raw); err != nil {
		return rep, err
	}
	if rep.DroppedHostSlots, err = dropHostSlots(b.KeysPath); err != nil {
		return rep, err
	}
	if b.V, err = vault.OpenSealed(b.VaultPath, b.KeysPath, Factor(rk)); err != nil {
		return rep, fmt.Errorf("recovery: the restored vault does not open with this recovery key: %w", err)
	}
	src := opt.Source
	if src == "" {
		src = "backup"
	}
	err = saveState(b.V, State{Restricted: true, RestoredAt: now.UTC(), Source: src})
	b.V.Close()
	if err != nil {
		return rep, err
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
func RestoreDrive(roots []Root, rk RecoveryKey, dst string, lay Layout, opt Options, now time.Time) (Report, error) {
	pub, err := backupPublic(rk)
	if err != nil {
		return Report{}, err
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(backupTo(pub, roots, pw, now)) }()
	opt.Source = "drive"
	rep, err := Restore(pr, rk, dst, lay, opt, now)
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
func writeTree(tw *tar.Writer, root, under string) error {
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

// extract writes a backup's entries under dst. Every entry's parent must
// be a directory this restore created, and files are created exclusively
// without following links, so no entry (a symlink first, a path beneath
// it next) can write outside dst.
func extract(tr *tar.Reader, dst string, opt Options, rep *Report) error {
	if err := os.Mkdir(dst, 0o700); err != nil {
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
		name := strings.TrimSuffix(hd.Name, "/")
		clean := path.Clean(name)
		if name == "" || clean != name || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || clean == "." {
			return fmt.Errorf("recovery: unsafe path in backup: %q", hd.Name)
		}
		if !dirs[path.Dir(clean)] {
			return fmt.Errorf("recovery: %q is not under a restored directory", clean)
		}
		p := filepath.Join(dst, filepath.FromSlash(clean))
		mode := os.FileMode(hd.Mode & 0o777)
		special := fileModeBits(hd.Mode)
		switch hd.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(p, 0o700); err != nil {
				return err
			}
			dirs[clean] = true
			if v, ok := hd.PAXRecords["SCHILY.xattr."+opaqueXattr]; ok {
				if err := syscall.Setxattr(p, opaqueXattr, []byte(v), 0); err != nil {
					return fmt.Errorf("recovery: %s: opaque marker: %v", clean, err)
				}
			}
			later = append(later, dirMode{p, mode | special})
		case tar.TypeReg:
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
			if err != nil {
				return err
			}
			n, err := io.Copy(f, tr)
			if err == nil {
				err = f.Sync()
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			rep.Files++
			rep.Bytes += n
			if err := os.Chmod(p, mode|special); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.Symlink(hd.Linkname, p); err != nil {
				return err
			}
		case tar.TypeChar:
			if hd.Devmajor != 0 || hd.Devminor != 0 {
				return fmt.Errorf("recovery: device node %q in backup", clean)
			}
			if err := syscall.Mknod(p, syscall.S_IFCHR, 0); err != nil {
				return fmt.Errorf("recovery: whiteout %s: %v", clean, err)
			}
		default:
			return fmt.Errorf("recovery: entry type %q not allowed: %q", hd.Typeflag, clean)
		}
		if opt.KeepOwners {
			if err := os.Lchown(p, hd.Uid, hd.Gid); err != nil {
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
	sort.Slice(later, func(i, j int) bool { return len(later[i].p) > len(later[j].p) })
	for _, d := range later {
		if err := os.Chmod(d.p, d.mode); err != nil {
			return err
		}
	}
	return syncDir(dst)
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
