package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Repository layout, the same on a maintainer's disk, a mirror, and a drive:
//
//	metadata/N.root.json      every root version, so a box can walk rotations
//	metadata/N.targets.json   signed by a threshold of maintainer keys
//	metadata/N.snapshot.json  online role
//	metadata/timestamp.json   online role, short expiry
//	targets/<dir>/<sha256>.<name>  content-addressed target files
//	staged/root.json, staged/targets.json  unpublished, collecting signatures
//
// Root and targets keys stay offline. Each holder signs the staged file on
// their own machine, and Publish refuses anything under the role's
// threshold. Snapshot and timestamp keys are online keys a scheduled job
// uses to keep metadata fresh; they cannot add or change a release.

// Default expiries. Refresh re-signs snapshot and timestamp, so a daily job
// keeps a live repository fresh; a frozen mirror goes stale within a day.
const (
	RootExpiry      = 365 * 24 * time.Hour
	TargetsExpiry   = 365 * 24 * time.Hour
	SnapshotExpiry  = 7 * 24 * time.Hour
	TimestampExpiry = 24 * time.Hour
)

// Repo is a release repository directory.
type Repo struct {
	Dir string
	// Now is the clock for expiries; nil means time.Now.
	Now func() time.Time
}

func (r Repo) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// RootConfig is the initial key set. Thresholds default to 1 only if
// left zero; the box refuses a root or targets threshold below its floor
// (Options.MinThreshold, default 2).
type RootConfig struct {
	Root, Targets, Snapshot, Timestamp []ed25519.PublicKey
	RootThreshold, TargetsThreshold    int
}

func (r Repo) p(parts ...string) string {
	return filepath.Join(append([]string{r.Dir}, parts...)...)
}

// Init stages version 1 of root and an empty targets role. Nothing is
// published until the staged files carry their thresholds.
func Init(dir string, cfg RootConfig) (Repo, error) {
	r := Repo{Dir: dir}
	if _, err := os.Stat(r.p("metadata")); err == nil {
		return r, errors.New("repository already initialised")
	}
	root := metadata.Root(r.now().Add(RootExpiry))
	root.Signed.ConsistentSnapshot = true
	for role, keys := range map[string][]ed25519.PublicKey{
		metadata.ROOT: cfg.Root, metadata.TARGETS: cfg.Targets,
		metadata.SNAPSHOT: cfg.Snapshot, metadata.TIMESTAMP: cfg.Timestamp,
	} {
		if len(keys) == 0 {
			return r, fmt.Errorf("no %s keys", role)
		}
		for _, k := range keys {
			tk, err := metadata.KeyFromPublicKey(k)
			if err != nil {
				return r, err
			}
			if err := root.Signed.AddKey(tk, role); err != nil {
				return r, err
			}
		}
	}
	for role, t := range map[string]int{metadata.ROOT: cfg.RootThreshold, metadata.TARGETS: cfg.TargetsThreshold} {
		if t == 0 {
			t = 1
		}
		if t < 1 || t > len(root.Signed.Roles[role].KeyIDs) {
			return r, fmt.Errorf("%s threshold %d does not fit %d keys", role, t, len(root.Signed.Roles[role].KeyIDs))
		}
		root.Signed.Roles[role].Threshold = t
	}
	targets := metadata.Targets(r.now().Add(TargetsExpiry))
	for _, d := range []string{"metadata", "targets", "staged"} {
		if err := os.MkdirAll(r.p(d), 0o755); err != nil {
			return r, err
		}
	}
	if err := writeMeta(r.p("staged", "root.json"), root); err != nil {
		return r, err
	}
	return r, writeMeta(r.p("staged", "targets.json"), targets)
}

type role interface {
	metadata.RootType | metadata.TargetsType | metadata.SnapshotType | metadata.TimestampType
}

func writeMeta[T role](name string, m *metadata.Metadata[T]) error {
	b, err := m.ToBytes(true)
	if err != nil {
		return err
	}
	return writeAtomic(name, b, 0o644)
}

func writeAtomic(name string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}

// latest returns the highest published version of a versioned role, or 0.
func (r Repo) latest(roleName string) (int64, error) {
	ents, err := os.ReadDir(r.p("metadata"))
	if err != nil {
		return 0, err
	}
	var best int64
	for _, e := range ents {
		n, ok := strings.CutSuffix(e.Name(), "."+roleName+".json")
		if !ok {
			continue
		}
		v, err := strconv.ParseInt(n, 10, 64)
		if err == nil && v > best {
			best = v
		}
	}
	return best, nil
}

func (r Repo) published(roleName string) (int64, []byte, error) {
	v, err := r.latest(roleName)
	if err != nil || v == 0 {
		return 0, nil, err
	}
	b, err := os.ReadFile(r.p("metadata", fmt.Sprintf("%d.%s.json", v, roleName)))
	return v, b, err
}

func (r Repo) root() (*metadata.Metadata[metadata.RootType], error) {
	_, b, err := r.published(metadata.ROOT)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errors.New("no published root")
	}
	return metadata.Root().FromBytes(b)
}

func keyIDOf(priv ed25519.PrivateKey) (string, error) {
	return KeyID(priv.Public())
}

func hasSig(sigs []metadata.Signature, id string) bool {
	for _, s := range sigs {
		if s.KeyID == id {
			return true
		}
	}
	return false
}

// Sign adds one key holder's signature to the staged root or targets
// file. The key must belong to that role: for root, in the staged root or
// the published one it replaces (a rotation needs both thresholds).
func (r Repo) Sign(roleName string, priv ed25519.PrivateKey) error {
	signer, err := Signer(priv)
	if err != nil {
		return err
	}
	id, err := keyIDOf(priv)
	if err != nil {
		return err
	}
	name := r.p("staged", roleName+".json")
	switch roleName {
	case metadata.ROOT:
		m, err := metadata.Root().FromFile(name)
		if err != nil {
			return fmt.Errorf("nothing staged for root: %w", err)
		}
		ok := contains(m.Signed.Roles[metadata.ROOT].KeyIDs, id)
		if prev, err := r.root(); err == nil {
			ok = ok || contains(prev.Signed.Roles[metadata.ROOT].KeyIDs, id)
		}
		if !ok {
			return errors.New("key is not a root key")
		}
		if hasSig(m.Signatures, id) {
			return errors.New("already signed with this key")
		}
		if _, err := m.Sign(signer); err != nil {
			return err
		}
		return writeMeta(name, m)
	case metadata.TARGETS:
		m, err := metadata.Targets().FromFile(name)
		if err != nil {
			return fmt.Errorf("nothing staged for targets: %w", err)
		}
		// Publish puts a staged root in force before it checks targets.
		root, err := metadata.Root().FromFile(r.p("staged", "root.json"))
		if err != nil {
			if root, err = r.root(); err != nil {
				return errors.New("no root to check the targets key against")
			}
		}
		if !contains(root.Signed.Roles[metadata.TARGETS].KeyIDs, id) {
			return errors.New("key is not a targets key")
		}
		if hasSig(m.Signatures, id) {
			return errors.New("already signed with this key")
		}
		if _, err := m.Sign(signer); err != nil {
			return err
		}
		return writeMeta(name, m)
	}
	return fmt.Errorf("only root and targets are signed offline, not %q", roleName)
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// stagedTargets returns the staged targets, starting a new version from
// the published one if none is staged. Any change clears its signatures.
func (r Repo) stagedTargets() (*metadata.Metadata[metadata.TargetsType], error) {
	name := r.p("staged", "targets.json")
	if m, err := metadata.Targets().FromFile(name); err == nil {
		return m, nil
	}
	v, b, err := r.published(metadata.TARGETS)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errors.New("no published targets")
	}
	m, err := metadata.Targets().FromBytes(b)
	if err != nil {
		return nil, err
	}
	m.Signed.Version = v + 1
	return m, nil
}

// targetFile is where a target's bytes live: content-addressed by SHA-256.
func targetFile(targetPath string, sha string) string {
	dir, base := path.Split(targetPath)
	return path.Join("targets", dir, sha+"."+base)
}

// AddRelease stages a release: each file in files (target path to local
// file) is copied in content-addressed, and the manifest becomes
// releases/<version>.json. A file already a target may be named in
// rel.Files without being in files. Versions only go up.
func (r Repo) AddRelease(rel Manifest, files map[string]string) error {
	if err := rel.Check(); err != nil {
		return err
	}
	m, err := r.stagedTargets()
	if err != nil {
		return err
	}
	for p := range m.Signed.Targets {
		if n, ok := releaseVersion(p); ok && n >= rel.Version {
			return fmt.Errorf("release %d is not newer than release %d", rel.Version, n)
		}
	}
	for p := range files {
		if !contains(rel.Files, p) {
			return fmt.Errorf("file %q is not one of the release's files", p)
		}
	}
	for _, p := range rel.Files {
		local, ok := files[p]
		if !ok {
			if _, ok := m.Signed.Targets[p]; !ok {
				return fmt.Errorf("release file %q is neither given nor already a target", p)
			}
			continue
		}
		tf, err := r.storeTarget(p, local)
		if err != nil {
			return err
		}
		m.Signed.Targets[p] = tf
	}
	man, err := json.MarshalIndent(rel, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(r.Dir, ".manifest-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	tmp.Write(man)
	tmp.Close()
	tf, err := r.storeTarget(ReleasePath(rel.Version), tmp.Name())
	if err != nil {
		return err
	}
	m.Signed.Targets[ReleasePath(rel.Version)] = tf
	m.Signed.Expires = r.now().Add(TargetsExpiry)
	m.ClearSignatures()
	return writeMeta(r.p("staged", "targets.json"), m)
}

func (r Repo) storeTarget(targetPath, local string) (*metadata.TargetFiles, error) {
	if !validTargetPath(targetPath) {
		return nil, fmt.Errorf("target path %q is not plain", targetPath)
	}
	f, err := os.Open(local)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	dst := r.p(filepath.FromSlash(targetFile(targetPath, sum)))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	out, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(out.Name())
	if _, err := io.Copy(out, f); err != nil {
		out.Close()
		return nil, err
	}
	if err := out.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(out.Name(), 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(out.Name(), dst); err != nil {
		return nil, err
	}
	raw, _ := hex.DecodeString(sum)
	return &metadata.TargetFiles{Length: n, Hashes: metadata.Hashes{"sha256": raw}, Path: targetPath}, nil
}

func releaseVersion(targetPath string) (int64, bool) {
	s, ok := strings.CutPrefix(targetPath, "releases/")
	if !ok {
		return 0, false
	}
	s, ok = strings.CutSuffix(s, ".json")
	if !ok || s == "" || s[0] == '0' || strings.TrimLeft(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n > 0
}

// Rotate stages the next root with keys added to and removed from a role
// and, if threshold > 0, a new threshold (UPD-8: rotate and revoke without
// reinstalling). It needs a threshold of the old root keys and of the new
// ones before Publish accepts it.
func (r Repo) Rotate(roleName string, add, remove []ed25519.PublicKey, threshold int) error {
	name := r.p("staged", "root.json")
	m, err := metadata.Root().FromFile(name)
	if err != nil {
		if m, err = r.root(); err != nil {
			return err
		}
		m.Signed.Version++
	}
	if m.Signed.Roles[roleName] == nil {
		return fmt.Errorf("no role %q", roleName)
	}
	for _, k := range add {
		tk, err := metadata.KeyFromPublicKey(k)
		if err != nil {
			return err
		}
		if err := m.Signed.AddKey(tk, roleName); err != nil {
			return err
		}
	}
	for _, k := range remove {
		id, err := KeyID(k)
		if err != nil {
			return err
		}
		if err := m.Signed.RevokeKey(id, roleName); err != nil {
			return err
		}
	}
	if threshold > 0 {
		m.Signed.Roles[roleName].Threshold = threshold
	}
	if t := m.Signed.Roles[roleName].Threshold; t > len(m.Signed.Roles[roleName].KeyIDs) {
		return fmt.Errorf("%s threshold %d is more than its %d keys", roleName, t, len(m.Signed.Roles[roleName].KeyIDs))
	}
	m.Signed.Expires = r.now().Add(RootExpiry)
	m.ClearSignatures()
	return writeMeta(name, m)
}

// Publish moves staged root and targets into metadata once each carries
// its thresholds, then signs a new snapshot and timestamp.
func (r Repo) Publish(snapshot, timestamp ed25519.PrivateKey) error {
	if err := r.publishRoot(); err != nil {
		return err
	}
	if err := r.publishTargets(); err != nil {
		return err
	}
	return r.Refresh(snapshot, timestamp)
}

func (r Repo) publishRoot() error {
	name := r.p("staged", "root.json")
	m, err := metadata.Root().FromFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	prev, err := r.root()
	switch {
	case err == nil:
		if m.Signed.Version != prev.Signed.Version+1 {
			return fmt.Errorf("staged root is version %d, want %d", m.Signed.Version, prev.Signed.Version+1)
		}
		if err := prev.VerifyDelegate(metadata.ROOT, m); err != nil {
			return fmt.Errorf("staged root lacks the old root threshold: %w", err)
		}
	case m.Signed.Version != 1:
		return fmt.Errorf("first root must be version 1, not %d", m.Signed.Version)
	}
	if err := m.VerifyDelegate(metadata.ROOT, m); err != nil {
		return fmt.Errorf("staged root lacks its own threshold: %w", err)
	}
	if err := writeMeta(r.p("metadata", fmt.Sprintf("%d.root.json", m.Signed.Version)), m); err != nil {
		return err
	}
	return os.Remove(name)
}

func (r Repo) publishTargets() error {
	name := r.p("staged", "targets.json")
	m, err := metadata.Targets().FromFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	root, err := r.root()
	if err != nil {
		return err
	}
	v, err := r.latest(metadata.TARGETS)
	if err != nil {
		return err
	}
	if m.Signed.Version != v+1 {
		return fmt.Errorf("staged targets is version %d, want %d", m.Signed.Version, v+1)
	}
	if err := root.VerifyDelegate(metadata.TARGETS, m); err != nil {
		return fmt.Errorf("staged targets lacks its threshold: %w", err)
	}
	if err := writeMeta(r.p("metadata", fmt.Sprintf("%d.targets.json", m.Signed.Version)), m); err != nil {
		return err
	}
	return os.Remove(name)
}

// Refresh signs a new snapshot and timestamp over the published targets.
// A scheduled job runs it with the online keys; it changes no release.
func (r Repo) Refresh(snapshot, timestamp ed25519.PrivateKey) error {
	root, err := r.root()
	if err != nil {
		return err
	}
	tv, tb, err := r.published(metadata.TARGETS)
	if err != nil {
		return err
	}
	if tb == nil {
		return errors.New("no published targets")
	}
	sv, err := r.latest(metadata.SNAPSHOT)
	if err != nil {
		return err
	}
	snap := metadata.Snapshot(r.now().Add(SnapshotExpiry))
	snap.Signed.Version = sv + 1
	tsum := sha256.Sum256(tb)
	snap.Signed.Meta["targets.json"] = &metadata.MetaFiles{Version: tv, Length: int64(len(tb)), Hashes: metadata.Hashes{"sha256": tsum[:]}}
	if err := signAs(root, metadata.SNAPSHOT, snap, snapshot); err != nil {
		return err
	}
	sb, err := snap.ToBytes(true)
	if err != nil {
		return err
	}
	ts := metadata.Timestamp(r.now().Add(TimestampExpiry))
	if old, err := metadata.Timestamp().FromFile(r.p("metadata", "timestamp.json")); err == nil {
		ts.Signed.Version = old.Signed.Version + 1
	}
	ssum := sha256.Sum256(sb)
	ts.Signed.Meta["snapshot.json"] = &metadata.MetaFiles{Version: snap.Signed.Version, Length: int64(len(sb)), Hashes: metadata.Hashes{"sha256": ssum[:]}}
	if err := signAs(root, metadata.TIMESTAMP, ts, timestamp); err != nil {
		return err
	}
	if err := writeAtomic(r.p("metadata", fmt.Sprintf("%d.snapshot.json", snap.Signed.Version)), sb, 0o644); err != nil {
		return err
	}
	return writeMeta(r.p("metadata", "timestamp.json"), ts)
}

func signAs[T metadata.SnapshotType | metadata.TimestampType](root *metadata.Metadata[metadata.RootType], roleName string, m *metadata.Metadata[T], priv ed25519.PrivateKey) error {
	signer, err := Signer(priv)
	if err != nil {
		return err
	}
	if _, err := m.Sign(signer); err != nil {
		return err
	}
	if err := root.VerifyDelegate(roleName, m); err != nil {
		return fmt.Errorf("%s key does not meet the %s role: %w", roleName, roleName, err)
	}
	return nil
}
