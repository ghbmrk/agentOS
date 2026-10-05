package update

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// Source is where a box reads a repository: a mirror, or a drive (DEP-4).
// Everything it returns is untrusted until checked.
type Source interface {
	Open(name string) (io.ReadCloser, error)
}

// DirSource reads a repository laid out in a directory, such as a drive.
type DirSource string

// Open opens a repository-relative path.
func (d DirSource) Open(name string) (io.ReadCloser, error) {
	if !validTargetPath(name) {
		return nil, fmt.Errorf("bad repository path %q", name)
	}
	return os.Open(filepath.Join(string(d), filepath.FromSlash(name)))
}

// Size limits for what a box reads before checking it.
const (
	maxMetadata = 4 << 20
	maxManifest = 64 << 10
	// MaxRootRotations bounds the root versions walked in one check.
	MaxRootRotations = 64
)

// Errors a check can return. Each wraps go-tuf's own error.
var (
	// ErrSignatures: metadata lacks its role's threshold of valid signatures.
	ErrSignatures = errors.New("update metadata is not signed by enough keys")
	// ErrExpired: metadata has expired, so the mirror may be frozen (online only).
	ErrExpired = errors.New("update metadata has expired")
	// ErrRollback: metadata older than what the box already trusts.
	ErrRollback = errors.New("update metadata is older than what this box trusts")
	// ErrWeakThreshold: the root or targets role needs fewer keys than the box's floor.
	ErrWeakThreshold = errors.New("update metadata threshold is below this box's floor")
	// ErrBadRepository: anything else wrong with what the source served.
	ErrBadRepository = errors.New("update repository is malformed")
)

func classify(err error) error {
	if err == nil {
		return nil
	}
	var (
		unsigned *metadata.ErrUnsignedMetadata
		expired  *metadata.ErrExpiredMetadata
		badVer   *metadata.ErrBadVersionNumber
		value    *metadata.ErrValue
	)
	switch {
	case errors.As(err, &unsigned), errors.As(err, &value) && strings.Contains(err.Error(), "threshold"):
		return fmt.Errorf("%w: %v", ErrSignatures, err)
	case errors.As(err, &expired):
		return fmt.Errorf("%w: %v", ErrExpired, err)
	case errors.As(err, &badVer):
		return fmt.Errorf("%w: %v", ErrRollback, err)
	}
	return fmt.Errorf("%w: %v", ErrBadRepository, err)
}

// OfflineNotice is what the box tells the owner after installing from a
// drive (UPD-8). P2-2 and the owner channel show it.
const OfflineNotice = "Update installed from a drive without a freshness check. The box will check it the next time it is online."

// Options for one check.
type Options struct {
	// Offline: reading a drive with no network. Signatures, thresholds and
	// versions are checked as online; expiry is not (UPD-8).
	Offline bool
	// Channel is ChannelStable (default) or ChannelFast. Fast also takes
	// stable releases.
	Channel string
	// MinThreshold is the fewest keys the root and targets roles may
	// require (default 2), so one stolen key cannot sign a release.
	MinThreshold int
	// Now is the clock for online expiry; nil means time.Now.
	Now func() time.Time
}

// Store is a box's update state: the trusted root, the newest timestamp
// and snapshot it has accepted, and the installed release.
//
//	root.json, timestamp.json, snapshot.json, installed.json
type Store struct {
	Dir string
}

// Installed is the box's current release.
type Installed struct {
	Version int64 `json:"version"`
	// UnconfirmedFreshness: installed offline; the next online check
	// clears it (UPD-8).
	UnconfirmedFreshness bool `json:"unconfirmed_freshness,omitempty"`
}

// InitStore bootstraps a box from the root shipped in its image and the
// image's own release version.
func InitStore(dir string, root []byte, installed int64) (*Store, error) {
	m, err := metadata.Root().FromBytes(root)
	if err != nil {
		return nil, classify(err)
	}
	if err := m.VerifyDelegate(metadata.ROOT, m); err != nil {
		return nil, classify(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir}
	if _, err := os.Stat(s.p("root.json")); err == nil {
		return nil, errors.New("update store already initialised")
	}
	if err := writeAtomic(s.p("root.json"), root, 0o600); err != nil {
		return nil, err
	}
	return s, s.writeInstalled(Installed{Version: installed})
}

func (s *Store) p(n string) string { return filepath.Join(s.Dir, n) }

// Installed reads the installed release.
func (s *Store) Installed() (Installed, error) {
	var in Installed
	b, err := os.ReadFile(s.p("installed.json"))
	if err != nil {
		return in, err
	}
	return in, json.Unmarshal(b, &in)
}

func (s *Store) writeInstalled(in Installed) error {
	b, _ := json.Marshal(in)
	return writeAtomic(s.p("installed.json"), b, 0o600)
}

// File is one target file a verified release names.
type File struct {
	Path   string
	Length int64
	SHA256 string
}

// Checked is a release whose metadata passed every check. Only Check
// makes one, so code that must act only on a verified release (A/B
// activation, UPD-1; signing a PCR policy for the new boot path, HW-5a)
// takes a *Checked. A Checked built anywhere else (a zero value) is
// refused by every method: only load sets sealed.
type Checked struct {
	sealed      bool
	release     Manifest
	manifest    File
	files       map[string]File
	fresh       bool
	maintainers map[string]bool
}

// ErrNotChecked: a Checked that Store.Check did not make.
var ErrNotChecked = errors.New("update: release was not made by Store.Check")

func (v *Checked) ok() bool { return v != nil && v.sealed }

// Manifest is the verified manifest.
func (v *Checked) Manifest() (Manifest, error) {
	if !v.ok() {
		return Manifest{}, ErrNotChecked
	}
	r := v.release
	r.Files = append([]string(nil), r.Files...)
	return r, nil
}

// Fresh is false when the check ran offline (UPD-8), or v is not sealed.
func (v *Checked) Fresh() bool { return v.ok() && v.fresh }

// ManifestFile is the release manifest target itself.
func (v *Checked) ManifestFile() (File, error) {
	if !v.ok() {
		return File{}, ErrNotChecked
	}
	return v.manifest, nil
}

// Files lists the release's files with their signed lengths and hashes.
func (v *Checked) Files() ([]File, error) {
	if !v.ok() {
		return nil, ErrNotChecked
	}
	out := make([]File, 0, len(v.files))
	for _, p := range v.release.Files {
		out = append(out, v.files[p])
	}
	return out, nil
}

// Fetch copies one of the release's files from src to dst, which appears
// only if the bytes match the signed length and hash.
func (v *Checked) Fetch(src Source, targetPath, dst string) error {
	if !v.ok() {
		return ErrNotChecked
	}
	f, ok := v.files[targetPath]
	if !ok {
		return fmt.Errorf("%q is not a file of release %d", targetPath, v.release.Version)
	}
	rc, err := src.Open(targetFile(f.Path, f.SHA256))
	if err != nil {
		return err
	}
	defer rc.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".fetch-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(rc, f.Length+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != f.Length || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("%w: %s does not match its signed hash", ErrBadRepository, targetPath)
	}
	return os.Rename(tmp.Name(), dst)
}

// Result of a check.
type Result struct {
	// Release is the newest verified release above the installed one on
	// the box's channel, or nil if there is none.
	Release *Checked
	// FreshnessConfirmed: an online check cleared an offline install's
	// pending freshness check.
	FreshnessConfirmed bool
}

func readAll(src Source, name string, max int64) ([]byte, error) {
	rc, err := src.Open(name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrBadRepository, name, max)
	}
	return b, nil
}

// Check reads the repository at src and returns the newest release this
// box may install (UPD-2, UPD-8). Root rotations are followed and saved;
// the timestamp and snapshot it accepts are saved for rollback checks.
func (s *Store) Check(src Source, o Options) (Result, error) {
	if o.Channel == "" {
		o.Channel = ChannelStable
	}
	if o.Channel != ChannelStable && o.Channel != ChannelFast {
		return Result{}, fmt.Errorf("channel %q has no automatic updates", o.Channel)
	}
	if o.MinThreshold == 0 {
		o.MinThreshold = 2
	}
	installed, err := s.Installed()
	if err != nil {
		return Result{}, err
	}
	rootBytes, err := os.ReadFile(s.p("root.json"))
	if err != nil {
		return Result{}, err
	}
	tm, err := trustedmetadata.New(rootBytes)
	if err != nil {
		return Result{}, classify(err)
	}
	switch {
	case o.Offline:
		// Nothing counts as expired; every other check stands.
		tm.RefTime = time.Unix(0, 0).UTC()
	case o.Now != nil:
		tm.RefTime = o.Now().UTC()
	}

	// Every root in the chain meets the floor, not only the last: a weak
	// intermediate root could otherwise vouch for the next with one key.
	if err := floor(tm.Root, o.MinThreshold); err != nil {
		return Result{}, err
	}
	// Root rotations, each signed by the previous root and itself.
	rotated := false
	for i := 0; i < MaxRootRotations; i++ {
		name := fmt.Sprintf("metadata/%d.root.json", tm.Root.Signed.Version+1)
		b, err := readAll(src, name, maxMetadata)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return Result{}, err
		}
		if _, err := tm.UpdateRoot(b); err != nil {
			return Result{}, classify(err)
		}
		if err := floor(tm.Root, o.MinThreshold); err != nil {
			return Result{}, err
		}
		rootBytes, rotated = b, true
	}
	if rotated {
		if err := writeAtomic(s.p("root.json"), rootBytes, 0o600); err != nil {
			return Result{}, err
		}
	}

	// Timestamp: the saved one first, for rollback protection. If a root
	// rotation changed the timestamp key it no longer verifies and is
	// dropped (TUF 5.3.11).
	if b, err := os.ReadFile(s.p("timestamp.json")); err == nil {
		tm.UpdateTimestamp(b)
	}
	tsBytes, err := readAll(src, "metadata/timestamp.json", maxMetadata)
	if err != nil {
		return Result{}, err
	}
	if _, err := tm.UpdateTimestamp(tsBytes); err != nil {
		var eq *metadata.ErrEqualVersionNumber
		if !errors.As(err, &eq) {
			return Result{}, classify(err)
		}
		tsBytes = nil // keep the saved copy
	}
	if tm.Timestamp == nil {
		return Result{}, fmt.Errorf("%w: no timestamp", ErrBadRepository)
	}

	if b, err := os.ReadFile(s.p("snapshot.json")); err == nil {
		tm.UpdateSnapshot(b, true)
	}
	sm := tm.Timestamp.Signed.Meta["snapshot.json"]
	if sm == nil {
		return Result{}, fmt.Errorf("%w: timestamp names no snapshot", ErrBadRepository)
	}
	snapBytes, err := readAll(src, fmt.Sprintf("metadata/%d.snapshot.json", sm.Version), maxMetadata)
	if err != nil {
		return Result{}, err
	}
	if _, err := tm.UpdateSnapshot(snapBytes, false); err != nil {
		return Result{}, classify(err)
	}

	tmeta := tm.Snapshot.Signed.Meta["targets.json"]
	if tmeta == nil {
		return Result{}, fmt.Errorf("%w: snapshot names no targets", ErrBadRepository)
	}
	tb, err := readAll(src, fmt.Sprintf("metadata/%d.targets.json", tmeta.Version), maxMetadata)
	if err != nil {
		return Result{}, err
	}
	targets, err := tm.UpdateTargets(tb)
	if err != nil {
		return Result{}, classify(err)
	}

	// All metadata checked: save what the next check must not go below.
	if tsBytes != nil {
		if err := writeAtomic(s.p("timestamp.json"), tsBytes, 0o600); err != nil {
			return Result{}, err
		}
	}
	if err := writeAtomic(s.p("snapshot.json"), snapBytes, 0o600); err != nil {
		return Result{}, err
	}

	var res Result
	if !o.Offline && installed.UnconfirmedFreshness {
		installed.UnconfirmedFreshness = false
		if err := s.writeInstalled(installed); err != nil {
			return Result{}, err
		}
		res.FreshnessConfirmed = true
	}

	var versions []int64
	for p := range targets.Signed.Targets {
		if n, ok := releaseVersion(p); ok && n > installed.Version {
			versions = append(versions, n)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] > versions[j] })
	for _, n := range versions {
		v, err := s.load(src, tm.Root, targets, n)
		if err != nil {
			return res, err
		}
		if v.release.Channel == ChannelStable || o.Channel == ChannelFast {
			v.fresh = !o.Offline
			res.Release = v
			return res, nil
		}
	}
	return res, nil
}

func floor(root *metadata.Metadata[metadata.RootType], min int) error {
	for _, r := range []string{metadata.ROOT, metadata.TARGETS} {
		role := root.Signed.Roles[r]
		if role == nil || role.Threshold < min {
			t := 0
			if role != nil {
				t = role.Threshold
			}
			return fmt.Errorf("%w: root v%d %s needs %d, floor is %d", ErrWeakThreshold, root.Signed.Version, r, t, min)
		}
	}
	return nil
}

func fileOf(p string, tf *metadata.TargetFiles) (File, error) {
	sum, ok := tf.Hashes["sha256"]
	if !ok || len(sum) != sha256.Size || tf.Length < 0 {
		return File{}, fmt.Errorf("%w: target %s has no SHA-256", ErrBadRepository, p)
	}
	return File{Path: p, Length: tf.Length, SHA256: hex.EncodeToString(sum)}, nil
}

func (s *Store) load(src Source, root *metadata.Metadata[metadata.RootType], targets *metadata.Metadata[metadata.TargetsType], n int64) (*Checked, error) {
	p := ReleasePath(n)
	man, err := fileOf(p, targets.Signed.Targets[p])
	if err != nil {
		return nil, err
	}
	if man.Length > maxManifest {
		return nil, fmt.Errorf("%w: manifest %s too large", ErrBadRepository, p)
	}
	b, err := readAll(src, targetFile(p, man.SHA256), maxManifest)
	if err != nil {
		return nil, err
	}
	if err := targets.Signed.Targets[p].VerifyLengthHashes(b); err != nil {
		return nil, classify(err)
	}
	rel, err := parseManifest(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRepository, err)
	}
	if rel.Version != n {
		return nil, fmt.Errorf("%w: %s holds version %d", ErrBadRepository, p, rel.Version)
	}
	v := &Checked{sealed: true, release: rel, manifest: man, files: map[string]File{}, maintainers: map[string]bool{}}
	for _, f := range rel.Files {
		tf, ok := targets.Signed.Targets[f]
		if !ok {
			return nil, fmt.Errorf("%w: release %d names %s, which is not signed", ErrBadRepository, n, f)
		}
		if v.files[f], err = fileOf(f, tf); err != nil {
			return nil, err
		}
	}
	for _, k := range root.Signed.Keys {
		pub, err := k.ToPublicKey()
		if err != nil {
			continue
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			continue
		}
		v.maintainers[fingerprint(der)] = true
	}
	return v, nil
}

func fingerprint(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// Commit records a release as installed once A/B activation passed its
// health check (UPD-1). An offline release leaves the freshness check
// pending, and the owner sees OfflineNotice.
func (s *Store) Commit(v *Checked) error {
	if !v.ok() {
		return ErrNotChecked
	}
	in, err := s.Installed()
	if err != nil {
		return err
	}
	if v.release.Version <= in.Version {
		return fmt.Errorf("%w: release %d is not newer than installed %d", ErrRollback, v.release.Version, in.Version)
	}
	return s.writeInstalled(Installed{Version: v.release.Version, UnconfirmedFreshness: !v.fresh})
}
