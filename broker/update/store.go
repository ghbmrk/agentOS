package update

import (
	"crypto/ed25519"
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
	"strconv"
	"strings"
	"syscall"
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
	// ErrDriveTooOld: offline, the drive's root expired more than
	// MaxOfflineRootAge ago; the owner sees DriveTooOldNotice.
	ErrDriveTooOld = errors.New("drive's update is too old to trust offline")
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

// DriveTooOldNotice is what the owner sees when a drive's update is refused
// for age (Mark, 2026-10-05). The same text accompanies the tier-4 override.
const DriveTooOldNotice = "This drive's update is too old to trust offline. Use a newer drive, or connect once."

// MaxOfflineRootAge: an offline install is refused when the drive's newest
// root expired longer ago than this, unless the owner overrides.
const MaxOfflineRootAge = 180 * 24 * time.Hour

// NotConfirmedNotice is what the owner sees when an online check finds the
// release installed from a drive missing from the fresh metadata.
const NotConfirmedNotice = "The update installed from a drive is not in the latest signed release list. It may have been withdrawn; the box will offer the current release."

// Options for one check.
type Options struct {
	// Offline: reading a drive with no network. Signatures, thresholds and
	// versions are checked as online; expiry is not (UPD-8).
	Offline bool
	// Channel is ChannelStable (default) or ChannelFast. Fast also takes
	// stable releases.
	Channel string
	// MinThreshold is the fewest keys the root and targets roles may
	// require, so one stolen key cannot sign a release. Values below 2
	// count as 2; it can only be raised.
	MinThreshold int
	// Attestors is the box's attestor allow-list: the keys pinned in its
	// image plus those the owner added (D6, arbitrator's correction). Only
	// these count as independent; empty means none do yet, and a security
	// fix takes the owner's CH-3 install path. While every listed key is
	// maintainer-operated (the project's test box, Mark 2026-10-05), those
	// keys count as the interim check; once any outside key is listed,
	// maintainer-operated keys stop counting.
	Attestors []ed25519.PublicKey
	// AllowOldDrive: the owner approved, with a tier-4 code, an offline
	// install from a drive whose root expired over MaxOfflineRootAge ago.
	AllowOldDrive bool
	// Now is the clock for expiry and drive age; nil means time.Now.
	Now func() time.Time
}

// Store is a box's update state: the trusted root, the newest timestamp
// and snapshot it has accepted, every key any accepted root has listed,
// and the installed release.
//
//	root.json, timestamp.json, snapshot.json, seen_keys.json, installed.json
type Store struct {
	Dir string
}

// Installed is the box's current release.
type Installed struct {
	Version int64 `json:"version"`
	// UnconfirmedFreshness: installed offline; an online check clears it
	// only if the fresh targets list this exact manifest (UPD-8).
	UnconfirmedFreshness bool `json:"unconfirmed_freshness,omitempty"`
	// ManifestPath and ManifestSHA256 name the installed release's
	// manifest bytes, recorded at Commit.
	ManifestPath   string `json:"manifest_path,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
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

// Verified is a release whose metadata passed every check. Only Check
// makes one, so code that must act only on a verified release (A/B
// activation, UPD-1; signing a PCR policy for the new boot path, HW-5a)
// takes a *Verified. A Verified built anywhere else (a zero value) is
// refused by every method: only load sets sealed.
type Verified struct {
	sealed      bool
	release     Manifest
	manifest    File
	files       map[string]File
	fresh       bool
	maintainers map[string]bool // keys any accepted root listed (no attestor)
	allowed     map[string]bool // Options.Attestors
	// interim: every allow-listed key is maintainer-operated, so the
	// project's test box counts until an outside attestor is listed
	// (Mark, 2026-10-05).
	interim  bool
	operated map[string]bool // maintainer-operated attestor keys
	security bool            // set only by WithAttestations
}

// ErrNotChecked: a Verified that Store.Check did not make.
var ErrNotChecked = errors.New("update: release was not made by Store.Check")

func (v *Verified) ok() bool { return v != nil && v.sealed }

// Manifest is the verified manifest.
func (v *Verified) Manifest() (Manifest, error) {
	if !v.ok() {
		return Manifest{}, ErrNotChecked
	}
	r := v.release
	r.Files = append([]string(nil), r.Files...)
	return r, nil
}

// OK reports whether v was made by Store.Check (a zero value or nil was not).
func (v *Verified) OK() bool { return v.ok() }

// Version is the release version as the change pipeline names it.
func (v *Verified) Version() string {
	if !v.ok() {
		return ""
	}
	return strconv.FormatInt(v.release.Version, 10)
}

// Images maps each release file (under host-image/ or guest-image/) to
// its signed SHA-256, the form the change pipeline evaluates (CHG-3).
func (v *Verified) Images() map[string]string {
	if !v.ok() {
		return nil
	}
	out := make(map[string]string, len(v.files))
	for p, f := range v.files {
		out[p] = f.SHA256
	}
	return out
}

// Security is true only for a security fix whose independent attestation
// WithAttestations has checked (UPD-8, D6). It is never the manifest flag
// alone.
func (v *Verified) Security() bool { return v.ok() && v.security }

// WithAttestations returns a copy whose Security reflects
// SecurityAutoStage(atts, own). An unsealed v gives nil.
func (v *Verified) WithAttestations(atts [][]byte, own ed25519.PublicKey) *Verified {
	if !v.ok() {
		return nil
	}
	c := *v
	c.security = v.SecurityAutoStage(atts, own) == nil
	return &c
}

// Fresh is false when the check ran offline (UPD-8), or v is not sealed.
func (v *Verified) Fresh() bool { return v.ok() && v.fresh }

// ManifestFile is the release manifest target itself.
func (v *Verified) ManifestFile() (File, error) {
	if !v.ok() {
		return File{}, ErrNotChecked
	}
	return v.manifest, nil
}

// Files lists the release's files with their signed lengths and hashes.
func (v *Verified) Files() ([]File, error) {
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
func (v *Verified) Fetch(src Source, targetPath, dst string) error {
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
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != f.Length || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("%w: %s does not match its signed hash", ErrBadRepository, targetPath)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dst))
}

// Result of a check.
type Result struct {
	// Release is the newest verified release above the installed one on
	// the box's channel, or nil if there is none.
	Release *Verified
	// FreshnessConfirmed: an online check found the release installed
	// from a drive in the fresh targets and cleared its pending check.
	FreshnessConfirmed bool
	// FreshnessFailed: an online check found the release installed from a
	// drive missing from the fresh targets (or changed); the check stays
	// pending and the owner sees NotConfirmedNotice.
	FreshnessFailed bool
	// RootRotatedTo is the new root version when this check accepted a
	// key rotation, else 0; the digest reports it (Security R3).
	RootRotatedTo int64
	// SecurityFix is the highest release above the installed one, on the
	// box's channel, whose manifest marks it a security fix, else 0. A
	// newer ordinary release does not hide it: the updater treats the
	// newest as carrying the fix (maintain M5, security lens C2).
	SecurityFix int64
}

// lock serializes checks and commits across processes sharing Dir, so two
// writers cannot interleave saved metadata and lower the rollback floor.
func (s *Store) lock() (func(), error) {
	f, err := os.OpenFile(s.p(".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
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

// readMeta reads a metadata file: capped, and refused if it holds a null.
func readMeta(src Source, name string) ([]byte, error) {
	b, err := readAll(src, name, maxMetadata)
	if err != nil {
		return nil, err
	}
	if err := noNull(b); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadRepository, name, err)
	}
	return b, nil
}

// Check reads the repository at src and returns the newest release this
// box may install (UPD-2, UPD-8). Root rotations are followed and saved;
// the timestamp and snapshot it accepts are saved for rollback checks.
func (s *Store) Check(src Source, o Options) (res Result, err error) {
	// What src serves is untrusted, and a parser panic reachable with only
	// the online keys (as go-tuf's null targets entry was) must fail closed,
	// not crash the process.
	defer func() {
		if r := recover(); r != nil {
			res, err = Result{}, fmt.Errorf("%w: %v", ErrBadRepository, r)
		}
	}()
	return s.check(src, o)
}

func (s *Store) check(src Source, o Options) (Result, error) {
	unlock, err := s.lock()
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if o.Channel == "" {
		o.Channel = ChannelStable
	}
	if o.Channel != ChannelStable && o.Channel != ChannelFast {
		return Result{}, fmt.Errorf("channel %q has no automatic updates", o.Channel)
	}
	if o.MinThreshold < 2 {
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
	seen, err := s.seenKeys()
	if err != nil {
		return Result{}, err
	}
	addKeys(seen, tm.Root)
	// Root rotations, each signed by the previous root and itself.
	rotated := false
	for i := 0; i < MaxRootRotations; i++ {
		name := fmt.Sprintf("metadata/%d.root.json", tm.Root.Signed.Version+1)
		b, err := readMeta(src, name)
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
		addKeys(seen, tm.Root)
		rootBytes, rotated = b, true
	}
	// A drive's root may be expired (UPD-8), but not by more than
	// MaxOfflineRootAge without the owner's override: such a drive cannot
	// carry a revocation newer than half a year past its root's life.
	if o.Offline && !o.AllowOldDrive {
		now := time.Now()
		if o.Now != nil {
			now = o.Now()
		}
		if exp := tm.Root.Signed.Expires; now.Sub(exp) > MaxOfflineRootAge {
			return Result{}, fmt.Errorf("%w: root v%d expired %s", ErrDriveTooOld, tm.Root.Signed.Version, exp.UTC().Format(time.DateOnly))
		}
	}
	var res Result
	if rotated {
		if err := s.writeSeenKeys(seen); err != nil {
			return Result{}, err
		}
		if err := writeAtomic(s.p("root.json"), rootBytes, 0o600); err != nil {
			return Result{}, err
		}
		res.RootRotatedTo = tm.Root.Signed.Version
	}

	// Timestamp: the saved one first, for rollback protection. If a root
	// rotation changed the timestamp key it no longer verifies and is
	// dropped (TUF 5.3.11).
	if b, err := os.ReadFile(s.p("timestamp.json")); err == nil {
		tm.UpdateTimestamp(b)
	}
	tsBytes, err := readMeta(src, "metadata/timestamp.json")
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
	snapBytes, err := readMeta(src, fmt.Sprintf("metadata/%d.snapshot.json", sm.Version))
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
	tb, err := readMeta(src, fmt.Sprintf("metadata/%d.targets.json", tmeta.Version))
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

	attestors, err := s.operatedAttestors(src, targets)
	if err != nil {
		return Result{}, err
	}

	allowed := map[string]bool{}
	for _, k := range o.Attestors {
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return Result{}, fmt.Errorf("attestor allow-list holds a key that is not Ed25519")
		}
		allowed[fingerprint(der)] = true
	}

	var versions []int64
	for p := range targets.Signed.Targets {
		if n, ok := releaseVersion(p); ok && n > installed.Version {
			versions = append(versions, n)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] > versions[j] })
	for _, n := range versions {
		v, err := s.load(src, seen, attestors, allowed, targets, n)
		if err != nil {
			return Result{}, err
		}
		if v.release.Channel != ChannelStable && o.Channel != ChannelFast {
			continue
		}
		if res.Release == nil {
			v.fresh = !o.Offline
			res.Release = v
		}
		if v.release.Security && res.SecurityFix == 0 {
			res.SecurityFix = n
		}
		if res.SecurityFix != 0 {
			break
		}
	}

	// The whole check passed: only now settle an offline install's
	// freshness, and only against the exact manifest it installed.
	if !o.Offline && installed.UnconfirmedFreshness {
		f, err := fileOf(installed.ManifestPath, targets.Signed.Targets[installed.ManifestPath])
		if err == nil && f.SHA256 == installed.ManifestSHA256 {
			installed.UnconfirmedFreshness = false
			if err := s.writeInstalled(installed); err != nil {
				return Result{}, err
			}
			res.FreshnessConfirmed = true
		} else {
			res.FreshnessFailed = true
		}
	}
	return res, nil
}

func addKeys(seen map[string]bool, root *metadata.Metadata[metadata.RootType]) {
	for _, k := range root.Signed.Keys {
		pub, err := k.ToPublicKey()
		if err != nil {
			continue
		}
		if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
			seen[fingerprint(der)] = true
		}
	}
}

func (s *Store) seenKeys() (map[string]bool, error) {
	seen := map[string]bool{}
	b, err := os.ReadFile(s.p("seen_keys.json"))
	if errors.Is(err, os.ErrNotExist) {
		return seen, nil
	}
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	for _, k := range list {
		seen[k] = true
	}
	return seen, nil
}

func (s *Store) writeSeenKeys(seen map[string]bool) error {
	list := make([]string, 0, len(seen))
	for k := range seen {
		list = append(list, k)
	}
	sort.Strings(list)
	b, _ := json.Marshal(list)
	return writeAtomic(s.p("seen_keys.json"), b, 0o600)
}

// operatedAttestors reads the signed list of maintainer-operated attestor
// keys (attestors/maintainer.json), if the repository has one.
func (s *Store) operatedAttestors(src Source, targets *metadata.Metadata[metadata.TargetsType]) (map[string]bool, error) {
	out := map[string]bool{}
	tf := targets.Signed.Targets[AttestorsPath]
	if tf == nil {
		return out, nil
	}
	f, err := fileOf(AttestorsPath, tf)
	if err != nil {
		return nil, err
	}
	b, err := readAll(src, targetFile(f.Path, f.SHA256), maxManifest)
	if err != nil {
		return nil, err
	}
	if err := tf.VerifyLengthHashes(b); err != nil {
		return nil, classify(err)
	}
	var list attestorList
	if err := decodeStrict(b, &list, attestorListFields); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadRepository, AttestorsPath, err)
	}
	for _, k := range list.Keys {
		fp, err := attestorFingerprint(k)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrBadRepository, AttestorsPath, err)
		}
		out[fp] = true
	}
	return out, nil
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
	if tf == nil {
		return File{}, fmt.Errorf("%w: no target %s", ErrBadRepository, p)
	}
	sum, ok := tf.Hashes["sha256"]
	if !ok || len(sum) != sha256.Size || tf.Length < 0 {
		return File{}, fmt.Errorf("%w: target %s has no SHA-256", ErrBadRepository, p)
	}
	return File{Path: p, Length: tf.Length, SHA256: hex.EncodeToString(sum)}, nil
}

func (s *Store) load(src Source, seen, attestors, allowed map[string]bool, targets *metadata.Metadata[metadata.TargetsType], n int64) (*Verified, error) {
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
	interim := len(allowed) > 0
	for fp := range allowed {
		if !attestors[fp] {
			interim = false
		}
	}
	v := &Verified{sealed: true, release: rel, manifest: man, files: map[string]File{}, maintainers: seen, operated: attestors, allowed: allowed, interim: interim}
	for _, f := range rel.Files {
		tf, ok := targets.Signed.Targets[f]
		if !ok {
			return nil, fmt.Errorf("%w: release %d names %s, which is not signed", ErrBadRepository, n, f)
		}
		if v.files[f], err = fileOf(f, tf); err != nil {
			return nil, err
		}
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
func (s *Store) Commit(v *Verified) error {
	if !v.ok() {
		return ErrNotChecked
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	in, err := s.Installed()
	if err != nil {
		return err
	}
	if v.release.Version <= in.Version {
		return fmt.Errorf("%w: release %d is not newer than installed %d", ErrRollback, v.release.Version, in.Version)
	}
	return s.writeInstalled(Installed{Version: v.release.Version, UnconfirmedFreshness: !v.fresh,
		ManifestPath: v.manifest.Path, ManifestSHA256: v.manifest.SHA256})
}
