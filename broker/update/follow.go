package update

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// Following a fork (OSS-10, OSS-9): the box trusts whichever root of trust
// the owner chose, and only FollowRoot changes it. Check never does: a root
// that does not chain from the trusted one is refused (B4). The tier-4 page
// shows DescribeRoot's summary, and the owner's code binds to its Digest
// (Security C6), so the switch follows exactly the root the owner saw.

// RootSummary is what the owner is shown before following a root.
type RootSummary struct {
	Version int64
	// Keys maps each role to its keys' fingerprints (SHA-256 of the PKIX
	// public key, hex), sorted.
	Keys       map[string][]string
	Thresholds map[string]int
	Expires    time.Time
	// RootSHA256 is the digest of the root's bytes.
	RootSHA256 string
	// Digest binds the root's bytes and every shown field; the owner's
	// tier-4 code approves this value and nothing else.
	Digest string
}

func (r RootSummary) digest() string {
	b, _ := json.Marshal(struct {
		Root       string              `json:"root_sha256"`
		Version    int64               `json:"version"`
		Keys       map[string][]string `json:"keys"`
		Thresholds map[string]int      `json:"thresholds"`
		Expires    string              `json:"expires"`
	}{r.RootSHA256, r.Version, r.Keys, r.Thresholds, r.Expires.UTC().Format(time.RFC3339Nano)})
	return Digest(b)
}

// ErrFollowNotApproved: the root is not the one whose summary the owner
// approved.
var ErrFollowNotApproved = errors.New("update: this root is not the one the owner approved")

var roles = []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP}

// verifyRoot checks a root to follow (Security C3): its own root-role
// threshold, the box's floor (the same floor as Check, never below 2), a
// nonzero threshold for every role, and unexpired by o.Now.
func verifyRoot(b []byte, o Options) (*metadata.Metadata[metadata.RootType], error) {
	if len(b) > maxMetadata {
		return nil, fmt.Errorf("%w: root is larger than %d bytes", ErrBadRepository, maxMetadata)
	}
	if err := noNull(b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRepository, err)
	}
	m, err := metadata.Root().FromBytes(b)
	if err != nil {
		return nil, classify(err)
	}
	for _, r := range roles {
		role := m.Signed.Roles[r]
		if role == nil {
			return nil, fmt.Errorf("%w: root has no %s role", ErrBadRepository, r)
		}
		if role.Threshold < 1 || role.Threshold > len(role.KeyIDs) {
			return nil, fmt.Errorf("%w: %s threshold (%d) does not fit its %d keys", ErrSignatures, r, role.Threshold, len(role.KeyIDs))
		}
	}
	if err := m.VerifyDelegate(metadata.ROOT, m); err != nil {
		return nil, classify(err)
	}
	if o.MinThreshold < 2 {
		o.MinThreshold = 2
	}
	if err := floor(m, o.MinThreshold); err != nil {
		return nil, err
	}
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	if m.Signed.IsExpired(now) {
		return nil, fmt.Errorf("%w: root v%d expired %s", ErrExpired, m.Signed.Version, m.Signed.Expires.UTC().Format(time.DateOnly))
	}
	return m, nil
}

// rootKeysWithin reports whether every root-role key a lists is one b
// lists.
func rootKeysWithin(a, b *metadata.Metadata[metadata.RootType]) bool {
	in := map[string]bool{}
	for _, k := range b.Signed.Roles[metadata.ROOT].KeyIDs {
		in[k] = true
	}
	for _, k := range a.Signed.Roles[metadata.ROOT].KeyIDs {
		if !in[k] {
			return false
		}
	}
	return true
}

// DescribeRoot verifies a root as FollowRoot will and returns what the
// owner is shown.
func DescribeRoot(b []byte, o Options) (RootSummary, error) {
	m, err := verifyRoot(b, o)
	if err != nil {
		return RootSummary{}, err
	}
	return describe(b, m)
}

// RootDigest is the summary Digest of a root the box already trusts
// (TrustedRoot), for telling whether it is the root an owner approved. It
// verifies nothing and so decides no trust: a recovering executor compares
// it with an approval it journalled.
func RootDigest(b []byte) (string, error) {
	m, err := metadata.Root().FromBytes(b)
	if err != nil {
		return "", classify(err)
	}
	s, err := describe(b, m)
	return s.Digest, err
}

func describe(b []byte, m *metadata.Metadata[metadata.RootType]) (RootSummary, error) {
	s := RootSummary{Version: m.Signed.Version, Keys: map[string][]string{}, Thresholds: map[string]int{},
		Expires: m.Signed.Expires.UTC(), RootSHA256: Digest(b)}
	for _, r := range roles {
		role := m.Signed.Roles[r]
		s.Thresholds[r] = role.Threshold
		fps := []string{}
		for _, id := range role.KeyIDs {
			k, ok := m.Signed.Keys[id]
			if !ok {
				return RootSummary{}, fmt.Errorf("%w: %s names an unknown key", ErrBadRepository, r)
			}
			pub, err := k.ToPublicKey()
			if err != nil {
				return RootSummary{}, fmt.Errorf("%w: %v", ErrBadRepository, err)
			}
			der, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				return RootSummary{}, fmt.Errorf("%w: %v", ErrBadRepository, err)
			}
			fps = append(fps, fingerprint(der))
		}
		sort.Strings(fps)
		s.Keys[r] = fps
	}
	s.Digest = s.digest()
	return s, nil
}

// ErrNotProject: a root is not the project's own, judged from the anchor
// (ProjectRoot). It wraps the cause where there is one.
var ErrNotProject = errors.New("update: this root is not the project's own")

// projectFile is the project's root as this box last trusted it, saved
// when a follow leaves the project chain: the anchor a switch back walks
// from (OSS-10w-r).
const projectFile = "project_root.json"

// ProjectRoot reports whether target is the project's own root, judged
// from anchor, the newest project root the box trusted (Store.ProjectRoot,
// else the root the image ships). It is when target's root-role keys, by
// key material, are anchor's and it is no older; or when the owner's links
// (any order, target among them or not) carry the anchor to exactly target
// by TUF root rotation (UPD-8): each root signed by its predecessor's root
// threshold and its own, versions one apart, every root meeting the box's
// floor, as Check walks a rotation. Expiry is DescribeRoot's.
func ProjectRoot(anchor, target []byte, links [][]byte, o Options) error {
	if err := projectRoot(anchor, target, links, o); err != nil {
		return fmt.Errorf("%w: %w", ErrNotProject, err)
	}
	return nil
}

func projectRoot(anchor, target []byte, links [][]byte, o Options) error {
	if len(links) > MaxRootRotations {
		return fmt.Errorf("more than %d root files", MaxRootRotations)
	}
	if o.MinThreshold < 2 {
		o.MinThreshold = 2
	}
	tm, err := trustedmetadata.New(anchor)
	if err != nil {
		return classify(err)
	}
	if err := floor(tm.Root, o.MinThreshold); err != nil {
		return err
	}
	if bytes.Equal(anchor, target) {
		return nil
	}
	t, err := verifyRoot(target, o)
	if err != nil {
		return err
	}
	if sameRootKeys(t, tm.Root) {
		if t.Signed.Version < tm.Root.Signed.Version {
			return fmt.Errorf("%w: root v%d is older than v%d", ErrRollback, t.Signed.Version, tm.Root.Signed.Version)
		}
		return nil
	}
	if t.Signed.Version <= tm.Root.Signed.Version {
		return fmt.Errorf("%w: root v%d is not newer than v%d, whose keys differ", ErrRollback, t.Signed.Version, tm.Root.Signed.Version)
	}
	type link struct {
		b []byte
		v int64
	}
	chain := []link{}
	hasTarget := false
	for _, b := range append(links, target) {
		if bytes.Equal(b, target) {
			if hasTarget {
				continue
			}
			hasTarget = true
		}
		if len(b) > maxMetadata {
			return fmt.Errorf("%w: root is larger than %d bytes", ErrBadRepository, maxMetadata)
		}
		if err := noNull(b); err != nil {
			return fmt.Errorf("%w: %v", ErrBadRepository, err)
		}
		m, err := metadata.Root().FromBytes(b)
		if err != nil {
			return classify(err)
		}
		// Root files at or below the anchor are history the box passed:
		// skipped, so the owner may bring them all, and never walked.
		if m.Signed.Version <= tm.Root.Signed.Version {
			continue
		}
		chain = append(chain, link{b, m.Signed.Version})
	}
	sort.SliceStable(chain, func(i, j int) bool { return chain[i].v < chain[j].v })
	last := anchor
	for _, l := range chain {
		if _, err := tm.UpdateRoot(l.b); err != nil {
			return classify(err)
		}
		if err := floor(tm.Root, o.MinThreshold); err != nil {
			return err
		}
		last = l.b
	}
	if !bytes.Equal(last, target) {
		return errors.New("the root files do not end at this root")
	}
	return nil
}

// sameRootKeys reports whether a and b list the same root-role keys, by
// key material, never by the key IDs they claim.
func sameRootKeys(a, b *metadata.Metadata[metadata.RootType]) bool {
	ka, kb := rootKeyMaterial(a), rootKeyMaterial(b)
	if ka == nil || kb == nil || len(ka) != len(kb) {
		return false
	}
	for k := range ka {
		if !kb[k] {
			return false
		}
	}
	return true
}

func rootKeyMaterial(m *metadata.Metadata[metadata.RootType]) map[string]bool {
	out := map[string]bool{}
	for _, id := range m.Signed.Roles[metadata.ROOT].KeyIDs {
		k, ok := m.Signed.Keys[id]
		if !ok {
			return nil
		}
		out[k.Type+"\x00"+k.Scheme+"\x00"+k.Value.PublicKey] = true
	}
	return out
}

// ProjectRoot is the project root saved when the box last left the
// project chain, or nil if it never has.
func (s *Store) ProjectRoot() ([]byte, error) {
	b, err := os.ReadFile(s.p(projectFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// followFile marks a switch in progress: it holds the Followed being
// switched to, written before the root. The next store operation finishes
// the switch if the root was written, or forgets it if not (settle).
const followFile = "following"

// sourceFile records the fork the box follows; absent on the project's
// own chain.
const sourceFile = "source.json"

// followSteps are the switch's writes, in order, under the store lock.
var followSteps = []string{"seen_keys", "interim_flag", "project_root", "marker", "root", "timestamp", "snapshot", "staged", "source", "done"}

// Followed is the fork the box takes updates from, for STATUS, the digest
// and the audit (Security C7). The zero Followed is the project's own chain.
type Followed struct {
	// Name is the owner's own name for the fork, as typed on the page.
	Name string `json:"name"`
	// Since is when the owner switched.
	Since time.Time `json:"since"`
	// RootSHA256 is the digest of the root the owner chose.
	RootSHA256 string `json:"root_sha256"`
	// Fingerprint is the first of that root's root-role key fingerprints
	// (sorted), as the page showed it.
	Fingerprint string `json:"fingerprint"`
}

// Following reads the fork the box follows; the zero Followed when it
// follows the project.
func (s *Store) Following() (Followed, error) {
	var src Followed
	b, err := os.ReadFile(s.p(sourceFile))
	if errors.Is(err, os.ErrNotExist) {
		return src, nil
	}
	if err != nil {
		return src, err
	}
	return src, json.Unmarshal(b, &src)
}

// TrustedRoot returns the root the box trusts now, after completing or
// forgetting any switch a crash interrupted, so a caller can tell whether
// a switch took effect.
func (s *Store) TrustedRoot() ([]byte, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.settle(); err != nil {
		return nil, err
	}
	return os.ReadFile(s.p("root.json"))
}

// followFault, set only by tests, fails the switch before a step, as a
// crash there would.
var followFault func(step string) error

func step(name string) error {
	if followFault != nil {
		return followFault(name)
	}
	return nil
}

// FollowRoot makes root the box's trusted root, replacing whatever chain it
// followed (OSS-10). Only the owner's tier-4 intent calls it, with the
// Digest of the summary the owner approved and the owner's name for the
// fork; an empty name means the root is the project's own (switching
// back), which the caller knows from the root its image ships. The root must pass verifyRoot.
// The installed version is kept, so a fork must release above it (UPD-8,
// Security C5); every key the new root and the current one list, in any
// role, joins seen_keys and never leaves (C2, C8); and the project's
// interim test box stops counting for good (C1, B2). The allow-list itself is the caller's and is unchanged.
func (s *Store) FollowRoot(root []byte, approved, name string, o Options) error {
	m, err := verifyRoot(root, o)
	if err != nil {
		return err
	}
	sum, err := describe(root, m)
	if err != nil {
		return err
	}
	if sum.Digest != approved {
		return ErrFollowNotApproved
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.settle(); err != nil {
		return err
	}
	// Narrowing writes first: a crash after them leaves the old chain
	// with fewer keys able to attest and no interim rule.
	if err := step("seen_keys"); err != nil {
		return err
	}
	seen, err := s.seenKeys()
	if err != nil {
		return err
	}
	// The chain being left: Check keeps its keys in seen_keys only once
	// it rotates, and they must never count once the box stops trusting
	// them as signers (C8).
	cur, err := os.ReadFile(s.p("root.json"))
	if err != nil {
		return err
	}
	old, err := metadata.Root().FromBytes(cur)
	if err != nil {
		return classify(err)
	}
	// A root no newer than the one the box trusts, whose root keys all
	// come from it, is the same chain going back, not a fork: it could
	// trust keys a later root revoked (security R2 on #180). The trusted
	// root itself, byte for byte, re-trusts nothing and may be followed
	// again under another name.
	if rootKeysWithin(m, old) && m.Signed.Version <= old.Signed.Version && !bytes.Equal(root, cur) {
		return fmt.Errorf("%w: root v%d is not newer than this chain's v%d", ErrRollback, m.Signed.Version, old.Signed.Version)
	}
	addKeys(seen, old)
	addKeys(seen, m)
	if err := s.writeSeenKeys(seen); err != nil {
		return err
	}
	if err := step("interim_flag"); err != nil {
		return err
	}
	if err := s.recordOutside(); err != nil {
		return err
	}
	if err := step("project_root"); err != nil {
		return err
	}
	// Leaving the project chain: the root being left is the anchor a
	// later switch back walks from (OSS-10w-r). It only raises the floor
	// a switch back must meet, so a crash after it narrows.
	if name != "" {
		if _, err := os.Stat(s.p(sourceFile)); errors.Is(err, os.ErrNotExist) {
			if err := writeAtomic(s.p(projectFile), cur, 0o600); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	if err := step("marker"); err != nil {
		return err
	}
	src := Followed{}
	if name != "" {
		now := time.Now()
		if o.Now != nil {
			now = o.Now()
		}
		src = Followed{Name: name, Since: now.UTC(), RootSHA256: sum.RootSHA256, Fingerprint: sum.Keys[metadata.ROOT][0]}
	}
	b, _ := json.Marshal(marker{Root: sum.RootSHA256, Source: src})
	if err := writeAtomic(s.p(followFile), b, 0o600); err != nil {
		return err
	}
	if err := step("root"); err != nil {
		return err
	}
	if err := writeAtomic(s.p("root.json"), root, 0o600); err != nil {
		return err
	}
	return s.finishFollow(src)
}

// marker is followFile's content.
type marker struct {
	Root   string   `json:"root_sha256"`
	Source Followed `json:"source"`
}

// finishFollow clears what the old chain left once the new root is written:
// the saved timestamp and snapshot (their versions belong to the old chain)
// and any staged release; records the source; then drops the marker. The
// caller holds the lock.
func (s *Store) finishFollow(src Followed) error {
	for _, n := range []string{"timestamp", "snapshot", "staged"} {
		if err := step(n); err != nil {
			return err
		}
		if err := os.Remove(s.p(n + ".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := step("source"); err != nil {
		return err
	}
	if src.Name == "" {
		if err := os.Remove(s.p(sourceFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		b, _ := json.Marshal(src)
		if err := writeAtomic(s.p(sourceFile), b, 0o600); err != nil {
			return err
		}
	}
	if err := step("done"); err != nil {
		return err
	}
	if err := os.Remove(s.p(followFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.Dir)
}

// settle completes or forgets a switch a crash interrupted. The caller
// holds the lock. Check, CommitStaged and FollowRoot settle first; Stage
// needs no settling, since a release checked under the old root fails
// trustUnchanged once the root is written.
func (s *Store) settle() error {
	b, err := os.ReadFile(s.p(followFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var want marker
	if err := json.Unmarshal(b, &want); err != nil {
		return fmt.Errorf("update: unreadable switch record: %v", err)
	}
	root, err := os.ReadFile(s.p("root.json"))
	if err != nil {
		return err
	}
	if want.Root == Digest(root) {
		return s.finishFollow(want.Source)
	}
	// The root was never written: the old chain stands. What was written
	// (seen keys, the interim flag) only narrows.
	if err := os.Remove(s.p(followFile)); err != nil {
		return err
	}
	return syncDir(s.Dir)
}
