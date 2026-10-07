package update

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// RenewWithin is how long before root or targets expire that Status warns
// (P4-3 PR1): the offline holders need weeks to meet and sign, and a box
// refuses expired metadata online.
const RenewWithin = 60 * 24 * time.Hour

// RoleStatus is one role of a repository as the maintainers see it.
type RoleStatus struct {
	Role string
	// Version, Expires, Signatures and Threshold describe the published
	// copy (Version 0: none). Signatures counts only signatures that verify
	// under a key the root in force gives the role.
	Version    int64
	Expires    time.Time
	Signatures int
	Threshold  int
	// StagedVersion (0: nothing staged) and its signatures, for root and
	// targets, which collect offline signatures before Publish. A staged
	// root counts against its own threshold; Publish also needs the old
	// root's (OldSignatures of OldThreshold).
	StagedVersion    int64
	StagedSignatures int
	StagedThreshold  int
	OldSignatures    int
	OldThreshold     int
}

// RepoStatus is what `agentos-release status` prints (UX-46-4).
type RepoStatus struct {
	Roles []RoleStatus
	// Releases are the release versions the published targets list.
	Releases []int64
	// Notes are staged roles still collecting signatures: information,
	// not a fault.
	Notes []string
	// Warnings need a maintainer: root or targets within RenewWithin of
	// expiry (PR1), snapshot or timestamp past half their life (PU1),
	// anything expired, or a published role under its threshold.
	Warnings []string
}

// Status reads the repository without changing it. Signatures are checked
// with go-tuf one at a time, so a bad or foreign one is not counted.
func (r Repo) Status() (RepoStatus, error) {
	var s RepoStatus
	now := r.now()
	var root *metadata.Metadata[metadata.RootType]
	if _, b, err := r.published(metadata.ROOT); err != nil {
		return s, err
	} else if b == nil {
		s.Warnings = append(s.Warnings, "no published root: sign the staged root and publish")
	} else if root, err = metadata.Root().FromBytes(b); err != nil {
		return s, err
	}
	stagedRoot, err := metadata.Root().FromFile(r.p("staged", "root.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return s, err
	}
	// The root that decides targets signatures: a staged one goes in
	// force first at Publish.
	targetsRoot := root
	if stagedRoot != nil {
		targetsRoot = stagedRoot
	}

	// root
	rs := RoleStatus{Role: metadata.ROOT}
	if root != nil {
		rs.Version, rs.Expires = root.Signed.Version, root.Signed.Expires
		rs.Signatures, rs.Threshold = count(root, metadata.ROOT, root, root.Signatures)
	}
	if stagedRoot != nil {
		rs.StagedVersion = stagedRoot.Signed.Version
		rs.StagedSignatures, rs.StagedThreshold = count(stagedRoot, metadata.ROOT, stagedRoot, stagedRoot.Signatures)
		note := fmt.Sprintf("staged root v%d: %d of %d signatures", rs.StagedVersion, rs.StagedSignatures, rs.StagedThreshold)
		if root != nil {
			rs.OldSignatures, rs.OldThreshold = count(root, metadata.ROOT, stagedRoot, stagedRoot.Signatures)
			note += fmt.Sprintf(", %d of %d from the root in force", rs.OldSignatures, rs.OldThreshold)
		}
		s.Notes = append(s.Notes, note)
	}
	s.Roles = append(s.Roles, rs)

	// targets
	ts := RoleStatus{Role: metadata.TARGETS}
	if v, b, err := r.published(metadata.TARGETS); err != nil {
		return s, err
	} else if b != nil {
		m, err := metadata.Targets().FromBytes(b)
		if err != nil {
			return s, err
		}
		ts.Version, ts.Expires = v, m.Signed.Expires
		if root != nil {
			ts.Signatures, ts.Threshold = count(root, metadata.TARGETS, m, m.Signatures)
		}
		for p := range m.Signed.Targets {
			if n, ok := releaseVersion(p); ok {
				s.Releases = append(s.Releases, n)
			}
		}
		sort.Slice(s.Releases, func(i, j int) bool { return s.Releases[i] < s.Releases[j] })
	}
	if m, err := metadata.Targets().FromFile(r.p("staged", "targets.json")); err == nil {
		ts.StagedVersion = m.Signed.Version
		if targetsRoot != nil {
			ts.StagedSignatures, ts.StagedThreshold = count(targetsRoot, metadata.TARGETS, m, m.Signatures)
		}
		s.Notes = append(s.Notes, fmt.Sprintf("staged targets v%d: %d of %d signatures", ts.StagedVersion, ts.StagedSignatures, ts.StagedThreshold))
	} else if !errors.Is(err, os.ErrNotExist) {
		return s, err
	}
	s.Roles = append(s.Roles, ts)

	// snapshot and timestamp
	ss := RoleStatus{Role: metadata.SNAPSHOT}
	if v, b, err := r.published(metadata.SNAPSHOT); err != nil {
		return s, err
	} else if b != nil {
		m, err := metadata.Snapshot().FromBytes(b)
		if err != nil {
			return s, err
		}
		ss.Version, ss.Expires = v, m.Signed.Expires
		if root != nil {
			ss.Signatures, ss.Threshold = count(root, metadata.SNAPSHOT, m, m.Signatures)
		}
	}
	s.Roles = append(s.Roles, ss)
	tss := RoleStatus{Role: metadata.TIMESTAMP}
	if m, err := metadata.Timestamp().FromFile(r.p("metadata", "timestamp.json")); err == nil {
		tss.Version, tss.Expires = m.Signed.Version, m.Signed.Expires
		if root != nil {
			tss.Signatures, tss.Threshold = count(root, metadata.TIMESTAMP, m, m.Signatures)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return s, err
	}
	s.Roles = append(s.Roles, tss)

	life := map[string]time.Duration{metadata.SNAPSHOT: SnapshotExpiry, metadata.TIMESTAMP: TimestampExpiry}
	for _, x := range s.Roles {
		if x.Version == 0 {
			if x.Role != metadata.ROOT && root != nil {
				s.Warnings = append(s.Warnings, fmt.Sprintf("no published %s", x.Role))
			}
			continue
		}
		left := x.Expires.Sub(now)
		switch {
		case left <= 0:
			s.Warnings = append(s.Warnings, fmt.Sprintf("%s v%d expired %s: boxes refuse it online", x.Role, x.Version, x.Expires.Format(time.DateOnly)))
		case life[x.Role] > 0 && left < life[x.Role]/2:
			s.Warnings = append(s.Warnings, fmt.Sprintf("%s v%d is past half its life, expiring in %s: run refresh", x.Role, x.Version, left.Round(time.Minute)))
		case life[x.Role] == 0 && left < RenewWithin:
			s.Warnings = append(s.Warnings, fmt.Sprintf("%s v%d expires in %d days (%s): stage, sign and publish a new version", x.Role, x.Version, int(left/(24*time.Hour)), x.Expires.Format(time.DateOnly)))
		}
		if root != nil && x.Signatures < x.Threshold {
			s.Warnings = append(s.Warnings, fmt.Sprintf("%s v%d has %d of %d signatures", x.Role, x.Version, x.Signatures, x.Threshold))
		}
	}
	return s, nil
}

// count returns how many of sigs verify under distinct keys delegator gives
// roleName, and the role's threshold. Each signature is checked alone
// against a copy of the delegator that trusts only its key with threshold
// 1, so go-tuf does the verification.
func count[T role](delegator *metadata.Metadata[metadata.RootType], roleName string, m *metadata.Metadata[T], sigs []metadata.Signature) (n, threshold int) {
	rl := delegator.Signed.Roles[roleName]
	if rl == nil {
		return 0, 0
	}
	b, err := delegator.ToBytes(false)
	if err != nil {
		return 0, rl.Threshold
	}
	seen := map[string]bool{}
	for _, sg := range sigs {
		if seen[sg.KeyID] || !contains(rl.KeyIDs, sg.KeyID) {
			continue
		}
		one, err := metadata.Root().FromBytes(b)
		if err != nil {
			continue
		}
		one.Signed.Roles[roleName].KeyIDs = []string{sg.KeyID}
		one.Signed.Roles[roleName].Threshold = 1
		cp := *m
		cp.Signatures = []metadata.Signature{sg}
		if one.VerifyDelegate(roleName, &cp) == nil {
			seen[sg.KeyID] = true
			n++
		}
	}
	return n, rl.Threshold
}
