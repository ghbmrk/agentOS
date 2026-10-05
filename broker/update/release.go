// Package update signs and verifies AgentOS releases (UPD-2, UPD-8, UPD-1a).
//
// Metadata follows The Update Framework through go-tuf, the reference Go
// implementation: root, targets, snapshot and timestamp roles, threshold
// signatures, key rotation by chained root versions, and content-addressed
// target files. Maintainers use Repo (and cmd/agentos-release) on offline
// machines; the box uses Store to accept a release only when the
// metadata checks out, online from any mirror or offline from a drive.
//
// A release is one TUF target, releases/<version>.json, naming the /usr
// verity root hash and the files that boot it (UPD-1a). Every file it names
// is itself a target, so the hash of each is signed by the targets role.
package update

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Channels a release can be published on (UPD-4).
const (
	ChannelStable = "stable"
	ChannelFast   = "fast"
)

// Release is the manifest a releases/<version>.json target holds.
type Release struct {
	// Version orders releases; a box never accepts one at or below the
	// installed version (UPD-8).
	Version int64 `json:"version"`
	// Channel is ChannelStable or ChannelFast.
	Channel string `json:"channel"`
	// Security marks a security fix, which auto-stages only with an
	// independent fast-channel attestation as well (UPD-5, UPD-8, D6).
	Security bool `json:"security,omitempty"`
	// UsrRootHash is the dm-verity root hash of /usr, hex (UPD-1a).
	UsrRootHash string `json:"usr_root_hash"`
	// Files are the target paths that make up the release: the boot
	// entry, kernel, initrd, and the /usr image and its verity data.
	Files []string `json:"files"`
}

// ReleasePath is the target path of a release manifest.
func ReleasePath(version int64) string { return fmt.Sprintf("releases/%d.json", version) }

var (
	rootHashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	segmentRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

// validTargetPath accepts relative paths of plain segments: no "..", no
// empty or hidden segments, nothing a mirror could use to escape its
// directory or a box could misread.
func validTargetPath(p string) bool {
	if p == "" || len(p) > 200 || path.Clean(p) != p || strings.HasPrefix(p, "/") {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if !segmentRE.MatchString(s) {
			return false
		}
	}
	return true
}

// Check reports the first thing wrong with a manifest.
func (r Release) Check() error {
	if r.Version < 1 {
		return errors.New("release version must be at least 1")
	}
	if r.Channel != ChannelStable && r.Channel != ChannelFast {
		return fmt.Errorf("release channel %q is not stable or fast", r.Channel)
	}
	if !rootHashRE.MatchString(r.UsrRootHash) {
		return errors.New("usr_root_hash must be 64 lowercase hex digits")
	}
	if len(r.Files) == 0 {
		return errors.New("a release names at least its boot entry")
	}
	seen := map[string]bool{}
	for _, f := range r.Files {
		if !validTargetPath(f) || strings.HasPrefix(f, "releases/") {
			return fmt.Errorf("release file %q is not a plain target path", f)
		}
		if seen[f] {
			return fmt.Errorf("release file %q listed twice", f)
		}
		seen[f] = true
	}
	return nil
}

func parseRelease(b []byte) (Release, error) {
	var r Release
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Release{}, fmt.Errorf("release manifest: %w", err)
	}
	if dec.More() {
		return Release{}, errors.New("release manifest: trailing data")
	}
	return r, r.Check()
}

// RootHashBytes returns the verity root hash as bytes.
func (r Release) RootHashBytes() []byte {
	b, _ := hex.DecodeString(r.UsrRootHash)
	return b
}
