package update

import (
	"encoding/hex"
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

// Manifest is the manifest a releases/<version>.json target holds.
type Manifest struct {
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
	// entry, kernel, initrd, and the /usr image and its verity data, each
	// under host-image/ or guest-image/ as the change pipeline expects.
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
func (r Manifest) Check() error {
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
		ns, _, _ := strings.Cut(f, "/")
		if !validTargetPath(f) || (ns != "host-image" && ns != "guest-image") {
			return fmt.Errorf("release file %q is not a plain path under host-image/ or guest-image/", f)
		}
		if seen[f] {
			return fmt.Errorf("release file %q listed twice", f)
		}
		seen[f] = true
	}
	return nil
}

var manifestFields = fields("version", "channel", "security", "usr_root_hash", "files")

func parseManifest(b []byte) (Manifest, error) {
	var r Manifest
	if err := decodeStrict(b, &r, manifestFields); err != nil {
		return Manifest{}, fmt.Errorf("release manifest: %w", err)
	}
	return r, r.Check()
}

// RootHashBytes returns the verity root hash as bytes.
func (r Manifest) RootHashBytes() []byte {
	b, _ := hex.DecodeString(r.UsrRootHash)
	return b
}
