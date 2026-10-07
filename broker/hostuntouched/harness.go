// Package hostuntouched is the HOST-1e acceptance harness: hash second
// disk / RTC / UEFI / TPM NV against an allow-list (HW-8, A1).
package hostuntouched

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// AllowList is the set of host artefacts that MAY change. Everything else
// on the measured set must keep its pre-boot hash.
type AllowList struct {
	// UEFIVars lists variable names that may differ (e.g. BootOrder when
	// using a one-time boot key is still forbidden — empty by default).
	UEFIVars []string
	// TPMNVIndices lists NV indices the box itself owns (vault counter).
	TPMNVIndices []uint32
}

// Snapshot is one measurement point.
type Snapshot struct {
	Disk2SHA256 string
	RTC         string // civil time truncated; compared only if PersistRTC
	UEFIVars    map[string]string // name -> sha256 of value
	TPMNV       map[uint32]string // index -> sha256 of contents
}

// Diff is one disallowed change.
type Diff struct {
	What string
	Want string
	Got  string
}

func (d Diff) Error() string {
	return fmt.Sprintf("host-untouched: %s changed: want %s got %s", d.What, d.Want, d.Got)
}

// Hash returns hex SHA-256 of b.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Check compares after to before under allow. PersistRTC when true requires
// RTC equality (HW-8).
func Check(before, after Snapshot, allow AllowList, persistRTC bool) []Diff {
	var out []Diff
	if before.Disk2SHA256 != "" && before.Disk2SHA256 != after.Disk2SHA256 {
		out = append(out, Diff{What: "2nd disk", Want: before.Disk2SHA256, Got: after.Disk2SHA256})
	}
	if persistRTC && before.RTC != after.RTC {
		out = append(out, Diff{What: "RTC", Want: before.RTC, Got: after.RTC})
	}
	allowedVar := map[string]bool{}
	for _, n := range allow.UEFIVars {
		allowedVar[n] = true
	}
	for name, want := range before.UEFIVars {
		got := after.UEFIVars[name]
		if want != got && !allowedVar[name] {
			out = append(out, Diff{What: "UEFI " + name, Want: want, Got: got})
		}
	}
	allowedNV := map[uint32]bool{}
	for _, i := range allow.TPMNVIndices {
		allowedNV[i] = true
	}
	for idx, want := range before.TPMNV {
		got := after.TPMNV[idx]
		if want != got && !allowedNV[idx] {
			out = append(out, Diff{What: fmt.Sprintf("TPM NV %#x", idx), Want: want, Got: got})
		}
	}
	return out
}
