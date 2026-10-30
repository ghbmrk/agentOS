//go:build linux

package bootab

// REQ: UPD-1a

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestVerityLabel: the verity label is the data label + "_verity", or
// EmptyLabel for EmptyLabel, and both fit GPT's 36 characters.
func TestVerityLabel(t *testing.T) {
	for label, want := range map[string]string{
		"agentos_20261031120000": "agentos_20261031120000_verity",
		EmptyLabel:               EmptyLabel,
		strings.Repeat("x", 29):  strings.Repeat("x", 29) + "_verity",
	} {
		if got, err := verityLabel(label); err != nil || got != want {
			t.Errorf("verityLabel(%q) = %q, %v; want %q", label, got, err, want)
		}
	}
	for _, label := range []string{strings.Repeat("x", 30), "agentos 1", ""} {
		if got, err := verityLabel(label); err == nil {
			t.Errorf("verityLabel(%q) = %q, want an error", label, got)
		}
	}
}

// TestClearImmutable: an immutable variable has only that flag cleared
// before a write; a variable without it is left alone; a file system
// without the flag ioctl has nothing to clear; any other failure stops
// the write. Setting the flag needs root, so the ioctls are stood in for.
func TestClearImmutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LoaderEntryDefault-"+loaderGUID)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	get, set := getFlags, setFlags
	t.Cleanup(func() { getFlags, setFlags = get, set })
	for _, c := range []struct {
		name    string
		flags   uint32
		getErr  error
		wantSet []uint32
		wantErr error
	}{
		{"immutable", fsImmutable | 0x80, nil, []uint32{0x80}, nil},
		{"mutable", 0x80, nil, nil, nil},
		{"no ioctl", 0, syscall.ENOTTY, nil, nil},
		{"failed read", 0, syscall.EIO, nil, syscall.EIO},
	} {
		t.Run(c.name, func(t *testing.T) {
			var sets []uint32
			getFlags = func(int) (uint32, error) { return c.flags, c.getErr }
			setFlags = func(_ int, f uint32) error { sets = append(sets, f); return nil }
			err := clearImmutable(path)
			if !errors.Is(err, c.wantErr) || (c.wantErr == nil) != (err == nil) {
				t.Errorf("clearImmutable = %v, want %v", err, c.wantErr)
			}
			if len(sets) != len(c.wantSet) || len(sets) == 1 && sets[0] != c.wantSet[0] {
				t.Errorf("set flags %x, want %x", sets, c.wantSet)
			}
		})
	}
}
