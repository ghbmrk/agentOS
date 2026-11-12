package load

// REQ: NET-2, KRN-12

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestListTellsAbsentFromUnread (#5491, ENF-l-15): only nft's exit 1 with
// the first stderr line exactly "Error: No such file or directory" is an
// absent table (ErrNoTable); EPERM, another message that ends the same way,
// another exit, a killed nft, a bad path and a deadline are not, so the
// enforcer reads them as an unread table.
func TestListTellsAbsentFromUnread(t *testing.T) {
	dir := t.TempDir()
	fake := func(name, body string) Loader {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return Loader{Bin: p}
	}
	for _, c := range []struct {
		name, body string
		absent     bool
	}{
		{"enoent", "echo 'Error: No such file or directory' >&2; exit 1", true},
		{"enoent-after-context", "printf 'Error: No such file or directory\\nlist table inet enforcer\\n' >&2; exit 1", true},
		{"eperm", "echo 'Error: Operation not permitted' >&2; exit 1", false},
		{"enoent-other-exit", "echo 'Error: No such file or directory' >&2; exit 2", false},
		{"enoent-other-message", "echo 'Error: Could not process rule: No such file or directory' >&2; exit 1", false},
		{"enoent-first-word", "echo 'No such file or directory: busy' >&2; exit 1", false},
		{"silent", "exit 1", false},
		{"killed", "echo 'Error: No such file or directory' >&2; kill -9 $$", false},
	} {
		_, err := fake(c.name, c.body).List(context.Background(), "enforcer")
		if err == nil || errors.Is(err, ErrNoTable) != c.absent {
			t.Errorf("%s: %v, absent want %v", c.name, err, c.absent)
		}
	}
	if _, err := (Loader{Bin: "/nonexistent/nft"}).List(context.Background(), "enforcer"); err == nil || errors.Is(err, ErrNoTable) {
		t.Errorf("a missing nft: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := fake("slow", "echo 'Error: No such file or directory' >&2; exec sleep 5").List(ctx, "enforcer"); err == nil || errors.Is(err, ErrNoTable) {
		t.Errorf("a listing past its deadline: %v", err)
	}
	// #5504 item 3: List's own guards. nft runs with an empty environment,
	// only from an absolute path and only for a plain identifier, and a
	// failure's line in the error is cut at 200 bytes.
	t.Setenv("AGENTOS_LOAD_CANARY", "1")
	ok := fake("ok", `[ -z "$AGENTOS_LOAD_CANARY" ] || exit 3; echo '{}'`)
	if out, err := ok.List(context.Background(), "enforcer"); err != nil || string(out) != "{}\n" {
		t.Errorf("a listing with an empty environment: %q %v", out, err)
	}
	for _, table := range []string{"", "Enforcer", "enforcer x", "enforcer;"} {
		if _, err := ok.List(context.Background(), table); err == nil {
			t.Errorf("table %q listed", table)
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, ok.Bin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Loader{Bin: "./" + rel}).List(context.Background(), "enforcer"); err == nil {
		t.Errorf("a relative nft path %q listed", rel)
	}
	long := fake("long", "printf 'Error: %0300d\\n' 0 >&2; exit 1")
	if _, err := long.List(context.Background(), "enforcer"); err == nil || len(err.Error()) > 300 {
		t.Errorf("a long failure line is not cut: %v", err)
	}
}
