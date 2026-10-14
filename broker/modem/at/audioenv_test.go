package at

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// REQ: ARC-2, CRED-1
//
// P3-4b-3r-env requirement 1 and r8b: arecord and aplay start through
// childproc with exactly a fixed PATH, nothing from the modem service's
// environment. Fakes on PATH dump the
// environment they were given: arecord to its output, aplay to a file.
func TestAudioToolsGetNoInheritedEnvironment(t *testing.T) {
	const canary = "+15550100999-audio-canary"
	dir := t.TempDir()
	out := filepath.Join(dir, "aplay.env")
	for name, body := range map[string]string{
		"arecord": "#!/bin/sh\nexec env\n",
		"aplay":   "#!/bin/sh\n{ env; echo END; } >" + out + ".tmp && exec mv " + out + ".tmp " + out + "\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AGENTOS_OWNER", canary)

	rec, err := ALSA{}.Record(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rec)
	rec.Close()
	if err != nil {
		t.Fatal(err)
	}
	play, err := ALSA{}.Play(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	defer play.Close()
	var pgot []byte
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if pgot, err = os.ReadFile(out); err == nil {
			break
		}
	}
	for tool, env := range map[string]string{"arecord": string(got), "aplay": string(pgot)} {
		var got []string
		for _, kv := range strings.Fields(env) {
			if !strings.HasPrefix(kv, "PWD=") && kv != "END" { // the fake's shell sets PWD itself
				got = append(got, kv)
			}
		}
		if want := []string{"PATH=/usr/bin:/bin"}; !slices.Equal(got, want) {
			t.Errorf("%s env %q, want %q", tool, got, want)
		}
	}
}
