package at

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: ARC-2
//
// P3-4b-3r-env requirement 1: arecord and aplay get a fixed PATH and
// nothing from the modem service's environment. Fakes on PATH dump the
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
		if !strings.Contains(env, "PATH=/usr/bin:/bin\n") {
			t.Errorf("%s: no fixed PATH in:\n%s", tool, env)
		}
		if strings.Contains(env, canary) {
			t.Errorf("%s sees the service's environment:\n%s", tool, env)
		}
	}
}
