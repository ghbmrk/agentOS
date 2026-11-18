package main

// REQ: HW-8, OWN-17

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// morUnit is the shipped unit whose stop runs clear and records its result.
const morUnit = "../../../image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-mor.service"

// morRecord is the file agentosd's STATUS reads (broker/cmd/agentosd
// wipenote.go wipeFailed, which TestRefusedClearIsToldInStatus holds to
// this unit).
const morRecord = "/var/lib/agentos-mor/refused"

// MOR-clear-owner (#6111): every refusal of clear, run through the unit's
// own stop step with the result systemd hands it (exit-code, exited and the
// status for a non-zero exit), leaves the record STATUS tells; a clear that
// succeeds removes it.
func TestRefusalIsRecorded(t *testing.T) {
	b, err := os.ReadFile(morUnit)
	if err != nil {
		t.Fatal(err)
	}
	var stops []string
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "ExecStopPost="); ok {
			stops = append(stops, strings.ReplaceAll(v, "$$", "$"))
		}
	}
	if len(stops) != 1 || !strings.Contains(stops[0], morRecord) {
		t.Fatalf("ExecStopPost %q, want one naming %s", stops, morRecord)
	}
	record := filepath.Join(t.TempDir(), "agentos-mor", "refused")
	stop := strings.ReplaceAll(stops[0], filepath.Dir(morRecord), filepath.Dir(record))
	// stopPost runs the step as systemd does after clear exits with rc.
	stopPost := func(rc int) {
		t.Helper()
		result := "success"
		if rc != 0 {
			result = "exit-code"
		}
		c := exec.Command("/bin/sh", "-c", stop)
		c.Env = []string{"SERVICE_RESULT=" + result, "EXIT_CODE=exited", fmt.Sprintf("EXIT_STATUS=%d", rc)}
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("rc %d: %v %s", rc, err, out)
		}
	}
	held := func(rel string) func(*host) {
		return func(h *host) {
			p := filepath.Join(h.s.root, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("synthetic-canary"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, c := range []struct {
		name    string
		cmdline string
		mor     []byte
		set     func(*host)
	}{
		{"dev/shm holds a file", wipe, morSet, held("dev/shm/seg")},
		{"setup files left", wipe, morSet, held("run/agentos-setup/passphrase")},
		{"no init_on_free=1", "console=ttyS0 rw", morSet, nil},
		{"MOR attributes", wipe, []byte{3, 0, 0, 0, 1}, nil},
		{"no page cache knob", wipe, morSet, func(h *host) {
			if err := os.Remove(filepath.Join(h.s.root, "proc/sys/vm/drop_caches")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		h := newHost(t, c.cmdline, c.mor)
		if c.set != nil {
			c.set(h)
		}
		rc, _, errOut := h.run("clear")
		if rc != 1 || !strings.Contains(errOut, "left set") {
			t.Fatalf("%s: rc %d, %q", c.name, rc, errOut)
		}
		stopPost(rc)
		if got, err := os.ReadFile(record); err != nil || string(got) != "exit-code exited 1\n" {
			t.Fatalf("%s: record %q, %v", c.name, got, err)
		}
		// The next orderly shutdown's clear succeeds and removes it.
		h = newHost(t, wipe, morSet)
		rc, out, _ := h.run("clear")
		if rc != 0 || out != "agentos-mor: mor=cleared\n" {
			t.Fatalf("rc %d, %q", rc, out)
		}
		stopPost(rc)
		if _, err := os.Lstat(record); !os.IsNotExist(err) {
			t.Fatalf("%s: record after a good clear: %v", c.name, err)
		}
	}
}

// The box's flag calls, which the scratch host replaces, read and write
// the file's own flags (a target since TestRefusalIsRecorded builds a sys).
func TestBoxFlagCalls(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "flags")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := int(f.Fd())
	s := newSys("/")
	got, err := s.getFlags(fd)
	want, werr := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if got != want || !errors.Is(err, werr) {
		t.Fatalf("getFlags %#x %v, want %#x %v", got, err, want, werr)
	}
	if werr == nil {
		if err := s.setFlags(fd, got); err != nil {
			t.Fatalf("setFlags of the same flags: %v", err)
		}
	}
}
