package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// writeHere lets the file gate write under dir for one test, as it writes
// under writeDirs on the box.
func writeHere(t *testing.T, dir string) {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := writeDirs
	writeDirs = append(append([]string{}, old...), real)
	t.Cleanup(func() { writeDirs = old })
}

// REQ: HW-10, ONB-3. The file gate decides on what an open reached, not
// on the path's spelling (#4609): a journal file is refused by its first
// bytes however it is reached (a link, another spelling, /proc's fd
// links, a worker's layer), and a write or a new link is refused unless
// its resolved place is under writeDirs or one of writeFiles, also when a
// directory link leads out of writeDirs.
func TestFileGateRefusesJournalsAndForeignWrites(t *testing.T) {
	logs, mine, other := t.TempDir(), t.TempDir(), t.TempDir()
	writeHere(t, mine)
	journal := filepath.Join(logs, "system.journal")
	if err := os.WriteFile(journal, []byte(journalMagic+"journal-canary-0f3a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(journal, filepath.Join(other, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(logs, filepath.Join(mine, "logs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(mine, "out")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(journal, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for _, p := range []string{
		journal,
		logs + "//./system.journal",
		filepath.Join(other, "../"+filepath.Base(logs), "system.journal"),
		filepath.Join(mine, "logs", "system.journal"),
		"/proc/self/root" + journal,
		"/proc/self/fd/" + strconv.Itoa(fd),
	} {
		if _, err := openRaw(p, unix.O_RDONLY, 0); !errors.Is(err, errJournal) {
			t.Errorf("openRaw(%q) = %v, want the journal refused", p, err)
		}
	}
	if fd, err := openRaw(filepath.Join(other, "link"), unix.O_RDONLY, 0); !errors.Is(err, errJournal) {
		if err == nil {
			unix.Close(fd)
		}
		t.Errorf("openRaw through a link = %v, want the journal refused", err)
	}
	if _, err := readNoFollow(journal); !errors.Is(err, errJournal) {
		t.Errorf("readNoFollow(journal) = %v", err)
	}
	r, err := os.OpenRoot(logs)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := rootOpen(r, "system.journal"); !errors.Is(err, errJournal) {
		t.Errorf("rootOpen(journal) = %v", err)
	}

	plain := filepath.Join(other, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		do   func() error
	}{
		{"new file outside", func() error { return writeNoFollow(filepath.Join(other, "ip"), []byte("#!/bin/sh"), 0o755) }},
		{"new file through a directory link", func() error { return writeNoFollow(filepath.Join(mine, "out", "ip"), []byte("#!/bin/sh"), 0o755) }},
		{"existing file opened for writing", func() error { _, err := openRaw(plain, unix.O_WRONLY, 0); return err }},
		{"existing file opened read-write", func() error { _, err := openRaw(plain, unix.O_RDWR, 0); return err }},
		{"existing file through a directory link", func() error { _, err := openRaw(filepath.Join(mine, "out", "plain"), unix.O_WRONLY, 0); return err }},
		{"link outside", func() error { return symlink(filepath.Join(mine, "x"), filepath.Join(other, "zz.service")) }},
		{"link through a directory link", func() error { return symlink(filepath.Join(mine, "x"), filepath.Join(mine, "out", "zz.service")) }},
	} {
		if err := c.do(); !errors.Is(err, errWrite) {
			t.Errorf("%s: %v, want the write refused", c.name, err)
		}
	}
	if got, _ := os.ReadFile(plain); string(got) != "x" {
		t.Errorf("a refused write changed the file: %q", got)
	}
	if _, err := os.Lstat(filepath.Join(other, "ip")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused write made a file: %v", err)
	}
	if err := writeNoFollow(filepath.Join(mine, "ok"), []byte("ok"), 0o600); err != nil {
		t.Errorf("a write under writeDirs: %v", err)
	}
	if err := symlink("ok", filepath.Join(mine, "ok-link")); err != nil {
		t.Errorf("a link under writeDirs: %v", err)
	}
	if b, err := readNoFollow(filepath.Join(mine, "ok")); err != nil || string(b) != "ok" {
		t.Errorf("a read of a plain file: %q, %v", b, err)
	}
}
