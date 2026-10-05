package main

// REQ: UPD-2, UPD-8

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The whole maintainer flow through the command: keys, a 2-of-3 root and
// targets, one release signed by two holders, and a box-side verify.
func TestReleaseFlowThroughTheCommand(t *testing.T) {
	d := t.TempDir()
	repo := filepath.Join(d, "repo")
	k := func(n string) string { return filepath.Join(d, n) }
	var out bytes.Buffer
	do := func(args ...string) error {
		out.Reset()
		return run(args, &out)
	}
	must := func(args ...string) {
		t.Helper()
		if err := do(args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out.String())
		}
	}
	for _, n := range []string{"r0", "r1", "r2", "t0", "t1", "t2", "snap", "ts"} {
		must("keygen", k(n))
	}
	if fi, _ := os.Stat(k("r0.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v", fi.Mode().Perm())
	}
	if err := do("keygen", k("r0")); err == nil {
		t.Fatal("keygen overwrote a key")
	}
	must("init", "-repo", repo,
		"-root", k("r0.pub")+","+k("r1.pub")+","+k("r2.pub"),
		"-targets", k("t0.pub")+","+k("t1.pub")+","+k("t2.pub"),
		"-snapshot", k("snap.pub"), "-timestamp", k("ts.pub"))
	must("sign", "-repo", repo, "-role", "root", "-key", k("r0.key"))
	must("sign", "-repo", repo, "-role", "root", "-key", k("r2.key"))
	must("sign", "-repo", repo, "-role", "targets", "-key", k("t1.key"))
	must("sign", "-repo", repo, "-role", "targets", "-key", k("t2.key"))
	must("publish", "-repo", repo, "-snapshot-key", k("snap.key"), "-timestamp-key", k("ts.key"))

	entry := k("entry.conf")
	os.WriteFile(entry, []byte("title AgentOS 7\n"), 0o644)
	must("add-release", "-repo", repo, "-version", "7", "-usr-root-hash", strings.Repeat("0f", 32),
		"-file", "boot/7/entry.conf="+entry, "-security")
	must("sign", "-repo", repo, "-role", "targets", "-key", k("t0.key"))
	if err := do("publish", "-repo", repo, "-snapshot-key", k("snap.key"), "-timestamp-key", k("ts.key")); err == nil {
		t.Fatal("published a release with 1 of 2 targets signatures")
	}
	must("sign", "-repo", repo, "-role", "targets", "-key", k("t1.key"))
	must("publish", "-repo", repo, "-snapshot-key", k("snap.key"), "-timestamp-key", k("ts.key"))
	must("refresh", "-repo", repo, "-snapshot-key", k("snap.key"), "-timestamp-key", k("ts.key"))

	must("verify", "-repo", repo, "-root", filepath.Join(repo, "metadata", "1.root.json"), "-installed", "6")
	if !strings.Contains(out.String(), "verified release 7 (stable, security=true)") || !strings.Contains(out.String(), "boot/7/entry.conf") {
		t.Fatalf("verify said %q", out.String())
	}
	must("verify", "-repo", repo, "-root", filepath.Join(repo, "metadata", "1.root.json"), "-installed", "7", "-offline")
	if !strings.Contains(out.String(), "no release newer than 7") {
		t.Fatalf("verify said %q", out.String())
	}
}
