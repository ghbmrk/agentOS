package main

// REQ: UPD-2, UPD-8

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/update"
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
	must("keygen", k("ci"))
	if !strings.Contains(out.String(), "offline media") {
		t.Fatalf("keygen gave no custody reminder: %q", out.String())
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
	must("attestors", "-repo", repo, "-keys", k("ci.pub"))
	must("sign", "-repo", repo, "-role", "targets", "-key", k("t0.key"))
	must("sign", "-repo", repo, "-role", "targets", "-key", k("t1.key"))
	must("publish", "-repo", repo, "-snapshot-key", k("snap.key"), "-timestamp-key", k("ts.key"))
	os.Chmod(k("snap.key"), 0o644)
	if err := do("refresh", "-repo", repo, "-snapshot-key", k("snap.key"), "-timestamp-key", k("ts.key")); err == nil {
		t.Fatal("used a world-readable key")
	}
	os.Chmod(k("snap.key"), 0o600)

	entry := k("entry.conf")
	os.WriteFile(entry, []byte("title AgentOS 7\n"), 0o644)
	must("add-release", "-repo", repo, "-version", "7", "-usr-root-hash", strings.Repeat("0f", 32),
		"-file", "host-image/7/entry.conf="+entry, "-security")
	must("sign", "-repo", repo, "-role", "targets", "-key", k("t0.key"))
	if err := do("publish", "-repo", repo, "-snapshot-key", k("snap.key"), "-timestamp-key", k("ts.key")); err == nil {
		t.Fatal("published a release with 1 of 2 targets signatures")
	}
	must("sign", "-repo", repo, "-role", "targets", "-key", k("t1.key"))
	must("publish", "-repo", repo, "-snapshot-key", k("snap.key"), "-timestamp-key", k("ts.key"))
	must("refresh", "-repo", repo, "-snapshot-key", k("snap.key"), "-timestamp-key", k("ts.key"))

	must("verify", "-repo", repo, "-root", filepath.Join(repo, "metadata", "1.root.json"), "-installed", "6")
	if !strings.Contains(out.String(), "verified release 7 (stable, security=true)") || !strings.Contains(out.String(), "host-image/7/entry.conf") {
		t.Fatalf("verify said %q", out.String())
	}
	must("verify", "-repo", repo, "-root", filepath.Join(repo, "metadata", "1.root.json"), "-installed", "7", "-offline")
	if !strings.Contains(out.String(), "no release newer than 7") {
		t.Fatalf("verify said %q", out.String())
	}

	// verify's scratch store opens under a TMPDIR reached through a link,
	// as macOS's /var is (#4225 item 4); a TMPDIR other uids can write is
	// still refused, and the error names TMPDIR as the remedy.
	tmp := t.TempDir()
	tmpLink := filepath.Join(d, "tmplink")
	if err := os.Symlink(tmp, tmpLink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmpLink)
	must("verify", "-repo", repo, "-root", filepath.Join(repo, "metadata", "1.root.json"), "-installed", "6")
	if err := os.Chmod(tmp, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := do("verify", "-repo", repo, "-root", filepath.Join(repo, "metadata", "1.root.json"), "-installed", "6"); err == nil || !strings.Contains(err.Error(), "TMPDIR") {
		t.Fatalf("verify under a group-writable TMPDIR: %v, want refused naming TMPDIR", err)
	}
	// A malformed root is not a scratch-store refusal: its error does not
	// send the maintainer to TMPDIR.
	bad := filepath.Join(d, "bad.root.json")
	if err := os.WriteFile(bad, []byte(`{"signed":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// It names the -root file as malformed, not the repository (#4977
	// item 4, #5059 item 4).
	if err := do("verify", "-repo", repo, "-root", bad, "-installed", "6"); err == nil || strings.Contains(err.Error(), "TMPDIR") ||
		!strings.HasPrefix(err.Error(), "verify: -root "+bad+": root metadata file is malformed") || strings.Contains(err.Error(), "repository") {
		t.Fatalf("verify with a malformed root: %v, want an error naming -root %s as malformed, not TMPDIR or the repository", err, bad)
	}
	// A root that parses but is not signed by its own keys names the -root
	// file as a signature failure (#5059 item 3).
	good, err := os.ReadFile(filepath.Join(repo, "metadata", "1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(good, &doc); err != nil {
		t.Fatal(err)
	}
	doc["signatures"] = []any{}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := filepath.Join(d, "unsigned.root.json")
	if err := os.WriteFile(unsigned, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := do("verify", "-repo", repo, "-root", unsigned, "-installed", "6"); err == nil ||
		!strings.HasPrefix(err.Error(), "verify: -root "+unsigned+": "+update.ErrSignatures.Error()) {
		t.Fatalf("verify with a root not signed by its own keys: %v, want an error naming -root %s and its signatures", err, unsigned)
	}
}

// agentos-release builds for macOS, where a maintainer may sign (#4918
// item 2): broker/update keeps its Linux-only openat2 path in a _linux.go
// file with a portable fallback.
func TestReleaseToolBuildsOnDarwin(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", os.DevNull, ".")
	cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("GOOS=darwin build: %v\n%s", err, out)
	}
}
