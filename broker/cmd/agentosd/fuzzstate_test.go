package main

// REQ: LOOP-7, LOOP-1, RES-4
//
// P3-4b-3r-confine-r2 and -r4: the fuzz user's tree is its own, beside
// the broker's state rather than inside it, and a disk quota of its own
// bounds it. A box that cannot bound it runs no fuzz targets.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/quota"
	"github.com/ghbmrk/agentos/broker/quota/quotatest"
)

// reachableQuotaDir is a fresh file system with project quotas whose
// mount point every user can reach, as /var/lib is.
func reachableQuotaDir(t *testing.T) string {
	t.Helper()
	d := quotatest.Dir(t, 64)
	for p := d; p != os.TempDir() && p != "/" && strings.HasPrefix(p, os.TempDir()); p = filepath.Dir(p) {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// LOOP-7: the fuzz state is a tree of its own under root-owned /var/lib,
// not under the broker's /var/lib/agentos, whose files a search ACL
// would open to the fuzz user (#588 L3 3, Security R3). main sets it from
// the constant; no flag moves it.
func TestTheFuzzStateIsATreeOfItsOwnBesideTheBrokers(t *testing.T) {
	if fuzzState != "/var/lib/agentos-fuzz" {
		t.Fatalf("fuzz state %s", fuzzState)
	}
	if filepath.Dir(fuzzState) != "/var/lib" || strings.HasPrefix(fuzzState+"/", "/var/lib/agentos/") {
		t.Fatalf("fuzz state %s is not beside the broker's", fuzzState)
	}
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`flag\.\w+\(&learn\.Loop7\b|"loop7"`).Match(b) {
		t.Fatal("main.go takes the fuzz state from a flag")
	}
	if !regexp.MustCompile(`learn\.Loop7\s*=\s*fuzzState\b`).Match(b) && !regexp.MustCompile(`learn\.Fuzz, learn\.Loop7(, \w+(\.\w+)?)* = fuzzRelease, fuzzState\b`).Match(b) {
		t.Fatal("main.go does not set the fuzz state from fuzzState")
	}
}

// RES-4: the fuzz tree's quota project is its own: machines take IDs
// above vm's projectBase (0x41470000), and 0 is every untagged file.
// Its limits hold the caches' 512 MiB with room for targets and scratch.
func TestTheFuzzTreeHasAProjectOfItsOwn(t *testing.T) {
	if fuzzProject == 0 || fuzzProject >= 0x41470000 {
		t.Fatalf("fuzz project %#x may be a machine's", fuzzProject)
	}
	// main leaves FuzzDiskBytes unset, so the box gets the constant.
	if fuzzDiskBytes != 1<<30 || (learnPaths{}).fuzzDisk() != 1<<30 || fuzzDiskInodes <= 0 {
		t.Fatalf("fuzz tree limits %d bytes (%d unset), %d inodes", fuzzDiskBytes, (learnPaths{}).fuzzDisk(), fuzzDiskInodes)
	}
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "FuzzDiskBytes") {
		t.Fatal("main.go sets the fuzz tree's quota")
	}
}

// LOOP-1, RES-4: with -disk-quota=off, or on a file system without
// project quotas, fuzzJail gives no jail and says why, and agentosd runs
// no fuzz targets rather than ones whose writes nothing bounds.
func TestFuzzRunsNothingWhoseDiskItCannotBound(t *testing.T) {
	for name, c := range map[string]struct {
		mode string
		want func(error) bool
	}{
		"quotas off":       {"off", func(err error) bool { return err != nil && strings.Contains(err.Error(), "-disk-quota=off") }},
		"no quota on disk": {"on", func(err error) bool { return errors.Is(err, quota.ErrUnsupported) }},
		"mode unset":       {"", func(err error) bool { return err != nil }},
	} {
		dir := t.TempDir()
		p := learnPaths{Loop7: filepath.Join(dir, "loop7"), FuzzUser: "nobody", Cgroup: t.TempDir(), DiskQuota: c.mode}
		if err := os.Mkdir(p.Loop7, 0o700); err != nil {
			t.Fatal(err)
		}
		j, err := fuzzJail(p)
		if j != nil || !c.want(err) {
			t.Errorf("%s: jail %v, err %v", name, j, err)
		}
		release := fakeFuzzRelease(t, crashing)
		p.Fuzz = release
		lp := openConfinedLearning(t, t.TempDir(), p)
		if lp.fuzz == nil || lp.fuzz.Recheck() != fuzzEvery {
			t.Errorf("%s: fuzz targets wired without a disk bound", name)
		}
	}
}

// LOOP-7 (F16): fuzzJail refuses a state the fuzz user could swap for a
// link: one whose parent it can write, or a link itself.
func TestFuzzJailRefusesAStateTheUserCouldSwap(t *testing.T) {
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "loop7")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	for name, state := range map[string]string{"parent writable": filepath.Join(open, "loop7"), "a link": link} {
		os.Mkdir(state, 0o700)
		j, err := fuzzJail(learnPaths{Loop7: state, FuzzUser: "nobody", Cgroup: t.TempDir(), DiskQuota: "on"})
		if j != nil || err == nil {
			t.Errorf("%s: jail %v, err %v", name, j, err)
		}
	}
}

// LOOP-7, LOOP-1, RES-4 (root, cgroup v2, project quotas; CI machines
// job): a jailed fuzz child in the real state path cannot read a broker
// file others may read (the modem's roles.json, 0644), cannot retag its
// tree out of its quota project, and is stopped at the quota when it
// writes past it, with the disk around it left free. A prjquota file
// system is mounted at the state path for the test.
func TestAFuzzChildReachesOnlyItsOwnBoundedTree(t *testing.T) {
	// The test's quota is 256 MiB, under the leaf's memory.max: the loop
	// device charges its backing file's page cache to the writer's memcg,
	// so at the box's 1 GiB the leaf's OOM kill would come first (#628).
	const testDisk = 256 << 20
	parent := os.Getenv("AGENTOS_CGROUP_PARENT")
	if os.Geteuid() != 0 || parent == "" {
		t.Skip("needs root and AGENTOS_CGROUP_PARENT (CI machines job)")
	}
	const broker = "/var/lib/agentos"
	for _, p := range []string{fuzzState, broker} {
		if _, err := os.Lstat(p); err == nil {
			t.Skipf("this host keeps %s", p)
		}
	}
	// The state is a directory below the file system's root, so the
	// untagged root shows the whole disk: statfs on a directory in a
	// project with inheritance reports the project's quota instead.
	q := quotatest.Dir(t, 2048)
	src := filepath.Join(q, "state")
	if err := os.Mkdir(src, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fuzzState, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(fuzzState) })
	if out, err := exec.Command("mount", "--bind", src, fuzzState).CombinedOutput(); err != nil {
		t.Fatalf("mount: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command("umount", fuzzState).Run() })
	if err := os.Chmod(fuzzState, 0o700); err != nil {
		t.Fatal(err)
	}
	roles := filepath.Join(broker, "modem", "roles.json")
	if err := os.Mkdir(broker, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(broker) })
	if os.Mkdir(filepath.Dir(roles), 0o755) != nil || os.WriteFile(roles, []byte(`{"canary":"loop7"}`), 0o644) != nil {
		t.Fatal("roles.json")
	}

	root := filepath.Join(parent, "agentosd-reach")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		leaf := &cgroup.Group{Path: filepath.Join(root, "fuzz")}
		leaf.Kill(ctx)
		leaf.Remove()
		os.Remove(root)
	})
	if _, err := cgroup.Open(root); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("", "agentosd-reach-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	release := filepath.Join(base, "release")
	if err := os.Chmod(base, 0o755); err != nil || os.Mkdir(release, 0o755) != nil {
		t.Fatal(err)
	}
	// The fuzz step tries each reach and writes what it got in its own
	// directory; what it measured is written after the fill is removed.
	// The fill bypasses the page cache, whose dirty pages the leaf's
	// memory.max would otherwise OOM-kill it for before the quota.
	probe := `case "$2" in -test.fuzz=*)
r=$PWD/reach
cat ` + roles + ` >/dev/null 2>&1 && echo "roles read" > $r || echo "roles denied" > $r
chattr -p 0 . >/dev/null 2>&1 && echo "retag done" >> $r || echo "retag $(chattr -p 0 . 2>&1 | grep -o 'Invalid argument' | head -n 1)" >> $r
f=$(dd if=/dev/zero of=big bs=1M count=384 oflag=direct 2>&1 >/dev/null; echo "exit $?")
f=$(echo "$f" | grep -v 'records\|copied' | tr '\n' ' ')
s=$(stat -c %s big)
rm -f big
echo "fill $f" >> $r
echo "size $s" >> $r;;
esac
exit 0`
	m := `{"targets":[{"pkg":"fake","name":"FuzzFake","binary":"fake.test"}]}`
	if os.WriteFile(filepath.Join(release, "manifest.json"), []byte(m), 0o644) != nil || os.WriteFile(filepath.Join(release, "fake.test"), []byte("#!/bin/sh\n"+probe+"\n"), 0o755) != nil {
		t.Fatal("release")
	}
	dir := t.TempDir()
	lp := openConfinedLearning(t, dir, learnPaths{Fuzz: release, Loop7: fuzzState, FuzzUser: "nobody", Cgroup: root, DiskQuota: "on", FuzzDiskBytes: testDisk})
	if lp.fuzz.Recheck() == fuzzEvery {
		t.Fatal("no fuzz targets wired")
	}
	if p, err := quota.Project(fuzzState); err != nil || p != fuzzProject {
		t.Fatalf("the fuzz state is in project %#x (%v), want %#x", p, err, fuzzProject)
	}

	ctx := context.Background()
	if _, err := lp.guard.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	j, ok := lp.fuzz.Next(ctx, false)
	if ok && j.Name == "probe:corpus" {
		if r := j.Run(ctx); r.Err != nil {
			t.Fatal(r.Err)
		}
		j, ok = lp.fuzz.Next(ctx, false)
	}
	if !ok || j.Name != "fuzz" {
		t.Fatalf("job %+v %v", j, ok)
	}
	if r := j.Run(ctx); r.Err != nil {
		t.Fatal(r.Err)
	}
	b, err := os.ReadFile(filepath.Join(fuzzState, "targets", "fake", "reach"))
	if err != nil {
		t.Fatalf("the fuzz step did not run: %v", err)
	}
	said := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(l, " ")
		said[k] = v
	}
	if said["roles"] != "denied" {
		t.Errorf("a fuzz child read the broker's roles.json: %q", b)
	}
	// EINVAL: the kernel refuses a project change from outside the
	// initial user namespace (fs/ioctl.c fileattr_set_prepare).
	if said["retag"] != "Invalid argument" {
		t.Errorf("a fuzz child moved its tree out of its quota project: %q", b)
	}
	// dd reports the write the quota refused and exits non-zero:
	// EDQUOT on ext4, ENOSPC on XFS.
	if f := said["fill"]; strings.Contains(f, "exit 0") || !strings.Contains(f, "Disk quota exceeded") && !strings.Contains(f, "No space left on device") {
		t.Errorf("a fill past the quota was not stopped by it: %q", b)
	}
	if n, err := strconv.ParseInt(said["size"], 10, 64); err != nil || n > testDisk {
		t.Errorf("a fuzz child wrote %s bytes past a %d byte quota", said["size"], int64(testDisk))
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(q, &st); err != nil || int64(st.Bavail)*st.Bsize < 1<<30 {
		t.Errorf("the disk around the fuzz tree was filled: %d bytes free (%v)", int64(st.Bavail)*st.Bsize, err)
	}
}
