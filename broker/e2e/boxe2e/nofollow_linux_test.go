package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

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

	// A create or truncate follows no link at the name, so nothing outside
	// is made or emptied before the check.
	if err := os.Symlink(filepath.Join(other, "made"), filepath.Join(mine, "dangle")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(plain, filepath.Join(mine, "tlink")); err != nil {
		t.Fatal(err)
	}
	if fd, err := openRaw(filepath.Join(mine, "dangle"), unix.O_WRONLY|unix.O_CREAT, 0o600); err == nil {
		unix.Close(fd)
		t.Error("openRaw created through a dangling link")
	}
	if fd, err := openRaw(filepath.Join(mine, "tlink"), unix.O_WRONLY|unix.O_TRUNC, 0); err == nil {
		unix.Close(fd)
		t.Error("openRaw truncated through a link")
	}
	if _, err := os.Lstat(filepath.Join(other, "made")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a create through a link made the target: %v", err)
	}
	if got, _ := os.ReadFile(plain); string(got) != "x" {
		t.Errorf("a truncate through a link emptied the target: %q", got)
	}

	// Only /dev/ptmx, directories read-only and regular files off procfs
	// and sysfs are opened: no device's raw contents, no process memory.
	for _, c := range []struct {
		path string
		flag int
	}{
		{"/dev/null", unix.O_WRONLY},
		{"/dev/zero", unix.O_RDONLY},
		{"/proc/self/mem", unix.O_RDONLY},
		{"/proc/self/environ", unix.O_RDONLY},
		{"/sys/kernel/uevent_seqnum", unix.O_RDONLY},
	} {
		// Each path exists on every Linux, so a missing one fails too.
		if fd, err := openRaw(c.path, c.flag, 0); !errors.Is(err, errKind) {
			if err == nil {
				unix.Close(fd)
			}
			t.Errorf("openRaw(%q) = %v, want it refused as a kind", c.path, err)
		}
	}
	fifo := filepath.Join(mine, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if fd, err := openRaw(fifo, unix.O_RDONLY|unix.O_NONBLOCK, 0); !errors.Is(err, errKind) {
		if err == nil {
			unix.Close(fd)
		}
		t.Errorf("openRaw(a FIFO) = %v, want it refused as a kind", err)
	}
	fd, err = openRaw("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Errorf("openRaw(/dev/ptmx) = %v", err)
	} else {
		if fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil || fl&unix.FD_CLOEXEC == 0 {
			t.Errorf("openRaw's descriptor is not close-on-exec: %#x, %v", fl, err)
		}
		unix.Close(fd)
	}
	if fd, err := openRaw(mine, unix.O_RDONLY|unix.O_DIRECTORY, 0); err != nil {
		t.Errorf("a directory read: %v", err)
	} else {
		unix.Close(fd)
	}
}

// REQ: HW-10, ONB-3. writeDirs hold their own trees only, not a sibling
// whose name starts the same, and writeFiles are those files only.
func TestFileGateWritesOnlyItsOwnPlaces(t *testing.T) {
	if mayWrite("/run/agentos-e2e-x/ip") || mayWrite("/run/agentos-e2e") || !mayWrite("/run/agentos-e2e/claim-code") {
		t.Error("mayWrite does not hold writeDirs to their own trees")
	}
	dir := t.TempDir()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := writeFiles
	writeFiles = append(append([]string{}, old...), filepath.Join(real, "drop-in.conf"))
	t.Cleanup(func() { writeFiles = old })
	if err := writeNoFollow(filepath.Join(dir, "drop-in.conf"), []byte("[Service]\n"), 0o644); err != nil {
		t.Errorf("a write of a writeFiles file: %v", err)
	}
	if err := writeNoFollow(filepath.Join(dir, "drop-in.conf.d"), nil, 0o644); !errors.Is(err, errWrite) {
		t.Errorf("a write beside a writeFiles file = %v, want it refused", err)
	}
}

// REQ: HW-10, ONB-3. The gate decides before an open acts (#4634, #4213): a
// FIFO opened to block is refused at once, a write to a file with another
// name (a hard link, whose other name may be outside writeDirs) is refused
// before it truncates, a trailing slash names the directory itself and
// not a name inside it, and the kernel's own filesystems (debugfs,
// tracefs, securityfs and the rest) are refused as procfs and sysfs are.
func TestFileGateChecksBeforeTheOpenActs(t *testing.T) {
	mine, other := t.TempDir(), t.TempDir()
	writeHere(t, mine)

	fifo := filepath.Join(mine, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(mine)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for name, open := range map[string]func() error{
		"openRaw": func() error {
			fd, err := openRaw(fifo, unix.O_RDONLY, 0)
			if err == nil {
				unix.Close(fd)
			}
			return err
		},
		"writeNoFollow": func() error { return writeNoFollow(fifo, nil, 0o600) },
		// readNoFollow is the read #4213 found blocking (agentos-localui
		// could leave a FIFO at its card latch); rootOpen is
		// workerOutFile's open, which a guest could race to a FIFO.
		"readNoFollow": func() error { _, err := readNoFollow(fifo); return err },
		"rootOpen": func() error {
			f, err := rootOpen(r, "fifo")
			if err == nil {
				f.Close()
			}
			return err
		},
	} {
		done := make(chan error, 1)
		go func() { done <- open() }()
		select {
		case err := <-done:
			if !errors.Is(err, errKind) {
				t.Errorf("%s(a FIFO, blocking) = %v, want it refused as a kind", name, err)
			}
		case <-time.After(5 * time.Second):
			// Open the other end so the blocked open returns.
			if fd, err := unix.Open(fifo, unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil {
				defer unix.Close(fd)
			}
			t.Errorf("%s(a FIFO, blocking) waited on the FIFO before the check", name)
		}
	}

	outside := filepath.Join(other, "unit.service")
	if err := os.WriteFile(outside, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(mine, "hard")
	if err := os.Link(outside, hard); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []int{unix.O_WRONLY, unix.O_RDWR, unix.O_WRONLY | unix.O_TRUNC, unix.O_RDONLY | unix.O_TRUNC, unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC} {
		if fd, err := openRaw(hard, flag, 0o600); !errors.Is(err, errWrite) {
			if err == nil {
				unix.Close(fd)
			}
			t.Errorf("openRaw(a hard link to a file outside, %#x) = %v, want the write refused", flag, err)
		}
	}
	if err := writeNoFollow(hard, []byte("PLANTED"), 0o600); !errors.Is(err, errWrite) {
		t.Errorf("writeNoFollow(a hard link to a file outside) = %v, want the write refused", err)
	}
	if got, _ := os.ReadFile(outside); string(got) != "ORIGINAL" {
		t.Errorf("a refused write through a hard link changed the file outside: %q", got)
	}
	if b, err := readNoFollow(hard); err != nil || string(b) != "ORIGINAL" {
		t.Errorf("a read of a hard-linked file: %q, %v", b, err)
	}

	sub := filepath.Join(mine, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{sub + "/", sub + "//", mine + "/"} {
		if fd, err := openRaw(p, unix.O_WRONLY|unix.O_CREAT, 0o600); err == nil {
			unix.Close(fd)
			t.Errorf("openRaw(%q, O_CREAT) opened something", p)
		}
		if err := symlink("x", p); err == nil {
			t.Errorf("symlink(%q) made a link", p)
		}
	}
	for _, p := range []string{filepath.Join(sub, "sub"), filepath.Join(mine, filepath.Base(mine))} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a trailing slash made %q: %v", p, err)
		}
	}

	link := filepath.Join(mine, "link")
	if err := os.Symlink(filepath.Join(mine, "hard"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := readNoFollow(link); !errors.Is(err, unix.ELOOP) {
		t.Errorf("readNoFollow(a link) = %v, want ELOOP", err)
	}

	// A network namespace (nsfs, as nsDialer opens /run/netns/<ns>) is
	// one of fileFS, and reopens through its O_PATH descriptor.
	if fd, err := openRaw("/proc/self/ns/net", unix.O_RDONLY, 0); err != nil {
		t.Errorf("openRaw(a netns) = %v", err)
	} else {
		unix.Close(fd)
	}

	for name, magic := range map[string]int64{
		"procfs": unix.PROC_SUPER_MAGIC, "sysfs": unix.SYSFS_MAGIC, "debugfs": unix.DEBUGFS_MAGIC,
		"tracefs": unix.TRACEFS_MAGIC, "securityfs": unix.SECURITYFS_MAGIC, "configfs": 0x62656570,
		"efivarfs": unix.EFIVARFS_MAGIC, "cgroupfs": unix.CGROUP_SUPER_MAGIC, "cgroup2": unix.CGROUP2_SUPER_MAGIC,
		"bpffs": unix.BPF_FS_MAGIC, "pstore": unix.PSTOREFS_MAGIC, "selinuxfs": unix.SELINUX_MAGIC,
		"binfmt_misc": unix.BINFMTFS_MAGIC, "rpc_pipefs": 0x67596969, "fusectl": 0x65735543,
		"mqueue": 0x19800202, "hugetlbfs": unix.HUGETLBFS_MAGIC, "resctrl": unix.RDTGROUP_SUPER_MAGIC,
		"devpts": unix.DEVPTS_SUPER_MAGIC, "fuse": 0x65735546,
	} {
		if fileFS[magic] {
			t.Errorf("fileFS holds %s, a kernel filesystem", name)
		}
	}
	// Where this host mounts one, a regular file on it is refused when
	// opened.
	for _, p := range []string{
		"/sys/kernel/security/lsm", "/sys/kernel/tracing/trace", "/sys/kernel/debug/tracing/trace",
		"/sys/fs/cgroup/cgroup.controllers", "/sys/fs/cgroup/cpu/tasks", "/proc/sys/fs/binfmt_misc/status",
		"/sys/fs/selinux/enforce", "/sys/fs/resctrl/schemata",
	} {
		var fs unix.Statfs_t
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() || unix.Statfs(p, &fs) != nil {
			continue
		}
		if fd, err := openRaw(p, unix.O_RDONLY, 0); !errors.Is(err, errKind) {
			if err == nil {
				unix.Close(fd)
			}
			t.Errorf("openRaw(%q) = %v, want it refused as a kind", p, err)
		}
	}
}

// openFDs counts this process's open descriptors.
func openFDs(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// REQ: HW-10, ONB-3. The gate's own steps hold: a missing name is the
// kernel's ENOENT and a create the kernel refuses its own error, not a
// descriptor taken as opened; a link reached at the name is ELOOP; and no
// open, refused or not, leaves a descriptor behind (#4634).
func TestFileGateStepsLeaveNothingOpen(t *testing.T) {
	mine := t.TempDir()
	writeHere(t, mine)
	if err := os.WriteFile(filepath.Join(mine, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(mine, "l")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(mine, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mine, "j"), []byte(journalMagic), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mine, "d"), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		path string
		flag int
	}{
		{filepath.Join(mine, "missing"), unix.O_RDONLY},
		{filepath.Join(mine, "missing"), unix.O_WRONLY | unix.O_TRUNC},
	} {
		if fd, err := openRaw(c.path, c.flag, 0); !errors.Is(err, unix.ENOENT) {
			if err == nil {
				unix.Close(fd)
			}
			t.Errorf("openRaw(%q, %#x) = %v, want ENOENT", c.path, c.flag, err)
		}
	}
	// The kernel refuses a directory opened for writing at the reopen.
	if fd, err := openRaw(filepath.Join(mine, "d"), unix.O_WRONLY, 0); !errors.Is(err, unix.EISDIR) {
		if err == nil {
			unix.Close(fd)
		}
		t.Errorf("openRaw(a directory, O_WRONLY) = %v, want EISDIR", err)
	}
	// sysfs makes no file on create; let the gate write there for this
	// one case so the kernel, not inDir, refuses it.
	writeHere(t, "/sys/kernel")
	if fd, err := openRaw("/sys/kernel/zz-gate-probe", unix.O_WRONLY|unix.O_CREAT, 0o600); !errors.Is(err, unix.EACCES) {
		if err == nil {
			unix.Close(fd)
		}
		t.Errorf("openRaw(a create sysfs refuses) = %v, want EACCES", err)
	}

	pfd, err := unix.Open(filepath.Join(mine, "l"), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkFD(pfd, false); !errors.Is(err, unix.ELOOP) {
		t.Errorf("checkFD(a link) = %v, want ELOOP", err)
	}
	unix.Close(pfd)

	r, err := os.OpenRoot(mine)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := rootOpen(r, "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("rootOpen(a missing name) = %v, want it not found", err)
	}
	try := func() {
		for _, c := range []struct {
			name string
			flag int
		}{
			{"f", unix.O_RDONLY}, {"f", unix.O_WRONLY}, {"l", unix.O_RDONLY | unix.O_NOFOLLOW},
			{"missing", unix.O_RDONLY}, {"fifo", unix.O_RDONLY}, {"f", unix.O_WRONLY | unix.O_TRUNC},
			{"new", unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC}, {"missing", unix.O_WRONLY | unix.O_TRUNC},
			{"j", unix.O_RDONLY}, {"d", unix.O_WRONLY}, {"d", unix.O_RDONLY},
		} {
			if fd, err := openRaw(filepath.Join(mine, c.name), c.flag, 0o600); err == nil {
				unix.Close(fd)
			}
			if f, err := rootOpen(r, c.name); err == nil {
				f.Close()
			}
		}
	}
	try() // the runtime's own descriptors settle on the first pass
	before := openFDs(t)
	for range 10 {
		try()
	}
	if after := openFDs(t); after != before {
		t.Errorf("the gate left descriptors open: %d before, %d after", before, after)
	}
}

// REQ: HW-10, ONB-3. A write is decided on the path this process's mount
// namespace gives the file, not on the text /proc gives it, which is the
// path in the file's own namespace (#4713): a thread in its own mount
// namespace bind-mounts a directory outside writeDirs onto one inside,
// and a write through /proc/<pid>/task/<tid>/root to that writeDir is
// refused and lands nowhere.
func TestFileGateWritesOnlyWhereThisNamespaceSays(t *testing.T) {
	wd, self, outside := t.TempDir(), t.TempDir(), t.TempDir()
	writeHere(t, wd)
	writeHere(t, self)
	real, err := filepath.EvalSymlinks(wd)
	if err != nil {
		t.Fatal(err)
	}
	realSelf, err := filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}

	type ns struct {
		tid int
		err error
	}
	ready, done := make(chan ns), make(chan struct{})
	go func() {
		// The thread stays locked and exits with the goroutine, so its
		// namespace goes with it and no other goroutine runs there.
		runtime.LockOSThread()
		err := unix.Unshare(unix.CLONE_NEWNS)
		if err == nil {
			err = unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "")
		}
		if err == nil {
			err = unix.Mount(outside, real, "", unix.MS_BIND, "")
		}
		// self bound onto itself: the same inode on another mount, so
		// only the mount ID tells the two apart.
		if err == nil {
			err = unix.Mount(realSelf, realSelf, "", unix.MS_BIND, "")
		}
		ready <- ns{unix.Gettid(), err}
		<-done
	}()
	n := <-ready
	defer close(done)
	if errors.Is(n.err, unix.EPERM) {
		t.Skipf("making a mount namespace needs CAP_SYS_ADMIN, which this run lacks: %v", n.err)
	}
	if n.err != nil {
		t.Fatalf("making the mount namespace: %v", n.err)
	}

	via := fmt.Sprintf("/proc/%d/task/%d/root%s", os.Getpid(), n.tid, real)
	if err := writeNoFollow(filepath.Join(via, "evil"), []byte("PLANTED"), 0o600); !errors.Is(err, errWrite) {
		t.Errorf("a write through another mount namespace = %v, want the write refused", err)
	}
	if err := symlink("x", filepath.Join(via, "evil-link")); !errors.Is(err, errWrite) {
		t.Errorf("a link through another mount namespace = %v, want it refused", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "there"), []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fd, err := openRaw(filepath.Join(via, "there"), unix.O_WRONLY, 0); !errors.Is(err, errWrite) {
		if err == nil {
			unix.Close(fd)
		}
		t.Errorf("an existing file opened for writing through another mount namespace = %v, want the write refused", err)
	}
	for _, name := range []string{"evil", "evil-link"} {
		if _, err := os.Lstat(filepath.Join(outside, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a refused write made %s outside writeDirs: %v", name, err)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(outside, "there")); string(got) != "ORIGINAL" {
		t.Errorf("a refused write changed the file outside: %q", got)
	}
	// A directory bound onto itself there has the inode it has here, and
	// is still another mount.
	viaSelf := fmt.Sprintf("/proc/%d/task/%d/root%s", os.Getpid(), n.tid, realSelf)
	if err := writeNoFollow(filepath.Join(viaSelf, "evil"), []byte("PLANTED"), 0o600); !errors.Is(err, errWrite) {
		t.Errorf("a write through another namespace's mount of the same directory = %v, want the write refused", err)
	}
	if _, err := os.Lstat(filepath.Join(self, "evil")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused write through another mount made a file: %v", err)
	}
	// The same writeDir, named in this namespace, is still written.
	if err := writeNoFollow(filepath.Join(wd, "ok"), []byte("ok"), 0o600); err != nil {
		t.Errorf("a write in this namespace: %v", err)
	}
}

// REQ: HW-10, ONB-3. fdPath gives a path only when this namespace's
// lookup of it reaches the same file (#4713), which an unprivileged run
// can check too: a file whose name is gone (the /proc text then reads
// "... (deleted)") and a descriptor that is not open each give errWrite,
// never the text.
func TestFdPathNamesOnlyTheFileItself(t *testing.T) {
	mine := t.TempDir()
	writeHere(t, mine)
	p := filepath.Join(mine, "f")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if real, err := fdPath(fd); err != nil || filepath.Base(real) != "f" {
		t.Errorf("fdPath(a named file) = %q, %v", real, err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if real, err := fdPath(fd); !errors.Is(err, errWrite) {
		t.Errorf("fdPath(a file whose name is gone) = %q, %v, want errWrite", real, err)
	}
	// A file named as the /proc text reads is another inode on the same
	// mount, so the inode, not the lookup, refuses it.
	if err := os.WriteFile(p+" (deleted)", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if real, err := fdPath(fd); !errors.Is(err, errWrite) {
		t.Errorf("fdPath(a gone file beside one named %q) = %q, %v, want errWrite", "f (deleted)", real, err)
	}
	if real, err := fdPath(-1); !errors.Is(err, errWrite) {
		t.Errorf("fdPath(no descriptor) = %q, %v, want errWrite", real, err)
	}
}

// REQ: HW-10, ONB-3. tmpfs's code also backs mounts no namespace names
// (#4877): a memfd, reached through /proc/<pid>/fd, is a process's memory
// and not a file, so the gate refuses it however its descriptor is
// named, as it does a tmpfs file whose name is gone, while a tmpfs file
// this namespace names still opens.
func TestFileGateRefusesMemfd(t *testing.T) {
	fd, err := unix.MemfdCreate("fu8-canary", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatalf("memfd_create: %v", err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte("memfd-canary-77c1")); err != nil {
		t.Fatal(err)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Fatalf("a memfd's filesystem = %#x, %v, want tmpfs, the case the gate must refuse", fs.Type, err)
	}
	for _, p := range []string{
		"/proc/self/fd/" + strconv.Itoa(fd),
		fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd),
		fmt.Sprintf("/proc/%d/task/%d/fd/%d", os.Getpid(), unix.Gettid(), fd),
	} {
		refusedAsShmem(t, p)
	}
	refusedAsShmem(t, "/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDWR)

	// A named tmpfs file opens; once its name is gone, the same
	// descriptor's /proc link is refused like a memfd's.
	shm := "/dev/shm"
	if err := unix.Statfs(shm, &fs); err != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Skipf("%s is not tmpfs here (%v), so the named-file half has no tmpfs to use", shm, err)
	}
	dir, err := os.MkdirTemp(shm, "fu8-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "named")
	if err := os.WriteFile(p, []byte("named"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readNoFollow(p); err != nil || string(b) != "named" {
		t.Errorf("readNoFollow(a named tmpfs file) = %q, %v", b, err)
	}
	held, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(held)
	if fd, err := openRaw("/proc/self/fd/"+strconv.Itoa(held), unix.O_RDONLY, 0); err != nil {
		t.Errorf("openRaw(the /proc link of a named tmpfs file) = %v", err)
	} else {
		unix.Close(fd)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	refusedAsShmem(t, "/proc/self/fd/"+strconv.Itoa(held))
}

// REQ: HW-10, ONB-3. A SysV shm segment, and a shared anonymous mapping,
// are memory on the same unnamed shmem mount as a memfd (#4877). No
// descriptor holds them, so /proc/<pid>/map_files reaches them, which
// only a run with CAP_SYS_ADMIN (or CAP_CHECKPOINT_RESTORE) may open,
// such as the box's harness or a reviewer's run as root; a run without
// it skips, as CI does.
func TestFileGateRefusesSysVShm(t *testing.T) {
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, 4096, unix.IPC_CREAT|0o600)
	if err != nil {
		t.Fatalf("shmget: %v", err)
	}
	defer unix.SysvShmCtl(id, unix.IPC_RMID, nil)
	seg, err := unix.SysvShmAttach(id, 0, 0)
	if err != nil {
		t.Fatalf("shmat: %v", err)
	}
	defer unix.SysvShmDetach(seg)
	copy(seg, "sysv-canary-2be9")
	anon, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(anon)

	// A SysV segment's inode number is its shmid; a shared anonymous
	// mapping reads /dev/zero (deleted), and any one of them will do.
	b, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	var sysv, zero string
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		switch {
		case strings.HasPrefix(f[5], "/SYSV") && f[4] == strconv.Itoa(id):
			sysv = f[0]
		case f[5] == "/dev/zero" && strings.HasPrefix(f[1], "rw-s"):
			zero = f[0]
		}
	}
	if sysv == "" || zero == "" {
		t.Fatalf("/proc/self/maps lists the segment at %q and the shared mapping at %q, want both", sysv, zero)
	}
	probe, err := unix.Open("/proc/self/map_files/"+sysv, unix.O_PATH|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOENT) {
		t.Skipf("opening /proc/self/map_files needs CAP_SYS_ADMIN or CAP_CHECKPOINT_RESTORE, which this run lacks: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(probe)
	refusedAsShmem(t, "/proc/self/map_files/"+sysv)
	refusedAsShmem(t, fmt.Sprintf("/proc/%d/map_files/%s", os.Getpid(), sysv), unix.O_RDWR)
	refusedAsShmem(t, "/proc/self/map_files/"+zero)
}

// refusedAsShmem fails t unless openRaw refuses p, opened with flag
// (read-only if none), as kernel-held memory.
func refusedAsShmem(t *testing.T, p string, flag ...int) {
	t.Helper()
	f := unix.O_RDONLY
	if len(flag) > 0 {
		f = flag[0]
	}
	fd, err := openRaw(p, f, 0)
	if err == nil {
		unix.Close(fd)
	}
	if !errors.Is(err, errShmem) {
		t.Errorf("openRaw(%q, %#x) = %v, want it refused as kernel-held memory", p, f, err)
	}
}
