package privfile

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

const ownerChild = "AGENTOS_PRIVFILE_OWNER_CHILD"

// OpenDir refuses a directory owned by a uid other than this one or root,
// since that uid can chmod it open. As root, a temporary directory is
// chowned to another uid; otherwise the test runs again in a user namespace
// that maps only this uid (as 0), where "/" is owned by the overflow uid.
func TestOpenDirRefusesADirOfAnotherUid(t *testing.T) {
	dir := "/"
	switch {
	case os.Getenv(ownerChild) != "":
	case os.Geteuid() == 0:
		dir = t.TempDir()
		if err := os.Chown(dir, 12345, 12345); err != nil {
			t.Fatal(err)
		}
	default:
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), ownerChild+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		out, err := cmd.CombinedOutput()
		t.Logf("in the child:\n%s", out)
		if err != nil && strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("no unprivileged user namespaces here")
		}
		if err != nil || !strings.Contains(string(out), "--- PASS: "+t.Name()) {
			t.Fatalf("child: %v", err)
		}
		return
	}
	d, r, err := OpenDir(dir)
	if err == nil {
		d.Close()
		r.Close()
		t.Fatalf("OpenDir opened %s, owned by another uid", dir)
	}
	if !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("OpenDir(%s) = %v; want the owner refusal", dir, err)
	}
}
