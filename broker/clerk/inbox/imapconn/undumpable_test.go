package imapconn

// REQ: CLK-1, A5

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

// After Undumpable the process reads as not dumpable, and the connection
// process's main calls it before it touches the session's descriptor.
func TestUndumpable(t *testing.T) {
	if err := Undumpable(); err != nil {
		t.Fatal(err)
	}
	v, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	if e != 0 || v != 0 {
		t.Fatalf("dumpable %d after Undumpable (%v)", v, e)
	}
	main, err := os.ReadFile("cmd/imapconn/main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(main)
	i, j := strings.Index(s, "imapconn.Undumpable()"), strings.Index(s, "os.NewFile(3,")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("main does not call Undumpable before it opens descriptor 3 (%d, %d)", i, j)
	}
}
