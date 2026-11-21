package main

// The harness's own checks on the board (row #6452, CAM-e2e-harness-fu): a panic is not a
// restart, every handle goes after QEMU quits, the mailbox lies in the guest's RAM, the tryboot
// command is the node's own, and the QMP socket is private. Run from broker/ as camnode-image.yml
// does: go test ../image/camnode/e2e/driver/*.go

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeQEMU is the QEMU end of a QMP connection: it greets, answers every command, writes word
// to pmemsave's file, and emits SHUTDOWN with reason once the client has negotiated. closed is
// closed when the harness closes its end.
type fakeQEMU struct {
	cmds   chan string
	closed chan struct{}
}

func startFake(t *testing.T, reason string, word uint32) (*vm, *fakeQEMU) {
	t.Helper()
	ours, theirs := net.Pipe()
	f := &fakeQEMU{cmds: make(chan string, 16), closed: make(chan struct{})}
	go func() {
		defer close(f.closed)
		enc := json.NewEncoder(theirs)
		enc.Encode(map[string]any{"QMP": map[string]any{}})
		dec := json.NewDecoder(bufio.NewReader(theirs))
		for {
			var c struct {
				Execute   string
				Arguments map[string]any
			}
			// The decoder fails only when the harness closes its end (net.Pipe: io.EOF).
			if dec.Decode(&c) != nil {
				return
			}
			f.cmds <- c.Execute
			if c.Execute == "pmemsave" {
				var p [4]byte
				binary.LittleEndian.PutUint32(p[:], word)
				os.WriteFile(c.Arguments["filename"].(string), p[:], 0o600)
			}
			enc.Encode(map[string]any{"return": map[string]any{}})
			if c.Execute == "qmp_capabilities" && reason != "" {
				enc.Encode(map[string]any{"event": "SHUTDOWN", "data": map[string]any{"guest": true, "reason": reason}})
			}
		}
	}()
	q, err := newQMP(ours)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	v := &vm{cmd: cmd, dir: t.TempDir(), qmp: q, done: make(chan error, 1)}
	go func() { v.done <- cmd.Wait() }()
	return v, f
}

func (f *fakeQEMU) seen() []string {
	var out []string
	for {
		select {
		case c := <-f.cmds:
			out = append(out, c)
		default:
			return out
		}
	}
}

// Row #6452 item 1.
// A panic stops the board with QEMU's reason guest-panic: stopped reports errPanic, never a
// restart, so the bad update's trial (test_update_rollback) cannot take a panic for its failure.
// A reset with an empty mailbox is still a plain restart.
func TestStoppedPanicIsNotARestart(t *testing.T) {
	v, _ := startFake(t, "guest-panic", 0)
	b := &board{}
	restart, err := v.stopped(b, 5*time.Second)
	if !errors.Is(err, errPanic) || restart != "" || b.tryboot {
		t.Fatalf("panic: restart %q, tryboot %v, err %v; want errPanic", restart, b.tryboot, err)
	}

	v, _ = startFake(t, "guest-reset", 0)
	if restart, err := v.stopped(b, 5*time.Second); err != nil || restart != "" || b.tryboot {
		t.Fatalf("plain reset: restart %q, tryboot %v, err %v", restart, b.tryboot, err)
	}
	v, _ = startFake(t, "guest-reset", 1)
	if restart, err := v.stopped(b, 5*time.Second); err != nil || restart != "0 tryboot" || !b.tryboot {
		t.Fatalf("tryboot reset: restart %q, tryboot %v, err %v", restart, b.tryboot, err)
	}
	v, _ = startFake(t, "guest-shutdown", 0)
	if _, err := v.stopped(b, 5*time.Second); err == nil || errors.Is(err, errPanic) {
		t.Fatalf("power-off: err %v, want a non-panic failure", err)
	}
}

// Row #6452 item 1.
// The board runs with the pvpanic device and QEMU stops it on a panic with a reason.
func TestQemuArgsPanicDevice(t *testing.T) {
	a := strings.Join((&board{}).qemuArgs(false), " ")
	if !strings.Contains(a, "-device pvpanic-pci") {
		t.Fatalf("no pvpanic-pci device in %s", a)
	}
}

// Row #6452 item 2.
// After QEMU quits, on the restart path and on the failure paths, the harness closes its QMP
// connection: the fake QEMU sees its peer go.
func TestStoppedClosesHandles(t *testing.T) {
	for _, tc := range []struct {
		reason string
		word   uint32
	}{{"guest-reset", 1}, {"guest-reset", 0}, {"guest-panic", 0}, {"guest-shutdown", 0}, {"guest-reset", 7}} {
		v, f := startFake(t, tc.reason, tc.word)
		v.stopped(&board{}, 5*time.Second)
		select {
		case <-f.closed:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s word %d: the QMP connection is still open after stopped", tc.reason, tc.word)
		}
		if !slices.Contains(f.seen(), "quit") {
			t.Fatalf("%s word %d: QEMU was not told to quit", tc.reason, tc.word)
		}
		select {
		case <-v.done:
		default:
			t.Fatalf("%s word %d: QEMU's exit was not collected", tc.reason, tc.word)
		}
	}
}

// Row #6452 item 3.
// The mailbox page must lie inside the RAM the /memory node QEMU writes describes.
func TestMailboxInsideMemory(t *testing.T) {
	cell := func(v uint64) string {
		return strconv.FormatUint(v>>32, 16) + " " + strconv.FormatUint(v&0xffffffff, 16)
	}
	for _, tc := range []struct {
		reg string
		ok  bool
	}{
		{cell(ramBase) + " " + cell(ramSize) + "\n", true},                               // the board's 1 GiB
		{cell(ramBase) + " " + cell(ramSize-0x1000), false},                              // the page past the end
		{cell(ramBase) + " " + cell(ramSize-0x800), false},                               // half the page
		{cell(ramBase+0x1000) + " " + cell(ramSize), true},                               // shifted, still covers
		{cell(mailbox+0x1000) + " " + cell(ramSize), false},                              // starts after it
		{cell(0) + " " + cell(0x1000) + " " + cell(ramBase) + " " + cell(ramSize), true}, // second range
		{"", false},
		{"0 40000000 0", false},
		{"0 4000000z 0 40000000", false},
	} {
		if err := inMemory(tc.reg); (err == nil) != tc.ok {
			t.Errorf("inMemory(%q) = %v, want ok %v", tc.reg, err, tc.ok)
		}
	}
}

// Row #6452 item 4.
// restartCmds' tryboot word carries the string agentos-camnode's reboot passes to the kernel
// (sys_linux.go), read from that file: if one changes without the other, this fails.
func TestRestartCmdsMatchNode(t *testing.T) {
	src := filepath.Join("..", "..", "..", "..", "broker", "cmd", "agentos-camnode", "sys_linux.go")
	file, err := parser.ParseFile(token.NewFileSet(), src, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "reboot" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "BytePtrFromString" || len(call.Args) != 1 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Fatalf("reboot's argument is not a string literal")
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			args = append(args, s)
			return true
		})
		return false
	})
	if len(args) != 1 {
		t.Fatalf("found %d restart arguments in %s's reboot, want 1", len(args), src)
	}
	if restartCmds[1] != args[0] {
		t.Fatalf("restartCmds[1] = %q, agentos-camnode's reboot passes %q", restartCmds[1], args[0])
	}
}

// Row #6452 item 5.
// The QMP socket sits in a directory only the harness's user can enter, and closing the
// listener removes it.
func TestQMPSocketPrivate(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o777)
	ln, err := qmpListen(dir)
	if err != nil {
		t.Fatal(err)
	}
	sock := ln.Addr().String()
	fi, err := os.Lstat(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 || filepath.Dir(filepath.Dir(sock)) != dir {
		t.Fatalf("socket %s in a directory with mode %v", sock, fi.Mode())
	}
	if c, err := net.Dial("unix", sock); err != nil {
		t.Fatalf("the harness's own user cannot connect: %v", err)
	} else {
		c.Close()
	}
	ln.Close()
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket left after close: %v", err)
	}
}
