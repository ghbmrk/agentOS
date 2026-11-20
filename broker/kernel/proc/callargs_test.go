package proc

// REQ: CLK-1

import (
	"bufio"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Args json cannot marshal refuse the call before any connection, never
// sent as null args the kernel would act on (#6268, CLK-1 fail closed); no
// args send an empty object.
func TestAKernelCallWithArgsThatCannotMarshalIsRefused(t *testing.T) {
	sock := filepath.Join(shortDir(t), "args.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lines := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadString('\n')
			lines <- line
			c.Write([]byte("{}\n"))
			c.Close()
		}
	}()
	c := Conn{Socket: sock, UID: os.Getuid(), Timeout: 5 * time.Second}
	var ute *json.UnsupportedValueError
	if err := c.Call("stop", struct{ F float64 }{math.NaN()}, nil); !errors.As(err, &ute) {
		t.Fatalf("a call with NaN args: %v, want json's refusal", err)
	}
	if err := c.Call("stop", nil, nil); err != nil {
		t.Fatalf("a call with no args: %v", err)
	}
	if got := <-lines; got != `{"op":"stop","args":{}}`+"\n" {
		t.Fatalf("the only line sent is %q, want the no-args call", got)
	}
	select {
	case got := <-lines:
		t.Fatalf("a second line was sent: %q", got)
	default:
	}
}
