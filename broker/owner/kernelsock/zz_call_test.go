package kernelsock

// REQ: KRN-5

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// answering serves one call on a fresh socket under this process's uid and
// answers it with answer (nothing when ""). heard stops serving and gives
// the request line it read, or "" if no call came.
func answering(t *testing.T, answer string) (o Owner, heard func() string) {
	t.Helper()
	path := filepath.Join(runDir(t), "k.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			lines <- ""
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		if answer != "" {
			c.Write([]byte(answer + "\n"))
		}
		lines <- line
	}()
	return Owner{Socket: path, UID: os.Getuid(), As: os.Geteuid()}, func() string { ln.Close(); return <-lines }
}

// Each answer the kernel can give comes back as what it is: a refusal and
// an error as Refused in the kernel's words, a result into out, a result
// out cannot hold or no answer at all as ErrLost; a call whose arguments do
// not encode fails with the encoder's error and sends nothing (KRN-5).
func TestEachAnswerComesBackAsWhatItIs(t *testing.T) {
	ctx := context.Background()
	code := fmt.Sprint(key.RVerb)
	for _, tc := range []struct {
		name, answer string
		out          any
		want         error
	}{
		{"a refusal", `{"refusal":{"code":"` + code + `","detail":"not yours"}}`, nil, Refused{code + ": not yours"}},
		{"an error", `{"error":"log full"}`, nil, Refused{"log full"}},
		{"a result out cannot hold", `{"result":"text"}`, new(int), ErrLost},
		{"no answer", "", nil, ErrLost},
		{"a result", `{"result":7}`, new(int), nil},
		{"a result nobody reads", `{"result":"text"}`, nil, nil},
	} {
		o, heard := answering(t, tc.answer)
		err := o.call(ctx, "status", map[string]int{"n": 1}, tc.out)
		if !errors.Is(err, tc.want) && err != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
		if line := heard(); line != `{"op":"status","args":{"n":1}}`+"\n" {
			t.Errorf("%s: the kernel heard %q", tc.name, line)
		}
		if n, ok := tc.out.(*int); ok && tc.want == nil && *n != 7 {
			t.Errorf("%s: out holds %d, want 7", tc.name, *n)
		}
	}
	o, heard := answering(t, `{"result":1}`)
	var ute *json.UnsupportedTypeError
	if err := o.call(ctx, "status", make(chan int), nil); !errors.As(err, &ute) {
		t.Errorf("arguments that do not encode: %v, want the encoder's error", err)
	}
	if line := heard(); line != "" {
		t.Errorf("arguments that do not encode reached the kernel: %q", line)
	}
}

// A uid this process cannot take fails the call as unreachable, with the
// kernel's own reason for refusing setresuid, before anything is sent.
func TestAUIDThatCannotBeTakenSaysWhy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can take any uid")
	}
	o, heard := answering(t, `{"result":1}`)
	o.As = os.Geteuid() + 1
	err := o.call(context.Background(), "status", nil, nil)
	if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("an owner uid this process cannot take: %v, want unreachable because setresuid was not permitted", err)
	}
	if line := heard(); line != "" {
		t.Fatalf("the kernel heard %q", line)
	}
}
