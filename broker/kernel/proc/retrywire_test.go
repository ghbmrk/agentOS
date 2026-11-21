package proc

// REQ: KRN-7

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

// agentosd's RETRY decodes into the kernel's own retryArgs, field for field,
// so the kernel retries the plan, step and attempt the owner approved and no
// other (#2783 b). The oracle is the kernel's type, not a copy of it: a tag
// renamed on either side is an unknown field here (KEY-9-reach-inbound-offset
// Security fix-list 1, #6305). As is this test's own uid, so it needs no root.
func TestRetrySendsTheKernelsOwnCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	lines := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		l, _ := bufio.NewReader(c).ReadBytes('\n')
		lines <- l
		c.Write([]byte("{\"result\":null}\n"))
	}()
	o := kernelsock.Owner{Socket: path, UID: os.Getuid(), As: os.Getuid()}
	if err := o.Retry(context.Background(), "plan:7", 2, 3); err != nil {
		t.Fatal(err)
	}
	var call kernelCall
	if err := json.Unmarshal(<-lines, &call); err != nil || call.Op != "retry" {
		t.Fatalf("call %+v %v, want op retry", call, err)
	}
	var a retryArgs
	d := json.NewDecoder(bytes.NewReader(call.Args))
	d.DisallowUnknownFields()
	if err := d.Decode(&a); err != nil {
		t.Fatalf("RETRY's args %s do not decode as the kernel's retryArgs: %v", call.Args, err)
	}
	if a != (retryArgs{Plan: "plan:7", Index: 2, Attempt: 3}) {
		t.Fatalf("the kernel reads RETRY as %+v, want plan:7 step 2 attempt 3", a)
	}
}
