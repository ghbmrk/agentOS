package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modelroute"
)

// REQ: ARC-2, CH-10, ONB-3, CRED-8

// A synthetic enrollment link: not a seed anyone holds.
const setupCanary = "otpauth://totp/AgentOS:AgentOS?secret=CANARYCANARYCANARY22&issuer=AgentOS"

// setupVault seals at finish what was confirmed since the last enroll
// (egress K17).
type setupVault struct{ pending, confirmed, sealed bool }

func (v *setupVault) Enroll() (string, error) {
	if v.sealed {
		return "", localsrv.EnrollClosed
	}
	v.pending, v.confirmed = true, false
	return setupCanary, nil
}

func (v *setupVault) ConfirmEnroll(code string) (bool, error) {
	if v.sealed {
		return false, localsrv.EnrollClosed
	}
	if !v.pending {
		return false, localsrv.EnrollNone
	}
	v.confirmed = code == "123456"
	v.pending = !v.confirmed
	return v.confirmed, nil
}

func (v *setupVault) SealEnroll() error {
	if v.sealed {
		return localsrv.EnrollClosed
	}
	if !v.confirmed || v.pending {
		return localsrv.EnrollNone
	}
	v.sealed = true
	return nil
}

func newSetupMode(t *testing.T) setupMode {
	t.Helper()
	dir, err := os.MkdirTemp("", "as")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	gid := os.Getgid()
	return setupMode{Dir: filepath.Join(dir, "run"), Page: &daemon.PageSocket{UID: os.Getuid(), GID: &gid},
		Record: localsrv.FileRecord{Path: filepath.Join(dir, "setup.json")}, OwnerState: filepath.Join(dir, "owner.json"),
		Enroll: &setupVault{}, Progress: setupProgress}
}

// Security L6: agentosd serves setup's ops on localui.sock until finish is
// recorded, then stops; the next start reads the owner from the record and
// serves no setup op.
func TestAgentosdServesSetupUntilFinishThenReadsTheRecord(t *testing.T) {
	m := newSetupMode(t)
	type result struct {
		owner string
		err   error
	}
	done := make(chan result, 1)
	go func() { o, err := m.run(context.Background()); done <- result{o, err} }()
	sock := filepath.Join(m.Dir, localapi.Socket)
	c := bridgeclient.Client{Path: sock}
	call := func(op string, args, out any) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return c.Call(ctx, op, args, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for call(localapi.OpSetupProgress, nil, nil) != nil {
		if time.Now().After(deadline) {
			t.Fatal("setup never served")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); err == nil || !strings.Contains(err.Error(), localapi.ErrNotEnrolled) {
		t.Fatalf("finish before enrollment: %v", err)
	}
	var l localapi.EnrollLink
	if err := call(localapi.OpSetupEnroll, nil, &l); err != nil || l.URI != setupCanary {
		t.Fatalf("enroll %v", err)
	}
	var ok localapi.Confirmed
	if err := call(localapi.OpSetupConfirm, localapi.Confirm{Code: "123456"}, &ok); err != nil || !ok.OK {
		t.Fatalf("confirm %v %v", err, ok)
	}
	// Finish's answer may race the socket closing; the record decides.
	call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil)
	select {
	case r := <-done:
		if r.err != nil || r.owner != "+15550100100" {
			t.Fatalf("run %q %v", r.owner, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setup did not end at finish")
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("localui.sock left serving setup: %v", err)
	}
	m.Enroll = nil // a restart needs no vault: the record names the owner
	if o, err := m.run(context.Background()); err != nil || o != "+15550100100" {
		t.Fatalf("restart %q %v", o, err)
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restart served setup")
	}
}

// Setup fails closed: an owned box with its record gone, an unreadable
// record, or no page to set it up refuses to start rather than serve
// setup.
func TestSetupModeFailsClosed(t *testing.T) {
	m := newSetupMode(t)
	if err := os.WriteFile(m.OwnerState, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.run(context.Background()); !errors.Is(err, errOwnedWithoutRecord) {
		t.Fatalf("owner state without a record: %v", err)
	}
	m = newSetupMode(t)
	if err := os.WriteFile(m.Record.(localsrv.FileRecord).Path, []byte(`{"finished":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.run(context.Background()); err == nil {
		t.Fatal("finished record without an owner accepted")
	}
	m = newSetupMode(t)
	m.Page = nil
	if _, err := m.run(context.Background()); err == nil {
		t.Fatal("setup without localui")
	}
	m = newSetupMode(t)
	m.Enroll = nil
	if _, err := m.run(context.Background()); err == nil {
		t.Fatal("setup without the vault")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, localapi.Socket)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("served setup while refusing to start")
	}
}

// K17: the vault's refusals reach setup as localsrv's sentinels; "never
// opened" stays apart from "sealed" (P2-2w c2 r1).
func TestTheVaultsEnrollRefusalsMap(t *testing.T) {
	for in, want := range map[error]error{
		modelroute.ErrEnrolled:                                 localsrv.EnrollClosed,
		modelroute.ErrEnrollNotOpen:                            localsrv.EnrollNotOpen,
		modelroute.ErrNoEnrollment:                             localsrv.EnrollNone,
		&modelroute.VerifyError{Kind: modelroute.VerifyPaused}: localsrv.EnrollPaused,
	} {
		if got := enrollErr(in); !errors.Is(got, want) {
			t.Errorf("%v: %v", in, got)
		}
	}
	for _, in := range []error{nil, modelroute.ErrVaultLocked} {
		if got := enrollErr(in); got != in {
			t.Errorf("%v: %v", in, got)
		}
	}
}
