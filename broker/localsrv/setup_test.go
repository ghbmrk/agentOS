package localsrv

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ARC-2, ONB-3, ONB-6, CRED-8

// A synthetic enrollment link: not a seed anyone holds.
const canaryLink = "otpauth://totp/AgentOS:AgentOS?secret=CANARYCANARYCANARY22&issuer=AgentOS"

// fakeVault stands in for the vault process's enroll ops (egress K17).
type fakeVault struct {
	sealed   bool
	pending  bool
	enrolls  int
	confirms int
	err      error
}

func (v *fakeVault) Enroll() (string, error) {
	v.enrolls++
	if v.err != nil {
		return "", v.err
	}
	if v.sealed {
		return "", EnrollClosed
	}
	v.pending = true
	return canaryLink, nil
}

func (v *fakeVault) ConfirmEnroll(code string) (bool, error) {
	v.confirms++
	if v.err != nil {
		return false, v.err
	}
	switch {
	case v.sealed:
		return false, EnrollClosed
	case !v.pending:
		return false, EnrollNone
	case code != good:
		return false, nil
	}
	v.sealed, v.pending = true, false
	return true, nil
}

type setupRig struct {
	t        *testing.T
	path     string
	vault    *fakeVault
	now      time.Time
	finished []string
	s        *Setup
}

func newSetupRig(t *testing.T) *setupRig {
	r := &setupRig{t: t, path: filepath.Join(t.TempDir(), "setup.json"), vault: &fakeVault{}, now: time.Unix(1_800_000_000, 0)}
	r.start()
	return r
}

// start makes a fresh Setup over the same record and vault: a restart.
func (r *setupRig) start() {
	r.s = NewSetup(SetupConfig{
		Record: FileRecord{Path: r.path},
		Enroll: r.vault,
		Progress: func() localapi.SetupProgress {
			return localapi.SetupProgress{Phase: "ready", Updated: true, Online: true}
		},
		Finished: func(owner string) { r.finished = append(r.finished, owner) },
		Now:      func() time.Time { return r.now },
	})
}

func (r *setupRig) call(op string, args, out any) error {
	r.t.Helper()
	h, ok := r.s.Ops()[op]
	if !ok {
		return sockets.ErrUnknownOp
	}
	raw, _ := json.Marshal(args)
	res, err := h(context.Background(), sockets.Peer{Kind: "localui"}, raw)
	if err != nil {
		return err
	}
	if out != nil {
		b, _ := json.Marshal(res)
		if err := json.Unmarshal(b, out); err != nil {
			r.t.Fatal(err)
		}
	}
	return nil
}

func (r *setupRig) enrollAndConfirm() {
	r.t.Helper()
	var l localapi.EnrollLink
	if err := r.call(localapi.OpSetupEnroll, nil, &l); err != nil || l.URI != canaryLink {
		r.t.Fatalf("enroll %v %q", err, l.URI)
	}
	var c localapi.Confirmed
	if err := r.call(localapi.OpSetupConfirm, localapi.Confirm{Code: good}, &c); err != nil || !c.OK {
		r.t.Fatalf("confirm %v %v", err, c)
	}
}

// Security L6: setup's ops are served until finish is recorded, then
// refused, every one, for good: a restart reads the record and stays
// closed.
func TestSetupOpsAreRefusedForGoodOnceFinishIsRecorded(t *testing.T) {
	r := newSetupRig(t)
	if len(r.s.Ops()) != len(localapi.SetupOps) {
		t.Fatalf("ops %d, contract lists %d", len(r.s.Ops()), len(localapi.SetupOps))
	}
	var p localapi.SetupProgress
	if err := r.call(localapi.OpSetupProgress, nil, &p); err != nil || p.Phase != "ready" {
		t.Fatalf("progress %v %+v", err, p)
	}
	r.enrollAndConfirm()
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.finished) != 1 || r.finished[0] != "+15550100100" {
		t.Fatalf("finished %v", r.finished)
	}
	args := map[string]any{
		localapi.OpSetupProgress: nil,
		localapi.OpSetupEnroll:   nil,
		localapi.OpSetupConfirm:  localapi.Confirm{Code: good},
		localapi.OpSetupFinish:   localapi.Finish{Owner: "+15550100199"},
	}
	check := func(when string) {
		for _, op := range localapi.SetupOps {
			if err := r.call(op, args[op], nil); code(err) != localapi.ErrSetupClosed {
				t.Errorf("%s: %s: %v", when, op, err)
			}
		}
	}
	check("after finish")
	r.start()
	check("after a restart")
	if got, ok := r.s.Owner(); !ok || got != "+15550100100" {
		t.Fatalf("owner %q %v", got, ok)
	}
	if len(r.finished) != 1 || r.vault.enrolls != 1 || r.vault.confirms != 1 {
		t.Fatalf("finished %v, enrolls %d, confirms %d", r.finished, r.vault.enrolls, r.vault.confirms)
	}
	b, _ := os.ReadFile(r.path)
	if strings.Contains(string(b), "CANARY") {
		t.Fatalf("record holds the link: %s", b)
	}
	if fi, err := os.Stat(r.path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %v %v", fi, err)
	}
}

// A record that cannot be read keeps setup closed: a false closed only
// stops setup, a false open would let the page pick the owner of an owned
// box.
func TestAnUnreadableRecordKeepsSetupClosed(t *testing.T) {
	r := newSetupRig(t)
	if err := os.WriteFile(r.path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.start()
	if err := r.call(localapi.OpSetupEnroll, nil, nil); code(err) != localapi.ErrSetupClosed {
		t.Fatalf("enroll %v", err)
	}
	if _, ok := r.s.Owner(); ok {
		t.Fatal("an unreadable record named an owner")
	}
	if r.vault.enrolls != 0 {
		t.Fatal("asked the vault")
	}
}

// ONB-3, CRED-8: finish needs a confirmed enrollment that agentosd saw
// itself, and a well-formed number; neither the page's word nor a wrong
// code counts.
func TestFinishNeedsAConfirmedEnrollmentAndANumber(t *testing.T) {
	r := newSetupRig(t)
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); code(err) != localapi.ErrNotEnrolled {
		t.Fatalf("finish before enrollment: %v", err)
	}
	if err := r.call(localapi.OpSetupConfirm, localapi.Confirm{Code: good}, nil); code(err) != localapi.ErrNoEnrollment {
		t.Fatalf("confirm with nothing pending: %v", err)
	}
	var l localapi.EnrollLink
	if err := r.call(localapi.OpSetupEnroll, nil, &l); err != nil {
		t.Fatal(err)
	}
	var c localapi.Confirmed
	if err := r.call(localapi.OpSetupConfirm, localapi.Confirm{Code: "000000"}, &c); err != nil || c.OK {
		t.Fatalf("wrong code: %v %v", err, c)
	}
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); code(err) != localapi.ErrNotEnrolled {
		t.Fatalf("finish after a wrong code: %v", err)
	}
	if err := r.call(localapi.OpSetupConfirm, localapi.Confirm{Code: strings.Repeat("1", localapi.MaxCode+1)}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("long code: %v", err)
	}
	if err := r.call(localapi.OpSetupConfirm, localapi.Confirm{Code: good}, &c); err != nil || !c.OK {
		t.Fatalf("confirm %v %v", err, c)
	}
	// A restart between confirming and finishing keeps the enrollment.
	r.start()
	for _, bad := range []string{"", "5550100100", "+0555", "+1555010010x", "+1555010010012345"} {
		if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: bad}, nil); code(err) != localapi.ErrBadArgs {
			t.Errorf("finish %q: %v", bad, err)
		}
	}
	if err := r.call(localapi.OpSetupFinish, map[string]string{"owner": "+15550100100", "extra": "x"}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("unknown field: %v", err)
	}
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); err != nil {
		t.Fatal(err)
	}
}

// K17: a vault whose enrollment is closed (sealed, or never opened by
// init -setup) shows no seed; setup then counts the code generator as set
// up, since someone already holds the vault's seed.
func TestASealedVaultCountsAsEnrolled(t *testing.T) {
	r := newSetupRig(t)
	r.vault.sealed = true
	if err := r.call(localapi.OpSetupEnroll, nil, nil); code(err) != localapi.ErrEnrolled {
		t.Fatalf("enroll %v", err)
	}
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); err != nil {
		t.Fatal(err)
	}
}

// The vault's own refusals reach the page as fixed codes only.
func TestVaultRefusalsAreFixedCodes(t *testing.T) {
	r := newSetupRig(t)
	for err, want := range map[error]string{
		EnrollPaused:               localapi.ErrLimited,
		errors.New("vault locked"): localapi.ErrFailed,
	} {
		r.vault.err = err
		if got := r.call(localapi.OpSetupEnroll, nil, nil); code(got) != want {
			t.Errorf("enroll %v: %v", err, got)
		}
		if got := r.call(localapi.OpSetupConfirm, localapi.Confirm{Code: good}, nil); code(got) != want {
			t.Errorf("confirm %v: %v", err, got)
		}
	}
}

// Each enroll makes a new seed in the vault, so a compromised page cannot
// have agentosd churn it faster than EnrollsPerMinute.
func TestEnrollsAreBounded(t *testing.T) {
	r := newSetupRig(t)
	for i := 0; i < EnrollsPerMinute; i++ {
		if err := r.call(localapi.OpSetupEnroll, nil, nil); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := r.call(localapi.OpSetupEnroll, nil, nil); code(err) != localapi.ErrLimited {
		t.Fatalf("over the bound: %v", err)
	}
	r.now = r.now.Add(time.Minute)
	if err := r.call(localapi.OpSetupEnroll, nil, nil); err != nil {
		t.Fatal(err)
	}
}

// Security L6: the full page server (an owned box) never serves setup.
func TestThePageServerServesNoSetupOp(t *testing.T) {
	ops := New(Config{Owner: &fakeOwner{now: &time.Time{}}}).Ops()
	for _, op := range localapi.SetupOps {
		if _, ok := ops[op]; ok {
			t.Errorf("page server serves %s", op)
		}
	}
}
