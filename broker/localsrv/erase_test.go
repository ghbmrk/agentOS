package localsrv

// REQ: LOG-4, CH-7

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

var testHandle = strings.Repeat("ab", localapi.EraseHandle/2)

// fakeErase records what reached the owner side.
type fakeErase struct {
	calls []string
	found localapi.EraseFound
	err   error
}

func (f *fakeErase) Find(_ context.Context, session, name string) (localapi.EraseFound, error) {
	f.calls = append(f.calls, "find "+session+" "+name)
	return f.found, f.err
}

func (f *fakeErase) Confirm(_ context.Context, session, handle string, ad, cd, sig []byte) (string, error) {
	f.calls = append(f.calls, fmt.Sprintf("confirm %s %s %x %x %x", session, handle, ad, cd, sig))
	return "Forgot everything named Alice (3 items). It can no longer be read.", f.err
}

func eraseRig(t *testing.T) (*rig, *fakeErase) {
	r, _ := passkeyRig(t)
	f := &fakeErase{found: localapi.EraseFound{Text: "Found 3 items named Alice. Confirm to forget them.", Handle: testHandle, Challenge: make([]byte, localapi.PasskeyChallenge)}}
	r.srv.cfg.Erase = f
	r.ops = r.srv.Ops()
	return r, f
}

func eraseArgs(tok string) map[string]any {
	return map[string]any{
		localapi.OpEraseFind:    localapi.EraseFind{Token: tok, Name: "Alice"},
		localapi.OpEraseConfirm: localapi.EraseConfirm{Token: tok, Handle: testHandle, AuthenticatorData: []byte{1}, ClientDataJSON: []byte{2}, Signature: []byte{3}},
	}
}

// Every erase op is refused without a live session and reaches nothing;
// with one, each reaches the owner side under the session's digest, never
// its token, and the owner side's texts reach the page unchanged.
func TestEraseOpsNeedALiveSession(t *testing.T) {
	r, f := eraseRig(t)
	for _, op := range localapi.EraseOps {
		for _, tok := range []string{"", strings.Repeat("0", 2*localapi.TokenBytes), "made-up"} {
			if _, err := r.call(op, eraseArgs(tok)[op]); code(err) != localapi.ErrUnauthorized {
				t.Errorf("%s with %q: %v", op, tok, err)
			}
		}
		if _, err := r.raw(op, `{}`); code(err) != localapi.ErrUnauthorized {
			t.Errorf("%s with no args: %v", op, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("reached the owner side: %v", f.calls)
	}
	tok := r.signIn()
	out, err := r.call(localapi.OpEraseFind, eraseArgs(tok)[localapi.OpEraseFind])
	if err != nil || out.(localapi.EraseFound).Text != f.found.Text || out.(localapi.EraseFound).Handle != testHandle {
		t.Fatalf("find %+v %v", out, err)
	}
	out, err = r.call(localapi.OpEraseConfirm, eraseArgs(tok)[localapi.OpEraseConfirm])
	if err != nil || out.(localapi.Text).Text != "Forgot everything named Alice (3 items). It can no longer be read." {
		t.Fatalf("confirm %+v %v", out, err)
	}
	sid := sessionID(tok)
	want := []string{"find " + sid + " Alice", "confirm " + sid + " " + testHandle + " 01 02 03"}
	if fmt.Sprint(f.calls) != fmt.Sprint(want) {
		t.Fatalf("calls %v", f.calls)
	}
}

// The frames are bounded before anything reaches the owner side, and
// finds are counted.
func TestEraseFramesAreBounded(t *testing.T) {
	r, f := eraseRig(t)
	tok := r.signIn()
	big := make([]byte, localapi.MaxPasskeyAssertion+1)
	one := []byte{1}
	confirm := func(h string, ad, cd, sig []byte) localapi.EraseConfirm {
		return localapi.EraseConfirm{Token: tok, Handle: h, AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig}
	}
	for i, c := range []struct {
		op   string
		args any
	}{
		{localapi.OpEraseFind, localapi.EraseFind{Token: tok}},
		{localapi.OpEraseFind, localapi.EraseFind{Token: tok, Name: "  "}},
		{localapi.OpEraseFind, localapi.EraseFind{Token: tok, Name: strings.Repeat("a", localapi.MaxEraseName+1)}},
		{localapi.OpEraseFind, localapi.EraseFind{Token: tok, Name: "Al\nice"}},
		{localapi.OpEraseConfirm, confirm("", one, one, one)},
		{localapi.OpEraseConfirm, confirm(testHandle[1:], one, one, one)},
		{localapi.OpEraseConfirm, confirm(strings.ToUpper(testHandle), one, one, one)},
		{localapi.OpEraseConfirm, confirm(testHandle, nil, one, one)},
		{localapi.OpEraseConfirm, confirm(testHandle, one, big, one)},
		{localapi.OpEraseConfirm, confirm(testHandle, one, one, nil)},
	} {
		if _, err := r.call(c.op, c.args); code(err) != localapi.ErrBadArgs {
			t.Errorf("case %d (%s): %v", i, c.op, err)
		}
	}
	if _, err := r.raw(localapi.OpEraseFind, `{"token":"`+tok+`","name":"a","extra":1}`); code(err) != localapi.ErrBadArgs {
		t.Errorf("an unknown field: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("reached the owner side: %v", f.calls)
	}
	if _, err := r.call(localapi.OpEraseFind, localapi.EraseFind{Token: tok, Name: strings.Repeat("é", localapi.MaxEraseName/2)}); err != nil {
		t.Fatalf("a name at the bound: %v", err)
	}
	for i := 1; i <= EraseFindsPerMinute; i++ {
		_, err := r.call(localapi.OpEraseFind, eraseArgs(tok)[localapi.OpEraseFind])
		if want := i == EraseFindsPerMinute; (code(err) == localapi.ErrLimited) != want {
			t.Fatalf("find %d: %v", i, err)
		}
	}
	// A confirm is not a find: the owner can still confirm.
	if _, err := r.call(localapi.OpEraseConfirm, eraseArgs(tok)[localapi.OpEraseConfirm]); err != nil {
		t.Fatalf("confirm after the finds: %v", err)
	}
}

// The ops are served only with Erase and Passkeys both: the tap needs the
// passkey page's name.
func TestEraseOpsNeedPasskeys(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.Erase = &fakeErase{}
	for _, op := range localapi.EraseOps {
		if r.srv.Ops()[op] != nil {
			t.Fatalf("%s served without passkeys", op)
		}
	}
	p, _ := passkeyRig(t)
	for _, op := range localapi.EraseOps {
		if p.ops[op] != nil {
			t.Fatalf("%s served without Erase", op)
		}
	}
	e, _ := eraseRig(t)
	if len(e.ops) != len(localapi.Ops)+len(localapi.PasskeyOps)+len(localapi.EraseOps) {
		t.Fatalf("%d ops with erase", len(e.ops))
	}
}

// Only the closed set of codes reaches the page, and a find whose handle
// or challenge is out of shape offers no tap.
func TestEraseRefusalsAreTheClosedSet(t *testing.T) {
	r, f := eraseRig(t)
	tok := r.signIn()
	for _, c := range localapi.EraseCodes {
		f.err = sockets.Code(c)
		if _, err := r.call(localapi.OpEraseConfirm, eraseArgs(tok)[localapi.OpEraseConfirm]); code(err) != c {
			t.Errorf("%s: %v", c, err)
		}
	}
	for _, e := range []error{errors.New("kernel: content closed"), sockets.Code(localapi.ErrPasskeyNotAnchor), sockets.Code("kernel text")} {
		f.err = e
		for _, op := range localapi.EraseOps {
			if _, err := r.call(op, eraseArgs(tok)[op]); code(err) != localapi.ErrEraseUnavailable {
				t.Errorf("%s with %v: %v", op, e, err)
			}
		}
	}
	f.err = nil
	for _, bad := range []localapi.EraseFound{
		{Text: "x", Handle: "short", Challenge: make([]byte, localapi.PasskeyChallenge)},
		{Text: "x", Handle: testHandle, Challenge: []byte{1}},
	} {
		f.found = bad
		if _, err := r.call(localapi.OpEraseFind, eraseArgs(tok)[localapi.OpEraseFind]); code(err) != localapi.ErrEraseUnavailable {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	f.found = localapi.EraseFound{Text: "Nothing named Alice was found."}
	if out, err := r.call(localapi.OpEraseFind, eraseArgs(tok)[localapi.OpEraseFind]); err != nil || out.(localapi.EraseFound).Handle != "" {
		t.Fatalf("nothing found: %+v %v", out, err)
	}
}
