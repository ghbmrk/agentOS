package localsrv

// REQ: KEY-4, CH-7, CLK-1

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// fakePasskeys records what reached the owner side.
type fakePasskeys struct {
	calls    []string
	sessions []string
	err      error
}

func (f *fakePasskeys) List(context.Context) (localapi.PasskeyList, error) {
	f.calls = append(f.calls, "list")
	return localapi.PasskeyList{Anchors: []localapi.Passkey{{ID: strings.Repeat("a", 64), Fingerprint: "aaaa aaaa aaaa", Alg: "es256"}}}, f.err
}

func (f *fakePasskeys) Begin(_ context.Context, session string, point []byte) ([]byte, error) {
	f.calls = append(f.calls, "begin")
	f.sessions = append(f.sessions, session)
	return make([]byte, 32), f.err
}

func (f *fakePasskeys) Finish(_ context.Context, session string, _, _, _ []byte) error {
	f.calls = append(f.calls, "finish")
	f.sessions = append(f.sessions, session)
	return f.err
}

func (f *fakePasskeys) CutOff(_ context.Context, id string, ad, cd, sig []byte) error {
	f.calls = append(f.calls, fmt.Sprintf("cutoff %s %x %x %x", id, ad, cd, sig))
	return f.err
}

func passkeyRig(t *testing.T) (*rig, *fakePasskeys) {
	r := newRig(t)
	f := &fakePasskeys{}
	r.srv.cfg.Passkeys = f
	r.ops = r.srv.Ops()
	return r, f
}

var testID = strings.Repeat("0f", 32)

func passkeyArgs(tok string) map[string]any {
	return map[string]any{
		localapi.OpPasskeys:      localapi.Auth{Token: tok},
		localapi.OpPasskeyBegin:  localapi.PasskeyBegin{Token: tok, Point: make([]byte, localapi.PasskeyPoint)},
		localapi.OpPasskeyFinish: localapi.PasskeyFinish{Token: tok, AuthenticatorData: []byte{1}, ClientDataJSON: []byte{2}, Signature: []byte{3}},
		localapi.OpPasskeyCutOff: localapi.PasskeyCutOff{Token: tok, ID: testID, AuthenticatorData: []byte{4}, ClientDataJSON: []byte{5}, Signature: []byte{6}},
	}
}

// Every passkey op is refused without a live session and reaches nothing;
// with one, each reaches the owner side under the session's digest, never
// its token.
func TestPasskeyOpsNeedALiveSession(t *testing.T) {
	r, f := passkeyRig(t)
	for _, op := range localapi.PasskeyOps {
		for _, tok := range []string{"", strings.Repeat("0", 2*localapi.TokenBytes), "made-up"} {
			if _, err := r.call(op, passkeyArgs(tok)[op]); code(err) != localapi.ErrUnauthorized {
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
	for _, op := range localapi.PasskeyOps {
		if _, err := r.call(op, passkeyArgs(tok)[op]); err != nil {
			t.Errorf("%s: %v", op, err)
		}
	}
	if len(f.calls) != 4 || f.calls[3] != "cutoff "+testID+" 04 05 06" {
		t.Fatalf("calls %v", f.calls)
	}
	for _, s := range f.sessions {
		if s != sessionID(tok) || strings.Contains(s, tok) {
			t.Fatalf("session %q for token %q", s, tok)
		}
	}
	// A signed-out session is dead at once.
	if _, err := r.call(localapi.OpSignOut, localapi.Auth{Token: tok}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.call(localapi.OpPasskeyBegin, passkeyArgs(tok)[localapi.OpPasskeyBegin]); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("after sign-out: %v", err)
	}
}

// The page's frames are bounded before anything reaches the owner side:
// a point is exactly 65 bytes, each assertion part 1 to
// MaxPasskeyAssertion bytes, an ID 64 lowercase hex; begins are counted.
func TestPasskeyFramesAreBounded(t *testing.T) {
	r, f := passkeyRig(t)
	tok := r.signIn()
	big := make([]byte, localapi.MaxPasskeyAssertion+1)
	for i, c := range []struct {
		op   string
		args any
	}{
		{localapi.OpPasskeyBegin, localapi.PasskeyBegin{Token: tok, Point: make([]byte, 64)}},
		{localapi.OpPasskeyBegin, localapi.PasskeyBegin{Token: tok, Point: make([]byte, 66)}},
		{localapi.OpPasskeyBegin, localapi.PasskeyBegin{Token: tok}},
		{localapi.OpPasskeyFinish, localapi.PasskeyFinish{Token: tok, AuthenticatorData: big, ClientDataJSON: []byte{1}, Signature: []byte{1}}},
		{localapi.OpPasskeyFinish, localapi.PasskeyFinish{Token: tok, AuthenticatorData: []byte{1}, ClientDataJSON: big, Signature: []byte{1}}},
		{localapi.OpPasskeyFinish, localapi.PasskeyFinish{Token: tok, AuthenticatorData: []byte{1}, ClientDataJSON: []byte{1}, Signature: big}},
		{localapi.OpPasskeyFinish, localapi.PasskeyFinish{Token: tok, AuthenticatorData: []byte{1}, ClientDataJSON: []byte{1}}},
		{localapi.OpPasskeyCutOff, localapi.PasskeyCutOff{Token: tok, ID: strings.ToUpper(testID)}},
		{localapi.OpPasskeyCutOff, localapi.PasskeyCutOff{Token: tok, ID: testID[:62]}},
		{localapi.OpPasskeyCutOff, localapi.PasskeyCutOff{Token: tok, ID: strings.Repeat("g", 64)}},
		// A cut-off's tap is whole or absent (#3209).
		{localapi.OpPasskeyCutOff, localapi.PasskeyCutOff{Token: tok, ID: testID, AuthenticatorData: []byte{1}, ClientDataJSON: []byte{1}}},
		{localapi.OpPasskeyCutOff, localapi.PasskeyCutOff{Token: tok, ID: testID, AuthenticatorData: []byte{1}, ClientDataJSON: []byte{1}, Signature: big}},
	} {
		if _, err := r.call(c.op, c.args); code(err) != localapi.ErrBadArgs {
			t.Errorf("case %d (%s): %v", i, c.op, err)
		}
	}
	if _, err := r.raw(localapi.OpPasskeyCutOff, `{"token":"`+tok+`","id":"`+testID+`","extra":1}`); code(err) != localapi.ErrBadArgs {
		t.Errorf("an unknown field: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("reached the owner side: %v", f.calls)
	}
	for i := range PasskeyBeginsPerMinute + 1 {
		_, err := r.call(localapi.OpPasskeyBegin, passkeyArgs(tok)[localapi.OpPasskeyBegin])
		if want := i == PasskeyBeginsPerMinute; (code(err) == localapi.ErrLimited) != want {
			t.Fatalf("begin %d: %v", i, err)
		}
	}
}

// Without Config.Passkeys the ops are not registered at all; with it, the
// rest of the socket is unchanged.
func TestPasskeyOpsAbsentWithoutConfig(t *testing.T) {
	r := newRig(t)
	for _, op := range localapi.PasskeyOps {
		if r.ops[op] != nil {
			t.Fatalf("%s served without -passkey-rp-id", op)
		}
	}
	p, _ := passkeyRig(t)
	if len(p.ops) != len(localapi.Ops)+len(localapi.PasskeyOps) {
		t.Fatalf("%d ops with passkeys", len(p.ops))
	}
}

// Only the closed set of codes reaches the page: an owner side's other
// error, text included, is ErrPasskeyUnavailable.
func TestPasskeyRefusalsAreTheClosedSet(t *testing.T) {
	r, f := passkeyRig(t)
	tok := r.signIn()
	for _, c := range localapi.PasskeyCodes {
		f.err = sockets.Code(c)
		if _, err := r.call(localapi.OpPasskeyFinish, passkeyArgs(tok)[localapi.OpPasskeyFinish]); code(err) != c {
			t.Errorf("%s: %v", c, err)
		}
	}
	for _, e := range []error{errors.New("kernel: an anchor is cut off only by recovery"), sockets.Code("unauthorized"), sockets.Code("kernel text")} {
		f.err = e
		for _, op := range localapi.PasskeyOps {
			if _, err := r.call(op, passkeyArgs(tok)[op]); code(err) != localapi.ErrPasskeyUnavailable {
				t.Errorf("%s with %v: %v", op, e, err)
			}
		}
	}
}
