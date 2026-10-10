package localsrv

// REQ: OSS-10, CH-7, UPD-8

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

var digest = strings.Repeat("ab", 32)

// WF3: changing where updates come from needs a live session token: none,
// an unminted one, an expired one or one a lock ended is refused before
// any field is read, and nothing reaches the updater.
func TestOSS10wFollowNeedsALiveSession(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.now = r.now.Add(r.own.UnlockPeriod() + time.Second)
	for _, tk := range []string{"", strings.Repeat("0", 2*localapi.TokenBytes), tok} {
		if _, err := r.call(localapi.OpFollow, localapi.Follow{Token: tk, Name: "Acme", Digest: digest}); code(err) != localapi.ErrUnauthorized {
			t.Fatalf("follow with %q: %v", tk, err)
		}
		if _, err := r.call(localapi.OpFollowRoot, localapi.FollowRoot{Token: tk, Root: []byte("root")}); code(err) != localapi.ErrUnauthorized {
			t.Fatalf("root with %q: %v", tk, err)
		}
	}
	if _, err := r.raw(localapi.OpFollow, `{"name":"Acme","digest":"`+digest+`","x":1}`); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("unknown field without a token: %v", err)
	}
	if len(r.follows) != 0 {
		t.Fatalf("reached the updater: %v", r.follows)
	}
}

func TestOSS10wFollowWithASession(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	out, err := r.call(localapi.OpFollowRoot, localapi.FollowRoot{Token: tok, Root: []byte("root")})
	if sum, ok := out.(localapi.RootSummary); err != nil || !ok || sum.Digest != digest || sum.Refusal != "" {
		t.Fatalf("%+v %v", out, err)
	}
	out, err = r.call(localapi.OpFollowRoot, localapi.FollowRoot{Token: tok, Root: []byte("forged")})
	if sum, ok := out.(localapi.RootSummary); err != nil || !ok || sum.Refusal != localapi.RefusedRoot || sum.Digest != "" {
		t.Fatalf("a refused root: %+v %v", out, err)
	}
	for _, name := range []string{"Acme", ""} {
		out, err = r.call(localapi.OpFollow, localapi.Follow{Token: tok, Name: name, Digest: digest})
		if txt, ok := out.(localapi.Text); err != nil || !ok || txt.Text != "Asked: K8" {
			t.Fatalf("%q: %+v %v", name, out, err)
		}
	}
	if len(r.follows) != 2 || r.follows[0] != "Acme@"+digest || r.follows[1] != "@"+digest {
		t.Fatalf("%v", r.follows)
	}
}

func TestOSS10wFollowFieldsAreBounded(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	for _, f := range []localapi.Follow{
		{Token: tok, Name: strings.Repeat("a", localapi.MaxFollowName+1), Digest: digest},
		{Token: tok, Name: "Acme", Digest: ""},
		{Token: tok, Name: "Acme", Digest: strings.ToUpper(digest)},
		{Token: tok, Name: "Acme", Digest: digest + "0"},
	} {
		if _, err := r.call(localapi.OpFollow, f); code(err) != localapi.ErrBadArgs {
			t.Fatalf("%+v: %v", f, err)
		}
	}
	for _, root := range [][]byte{nil, make([]byte, localapi.MaxRoot+1)} {
		if _, err := r.call(localapi.OpFollowRoot, localapi.FollowRoot{Token: tok, Root: root}); code(err) != localapi.ErrBadArgs {
			t.Fatalf("root of %d bytes: %v", len(root), err)
		}
	}
	// OSS-10w-r: the root files brought with it are bounded alike.
	for _, chain := range [][][]byte{{nil}, {make([]byte, localapi.MaxRoot+1)}, make([][]byte, localapi.MaxRootChain+1)} {
		for i := range chain {
			if chain[i] == nil && len(chain) > 1 {
				chain[i] = []byte("root")
			}
		}
		if _, err := r.call(localapi.OpFollowRoot, localapi.FollowRoot{Token: tok, Root: []byte("root"), Chain: chain}); code(err) != localapi.ErrBadArgs {
			t.Fatalf("chain of %d: %v", len(chain), err)
		}
	}
	if len(r.follows) != 0 {
		t.Fatalf("%v", r.follows)
	}
}

// Without the updater wired, the ops fail closed with a fixed code.
func TestOSS10wFollowUnwiredFailsClosed(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.DescribeRoot, r.srv.cfg.Follow = nil, nil
	tok := r.signIn()
	if _, err := r.call(localapi.OpFollow, localapi.Follow{Token: tok, Name: "Acme", Digest: digest}); code(err) != localapi.ErrFailed {
		t.Fatalf("%v", err)
	}
	if _, err := r.call(localapi.OpFollowRoot, localapi.FollowRoot{Token: tok, Root: []byte("root")}); code(err) != localapi.ErrFailed {
		t.Fatalf("%v", err)
	}
	r.srv.cfg.Follow = func(context.Context, string, string) (string, error) { return "", context.Canceled }
	if _, err := r.call(localapi.OpFollow, localapi.Follow{Token: tok, Name: "Acme", Digest: digest}); code(err) != localapi.ErrFailed {
		t.Fatalf("a failed submit: %v", err)
	}
}

// OSS-10w L3 decision: a refused root carries a coarse reason the page
// words (expired by the box's clock, too few valid signatures, a
// threshold below the box's floor), which agentosd maps from the
// updater's error; any other text is dropped, as is the rest of the
// summary.
func TestOSS10w2RefusedRootHasACoarseReason(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	for _, tc := range []struct{ reason, want string }{
		{localapi.RootExpired, localapi.RootExpired},
		{localapi.RootSignatures, localapi.RootSignatures},
		{localapi.RootThreshold, localapi.RootThreshold},
		{"tuf: root v3 expired 2026-01-01 by key 0f3a", ""},
		{"", ""},
	} {
		r.srv.cfg.DescribeRoot = func(context.Context, []byte, [][]byte) (localapi.RootSummary, error) {
			return localapi.RootSummary{Version: 3, Digest: digest, Reason: tc.reason}, errFailed
		}
		out, err := r.call(localapi.OpFollowRoot, localapi.FollowRoot{Token: tok, Root: []byte("root")})
		sum, ok := out.(localapi.RootSummary)
		if err != nil || !ok || sum.Refusal != localapi.RefusedRoot || sum.Reason != tc.want || sum.Digest != "" || sum.Version != 0 {
			t.Fatalf("%q: %+v %v", tc.reason, out, err)
		}
	}
	// A root that verifies carries no reason.
	r.srv.cfg.DescribeRoot = func(context.Context, []byte, [][]byte) (localapi.RootSummary, error) {
		return localapi.RootSummary{Version: 3, Digest: digest, Reason: localapi.RootExpired, Refusal: "x", Project: true}, nil
	}
	out, err := r.call(localapi.OpFollowRoot, localapi.FollowRoot{Token: tok, Root: []byte("root")})
	if sum, ok := out.(localapi.RootSummary); err != nil || !ok || sum.Reason != "" || sum.Refusal != "" || sum.Digest != digest || !sum.Project {
		t.Fatalf("%+v %v", out, err)
	}
}

// OSS-10w-r: the chain reaches agentosd's describe as brought.
func TestOSS10wrChainIsPassedThrough(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	var got [][]byte
	r.srv.cfg.DescribeRoot = func(_ context.Context, _ []byte, chain [][]byte) (localapi.RootSummary, error) {
		got = chain
		return localapi.RootSummary{Version: 3, Digest: digest}, nil
	}
	want := [][]byte{[]byte("v1"), []byte("v2")}
	if _, err := r.call(localapi.OpFollowRoot, localapi.FollowRoot{Token: tok, Root: []byte("root"), Chain: want}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got[0]) != "v1" || string(got[1]) != "v2" {
		t.Fatalf("%q", got)
	}
}
