package localui

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// REQ: ONB-3, ONB-4, ONB-5, ONB-8

// codeSeq is a provider whose every started sign-in issues a new code,
// CODE-0001 first, or answers err while err is set.
type codeSeq struct {
	*fakeHooks
	s *seqState
}

type seqState struct {
	mu     sync.Mutex
	starts int
	err    error
	link   string // the link when set
}

func (c codeSeq) StartDeviceCode(id string) (string, string, string, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if c.s.err != nil {
		return "", "", "", c.s.err
	}
	c.s.starts++
	link := "https://example.invalid/device"
	if c.s.link != "" {
		link = c.s.link
	}
	return link, fmt.Sprintf("CODE-%04d", c.s.starts), "Example", nil
}

func (s *seqState) set(err error) { s.mu.Lock(); s.err = err; s.mu.Unlock() }
func (s *seqState) n() int        { s.mu.Lock(); defer s.mu.Unlock(); return s.starts }

func newSeqRig(t *testing.T) (*rig, *seqState) {
	r := newRig(t)
	s := &seqState{}
	r.via = codeSeq{r.hooks, s}
	r.srv = r.open(&MemStore{})
	r.runSetupToAI()
	return r, s
}

// submit posts the page's rendered form key ("ai-device anthropic") as a
// browser would: its provider, and its private box if ticked.
func submit(r *rig, page, key string) {
	r.t.Helper()
	f, ok := setupForms(r.t, page)[key]
	if !ok {
		r.t.Fatalf("no %s form on the page:\n%s", key, page)
	}
	action, provider, _ := strings.Cut(key, " ")
	v := url.Values{"provider": {provider}}
	if regexp.MustCompile(`name="private" value="1" checked>`).MatchString(f) {
		v.Set("private", "1")
	}
	r.post("/setup/"+action, v)
}

// shownCode is the code the page shows as current, or "".
func shownCode(page string) string {
	if m := devicePrompt.FindStringSubmatch(page); m != nil {
		return m[2]
	}
	return ""
}

// UX3-1 acceptance 1 (ONB-3, ONB-4, ONB-8): from the page as rendered, the
// owner starts a sign-in, gets a new code from the control beside the
// shown one, and setup finishes once the provider reports connected. No
// empty link is ever shown.
func TestTheRenderedSignInControlsStartRetryAndFinish(t *testing.T) {
	r, s := newSeqRig(t)
	page := r.get("/setup")
	if strings.Contains(page, `href=""`) || shownCode(page) != "" {
		t.Fatalf("a code or empty link shown before any sign-in:\n%s", page)
	}
	submit(r, page, "ai-device anthropic")
	page = r.get("/setup")
	if shownCode(page) != "CODE-0001" || !strings.Contains(page, "Example") {
		t.Fatalf("started sign-in not shown with its issuer:\n%s", page)
	}
	if !r.hooks.private["anthropic"] {
		t.Fatal("the plan's ticked private answer was not recorded")
	}
	submit(r, page, "ai-retry anthropic")
	page = r.get("/setup")
	if shownCode(page) != "CODE-0002" || strings.Contains(page, "CODE-0001") || s.n() != 2 {
		t.Fatalf("new code not shown in place of the old (%d starts):\n%s", s.n(), page)
	}
	if strings.Contains(page, `href=""`) {
		t.Fatalf("empty link shown:\n%s", page)
	}
	r.hooks.mu.Lock()
	r.hooks.connected = true // the owner finished on the provider's site
	r.hooks.mu.Unlock()
	r.do("GET", "/setup", nil)
	if !r.srv.setup.done() || r.hooks.finishes != 1 {
		t.Fatalf("setup not finished once connected: done %v, finishes %d", r.srv.setup.done(), r.hooks.finishes)
	}
}

// UX3-1 acceptance 2: a new code asked for while the provider's sign-in
// still waits keeps the shown code, which still works.
func TestANewCodeWhileTheSignInWaitsKeepsTheCode(t *testing.T) {
	r, s := newSeqRig(t)
	submit(r, r.get("/setup"), "ai-device anthropic")
	s.set(fmt.Errorf("%w (sign-in busy)", ErrSignInBusy))
	submit(r, r.get("/setup"), "ai-retry anthropic")
	if e := r.setupErr(); !strings.Contains(e, "still waiting") {
		t.Fatalf("busy not named: %q", e)
	}
	page := r.get("/setup")
	if shownCode(page) != "CODE-0001" {
		t.Fatalf("a code still waiting was dropped:\n%s", page)
	}
	if _, ok := setupForms(t, page)["ai-retry anthropic"]; !ok {
		t.Fatal("no way to ask again once the code expires")
	}
}

// UX3-1 acceptance 2: once the provider's sign-in has ended (expired,
// declined, or the provider failed) and no new one starts, the old code is
// no longer shown as current: the page says so and offers Sign in again,
// scoped to that provider. A Sign in that then meets the old sign-in still
// waiting shows its code again, since busy proves it waits.
func TestANewCodeThatFailsDropsTheOldCode(t *testing.T) {
	for name, err := range map[string]error{
		"failed":  errors.New("failed"),
		"limited": errors.New("limited"),
		"http://": nil,
	} {
		t.Run(name, func(t *testing.T) {
			r, s := newSeqRig(t)
			submit(r, r.get("/setup"), "ai-device anthropic")
			if err != nil {
				s.set(err)
			} else {
				s.mu.Lock()
				s.link = "http://example.invalid/device"
				s.mu.Unlock()
			}
			submit(r, r.get("/setup"), "ai-retry anthropic")
			if e := r.setupErr(); !strings.Contains(e, "Could not get a new code") {
				t.Fatalf("status not shown: %q", e)
			}
			page := r.get("/setup")
			if strings.Contains(page, "CODE-0001") || shownCode(page) != "" {
				t.Fatalf("an ended code still shown as current:\n%s", page)
			}
			forms := setupForms(t, page)
			if _, ok := forms["ai-device anthropic"]; !ok {
				t.Fatalf("no Sign in offered:\n%s", page)
			}
			if _, ok := forms["ai-device openai"]; ok {
				t.Fatal("sign-in offered for a provider without device codes")
			}
			if err == nil { // the refused start ended the old sign-in
				s.set(fmt.Errorf("%w (sign-in busy)", ErrSignInBusy))
				submit(r, r.get("/setup"), "ai-device anthropic")
				if page := r.get("/setup"); shownCode(page) != "" || strings.Contains(page, "CODE-0001") {
					t.Fatalf("an ended code shown again after a refused new code:\n%s", page)
				}
			}
		})
	}
	t.Run("busy brings it back", func(t *testing.T) {
		r, s := newSeqRig(t)
		submit(r, r.get("/setup"), "ai-device anthropic")
		s.set(errors.New("failed"))
		submit(r, r.get("/setup"), "ai-retry anthropic")
		s.set(fmt.Errorf("%w (sign-in busy)", ErrSignInBusy))
		submit(r, r.get("/setup"), "ai-device anthropic")
		if page := r.get("/setup"); shownCode(page) != "CODE-0001" {
			t.Fatalf("a sign-in proved waiting not shown again:\n%s", page)
		}
		s.set(nil)
		submit(r, r.get("/setup"), "ai-retry anthropic")
		if page := r.get("/setup"); shownCode(page) != "CODE-0002" {
			t.Fatalf("new code not shown:\n%s", page)
		}
	})
	t.Run("a refused sign-in clears it", func(t *testing.T) {
		r, s := newSeqRig(t)
		submit(r, r.get("/setup"), "ai-device anthropic")
		s.set(errors.New("failed"))
		submit(r, r.get("/setup"), "ai-retry anthropic")
		s.set(nil)
		s.mu.Lock()
		s.link = "http://example.invalid/device"
		s.mu.Unlock()
		submit(r, r.get("/setup"), "ai-device anthropic")
		s.mu.Lock()
		s.link = ""
		s.mu.Unlock()
		s.set(fmt.Errorf("%w (sign-in busy)", ErrSignInBusy))
		submit(r, r.get("/setup"), "ai-device anthropic")
		if page := r.get("/setup"); shownCode(page) != "" || strings.Contains(page, "CODE-0001") {
			t.Fatalf("an ended code came back after a refused sign-in:\n%s", page)
		}
	})
	t.Run("a new sign-in clears it", func(t *testing.T) {
		r, s := newSeqRig(t)
		submit(r, r.get("/setup"), "ai-device anthropic")
		s.set(errors.New("failed"))
		submit(r, r.get("/setup"), "ai-retry anthropic")
		s.set(nil)
		submit(r, r.get("/setup"), "ai-device anthropic")
		s.set(fmt.Errorf("%w (sign-in busy)", ErrSignInBusy))
		submit(r, r.get("/setup"), "ai-retry anthropic")
		if page := r.get("/setup"); shownCode(page) != "CODE-0002" || strings.Contains(page, "CODE-0001") {
			t.Fatalf("an ended code came back:\n%s", page)
		}
	})
}

// UX3-1 acceptance 3 and 4 (ONB-3, ONB-5): a new code changes neither
// pairing, the code generator, recovery nor the private answer, and asks
// for no new step.
func TestANewCodeKeepsSetupState(t *testing.T) {
	r, _ := newSeqRig(t)
	submit(r, r.get("/setup"), "ai-device anthropic")
	before := r.srv.setup.st
	privates, private := r.hooks.privates, r.hooks.private["anthropic"]
	submit(r, r.get("/setup"), "ai-retry anthropic")
	after := r.srv.setup.st
	if after.Owner != before.Owner || after.Device != before.Device || after.Codes != before.Codes ||
		after.Recovery != before.Recovery || after.Host != before.Host || after.HostTrusted != before.HostTrusted || after.Done {
		t.Fatalf("a new code changed setup: %+v -> %+v", before, after)
	}
	if r.hooks.privates != privates || r.hooks.private["anthropic"] != private {
		t.Fatal("a new code re-recorded the private answer")
	}
}

// UX3-1 acceptance 3 (ONB-3): another phone on the Wi-Fi cannot replace
// the shown code, and a new code with none shown starts nothing.
func TestOnlyThePairedPhoneGetsANewCode(t *testing.T) {
	r, s := newSeqRig(t)
	r.post("/setup/ai-retry", url.Values{"provider": {"anthropic"}})
	if s.n() != 0 {
		t.Fatal("a new code started with no sign-in shown")
	}
	submit(r, r.get("/setup"), "ai-device anthropic")
	r.asOther(func() {
		r.post("/setup/ai-retry", url.Values{"provider": {"anthropic"}})
	})
	if page := r.get("/setup"); s.n() != 1 || shownCode(page) != "CODE-0001" {
		t.Fatalf("another phone replaced the code (%d starts):\n%s", s.n(), page)
	}
	r.post("/setup/ai-retry", url.Values{"provider": {"openai"}})
	if s.n() != 1 {
		t.Fatal("a new code started for a provider with none shown")
	}
}
