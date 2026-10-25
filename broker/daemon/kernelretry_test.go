package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-2, CH-10, CH-12, KRN-7

// The kernel's unsettled steps, as a running kernel lists them: an unknown
// outcome, a parked one the owner may RETRY, an unsent step of a live plan,
// and an unsent step of a cancelled plan, which never acted.
func kernelSteps() []KernelStep {
	return []KernelStep{
		{Plan: "p1", Verb: "post", Clerk: "web", Phase: KernelUnknown, PlanStatus: KernelPlanActive},
		{Plan: "p2", Index: 1, Verb: "archive", Clerk: "mail", Phase: KernelParked, Retry: true, PlanStatus: KernelPlanActive},
		{Plan: "p3", Verb: "send", Clerk: "mail", Phase: KernelUnsent, PlanStatus: KernelPlanActive},
		{Plan: "p4", Verb: "send", Clerk: "mail", Phase: KernelUnsent, PlanStatus: "cancelled"},
	}
}

// STATUS counts the kernel's unsettled steps beside the journal's (#2783
// b): an unknown or parked outcome may have happened, an unsent step of a
// live plan waits to run, and one of an ended plan is not counted. Steps
// that cannot be read are named, never counted as none in silence.
func TestSTATUSCountsTheKernelsUnsettledSteps(t *testing.T) {
	k := &fakeKernel{steps: kernelSteps()}
	dir := withKernel(t, k)
	want := "Running. 2 may have happened (post/web, archive/mail), 1 waiting to run, 0 awaiting a decision."
	if r := text(t, dir, owner, "STATUS")[0]; !strings.HasPrefix(r, want) || strings.Contains(r, "Part of me") {
		t.Fatalf("STATUS: %q, want it to start %q", r, want)
	}
	k.set(func(k *fakeKernel) { k.unlisted = true })
	r := text(t, dir, owner, "STATUS")[0]
	if !strings.HasPrefix(r, "Running. 0 may have happened, 0 waiting to run") || !strings.Contains(r, kernelUnlisted) {
		t.Fatalf("STATUS with the steps unread: %q", r)
	}
	k.set(func(k *fakeKernel) { k.unlisted, k.setup = false, true })
	if r := text(t, dir, owner, "STATUS")[0]; strings.Contains(r, "Part of me") {
		t.Fatalf("a setup-only kernel was named as not answering: %q", r)
	}
}

// After a STOP whose kernel leg failed, STATUS reads "Stopped." from the
// journal and still names the kernel that did not answer (#3077 Security
// later 2), until it answers.
func TestSTATUSNamesAKernelThatMissedTheSTOP(t *testing.T) {
	k := &fakeKernel{down: true}
	dir := withKernel(t, k)
	if r := text(t, dir, owner, "STOP"); !strings.HasPrefix(r[0], "STOP failed") {
		t.Fatalf("STOP with no kernel: %q", r)
	}
	if r := text(t, dir, owner, "STATUS")[0]; !strings.HasPrefix(r, "Stopped.") || !strings.Contains(r, kernelUnreached) {
		t.Fatalf("STATUS after the kernel missed the STOP: %q", r)
	}
	k.set(func(k *fakeKernel) { k.down = false })
	if r := text(t, dir, owner, "STATUS")[0]; !strings.HasPrefix(r, "Stopped.") || strings.Contains(r, "Part of me") {
		t.Fatalf("STATUS once the kernel answers: %q", r)
	}
}

// withKernelChannel runs the daemon with the kernel and the owner channel
// over a modem line, as agentosd runs it, and returns the owner's phone.
func withKernelChannel(t *testing.T, k KernelOwner) (*Daemon, *modem.Line) {
	t.Helper()
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	carrier := modem.NewCarrier()
	phone := carrier.Line(owner)
	_, d := startWith(t, dir, func(c *Config) {
		c.Kernel, c.Auth, c.OwnerState, c.Modem = k, nil, filepath.Join(dir, "owner.json"), carrier.Line("+15550000009")
	})
	return d, phone
}

// RETRY offers the step the kernel holds parked, and only that one, as its
// own request: the owner's approval with the texted code retries that plan
// and step on the kernel, and the owner is told it may go twice (#2783 b,
// CH-12).
func TestRETRYRetriesTheKernelsParkedStep(t *testing.T) {
	k := &fakeKernel{steps: kernelSteps()}
	d, phone := withKernelChannel(t, k)
	ctx := context.Background()
	if got := d.Owner().Handle(ctx, owner, "RETRY"); len(got) != 0 {
		t.Fatalf("RETRY replies %q", got)
	}
	req := nextText(t, phone)
	m := retryCodeRe.FindStringSubmatch(req)
	if m == nil || !strings.Contains(req, "archive on mail") || !strings.Contains(req, "may go twice") || strings.Contains(req, "post") {
		t.Fatalf("request %q", req)
	}
	if got := d.Owner().Handle(ctx, owner, "YES "+m[1]+" "+m[2]); len(got) != 1 || got[0] != "Approved "+m[1]+"." {
		t.Fatalf("approve: %q", got)
	}
	d.retry.running.Wait()
	if got, want := nextText(t, phone), "Retry "+m[1]+": archive on mail will be tried again; it may go twice. Text STATUS to see how it ends."; got != want {
		t.Fatalf("outcome %q, want %q", got, want)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.retried) != 1 || k.retried[0] != "p2/1" {
		t.Fatalf("the kernel retried %q, want p2/1", k.retried)
	}
}

// Every answer but an approval retries nothing; a refusal or a lost answer
// is told as such, never as a retry under way, and is listed again.
func TestAKernelRETRYOnlyOnTheOwnersWord(t *testing.T) {
	k := &fakeKernel{steps: kernelSteps()}
	d, _ := withKernelChannel(t, k)
	var told []string
	d.retry.mu.Lock()
	d.retry.inform = func(s string) error { told = append(told, s); return nil }
	d.retry.mu.Unlock()
	relisted := 0
	d.OnRetryRefused(func() { relisted++ })
	ref := func() string {
		for _, it := range d.retry.items() {
			if strings.HasPrefix(it.Ref, kernelRefPrefix) {
				return it.Ref
			}
		}
		t.Fatal("RETRY offered no kernel step")
		return ""
	}
	for _, why := range []string{"owner", "expired", "void", "not chosen", "restart"} {
		d.retry.decide(noGate(t))(ownerch.Decision{Request: "A1", Item: 1, Ref: ref(), Why: why})
	}
	d.retry.decide(noGate(t))(ownerch.Decision{Request: "A1", Item: 1, Ref: kernelRefPrefix + "forged", Approved: true})
	d.retry.running.Wait()
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.retried) != 0 || len(told) != 0 {
		t.Fatalf("a RETRY the owner did not approve ran: %q, told %q", k.retried, told)
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{KernelRefused{Text: "kernel: no parked step of a live plan there to retry"}, "Retry B1 refused: it is no longer waiting for a retry. Archive on mail was not tried again; text RETRY later."},
		{KernelRefused{Text: "kernel: the step cannot be sent again now: stopped: stop is in force"}, "Retry B1 refused: STOP is on. Archive on mail was not tried again; text RETRY later."},
		{KernelRefused{Text: "kernel: the step cannot be sent again now: revoked: x"}, "Retry B1 refused: my checks refused it. Archive on mail was not tried again; text RETRY later."},
		{ErrKernelLost, "Retry B1: I could not tell whether archive on mail will be tried again. Text STATUS to see; text RETRY to ask again."},
		{errors.New("unreachable"), "Retry B1 refused: it could not be started. Archive on mail was not tried again; text RETRY later."},
	} {
		k.retryErr = c.err
		k.mu.Unlock()
		told, relisted = nil, 0
		d.retry.decide(noGate(t))(ownerch.Decision{Request: "B1", Item: 1, Ref: ref(), Approved: true})
		d.retry.running.Wait()
		k.mu.Lock()
		if len(told) != 1 || told[0] != c.want || relisted != 1 {
			t.Fatalf("%v: told %q, relisted %d; want %q", c.err, told, relisted, c.want)
		}
	}
}

// A parked step's line takes the tier its own facts give (CH-10, CH-11):
// money is always the code generator's, a recipient the broker has not
// looked up is high, and the owner's excluded verbs still bind, since the
// verb is the step's own.
func TestAKernelRETRYLineTakesItsStepsTier(t *testing.T) {
	low := ownerch.Limits{AmountLimit: 1 << 40}
	for _, c := range []struct {
		s    KernelStep
		lim  ownerch.Limits
		want ownerch.Tier
	}{
		{KernelStep{Verb: "archive", Clerk: "mail"}, low, ownerch.Low},
		{KernelStep{Verb: "archive", Clerk: "mail"}, ownerch.Limits{AmountLimit: 1 << 40, ExcludedVerbs: []string{"archive"}}, ownerch.High},
		{KernelStep{Verb: "send", Clerk: "mail", Recipient: "a@example.test"}, low, ownerch.High},
		{KernelStep{Verb: "pay", Clerk: "bank", Money: true, Amount: 5}, low, ownerch.High},
	} {
		it := kernelItem(c.s)
		if got := ownerch.Classify(it.Facts, c.lim, it.Facts.RecipientSince); got != c.want {
			t.Errorf("%+v: tier %v, want %v", c.s, got, c.want)
		}
	}
	if it := kernelItem(KernelStep{Verb: "pay", Clerk: "bank", Money: true, Amount: 1250}); it.Amount != "1250 minor units" || it.Facts.Kind != ownerch.MoneyRetry {
		t.Fatalf("a money step's line: %+v", it)
	}
}

// A line the owner cannot approve by text (here, a recipient that is not
// canonical) is retried only when approved on the local page with its sum;
// a texted approval is refused and retries nothing (grants
// ErrRetryNotConfirmed's rule).
func TestAKernelRETRYOfALocalLineNeedsThePage(t *testing.T) {
	k := &fakeKernel{}
	d, _ := withKernelChannel(t, k)
	var told []string
	d.retry.mu.Lock()
	d.retry.inform = func(s string) error { told = append(told, s); return nil }
	d.retry.mu.Unlock()
	s := KernelStep{Plan: "p5", Verb: "send", Clerk: "mail", Recipient: "Alice <not canonical>"}
	a := kernelAsk(s)
	if ownerch.SMSApprovable(a.line.Shown) {
		t.Fatal("the line is approvable by text")
	}
	d.retry.runKernel("C1", a, false)
	if len(told) != 1 || !strings.HasPrefix(told[0], "Retry C1 refused: it must be approved on my Wi-Fi page.") || len(k.retried) != 0 {
		t.Fatalf("a texted approval of a local line: told %q, retried %q", told, k.retried)
	}
	d.retry.runKernel("C2", a, true)
	if len(k.retried) != 1 || k.retried[0] != "p5/0" {
		t.Fatalf("a page approval: retried %q", k.retried)
	}
}
