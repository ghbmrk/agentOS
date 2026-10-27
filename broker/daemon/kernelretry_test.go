package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-2, CH-10, CH-12, KRN-4, KRN-7

// The kernel's unsettled steps, as a running kernel lists them: an unknown
// outcome, a parked one the owner may RETRY, an unsent step of a live plan,
// and an unsent step of a cancelled plan, which never acted.
func kernelSteps() []KernelStep {
	return []KernelStep{
		{Plan: "p1", Verb: "post", Clerk: "web", Phase: KernelUnknown, PlanStatus: KernelPlanActive},
		{Plan: "p2", Index: 1, Verb: "organize", Clerk: "mail", Phase: KernelParked, Retry: true, Attempt: 1, PlanStatus: KernelPlanActive},
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
	want := "Running. 2 may have happened (post/web, organize/mail), 1 waiting to run, 0 awaiting a decision."
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
	if m == nil || !strings.Contains(req, "organize on mail") || !strings.Contains(req, "may go twice") || strings.Contains(req, "post") {
		t.Fatalf("request %q", req)
	}
	if got := d.Owner().Handle(ctx, owner, "YES "+m[1]+" "+m[2]); len(got) != 1 || got[0] != "Approved "+m[1]+"." {
		t.Fatalf("approve: %q", got)
	}
	d.retry.running.Wait()
	if got, want := nextText(t, phone), "Retry "+m[1]+": organize on mail will be tried again; it may go twice. Text STATUS to see how it ends."; got != want {
		t.Fatalf("outcome %q, want %q", got, want)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.retried) != 1 || k.retried[0] != "p2/1" {
		t.Fatalf("the kernel retried %q, want p2/1", k.retried)
	}
}

// listed is items without its error, for tests of what RETRY offers.
func (r *retrier) listed() []ownerch.Item {
	items, _ := r.items()
	return items
}

// Two RETRY asks about one parked step each name the attempt they read
// (CH-10): approving the first retries it; once it has been sent again and
// re-parked, approving the second, older ask sends the attempt that ask
// read, the kernel refuses it, nothing is retried, and the owner is told
// in fixed words. Revert mutant: re-read the attempt at approval time
// (from Status), and the older ask retries the step a third time.
func TestAnOlderKernelRETRYAskRetriesNothing(t *testing.T) {
	k := &fakeKernel{steps: kernelSteps()}
	d, phone := withKernelChannel(t, k)
	var told []string
	d.retry.mu.Lock()
	d.retry.inform = func(s string) error { told = append(told, s); return nil }
	d.retry.mu.Unlock()
	ctx := context.Background()
	var asks [][]string
	for range 2 {
		if got := d.Owner().Handle(ctx, owner, "RETRY"); len(got) != 0 {
			t.Fatalf("RETRY replies %q", got)
		}
		asks = append(asks, retryCodeRe.FindStringSubmatch(nextText(t, phone)))
	}
	if asks[0] == nil || asks[1] == nil || asks[0][1] == asks[1][1] {
		t.Fatalf("two asks: %q", asks)
	}
	d.Owner().Handle(ctx, owner, "YES "+asks[0][1]+" "+asks[0][2])
	d.retry.running.Wait()
	if len(told) != 1 || !strings.Contains(told[0], "will be tried again") {
		t.Fatalf("first approval: %q", told)
	}
	// The redo is sent, fails its checks and parks again at attempt 2.
	k.set(func(k *fakeKernel) { k.steps[1].Attempt = 2 })
	if got := d.Owner().Handle(ctx, owner, "YES "+asks[1][1]+" "+asks[1][2]); len(got) != 1 || got[0] != "Approved "+asks[1][1]+"." {
		t.Fatalf("second approve: %q", got)
	}
	d.retry.running.Wait()
	want := "Retry " + asks[1][1] + " refused: it was sent again since I asked you. Organize on mail was not tried again; text RETRY later."
	if len(told) != 2 || told[1] != want {
		t.Fatalf("older approval: %q, want %q", told, want)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.retried) != 1 || !slices.Equal(k.attempts, []int{1, 1}) {
		t.Fatalf("retried %q with attempts %v, want one retry and both asks at attempt 1", k.retried, k.attempts)
	}
}

// A kernel whose steps cannot be read is named on RETRY, never answered
// "Nothing to retry." (KRN-7); a kernel waiting for setup holds no steps,
// as STATUS reads it, so it is not named. Revert mutants: drop the Status
// error, and the unread kernel answers "Nothing to retry."; drop the
// setup check, and a setup-only box says part of it is not answering.
func TestRETRYNamesAKernelThatCannotBeRead(t *testing.T) {
	for _, c := range []struct {
		name   string
		set    func(*fakeKernel)
		unread bool
	}{
		{"steps unread", func(k *fakeKernel) { k.unlisted = true }, true},
		{"down", func(k *fakeKernel) { k.down = true }, true},
		{"waiting for setup", func(k *fakeKernel) { k.setup = true }, false},
	} {
		k := &fakeKernel{}
		c.set(k)
		d, _ := withKernelChannel(t, k)
		if _, err := d.retry.items(); (err != nil) != c.unread {
			t.Fatalf("%s: items error %v", c.name, err)
		}
		got := d.Owner().Handle(context.Background(), owner, "RETRY")
		if len(got) != 1 || strings.HasPrefix(got[0], "Part of me is not answering") != c.unread || (!c.unread && got[0] != "Nothing to retry.") {
			t.Fatalf("%s: RETRY replies %q", c.name, got)
		}
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
		for _, it := range d.retry.listed() {
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
		{KernelRefused{Text: "kernel: no parked step of a live plan there to retry"}, "Retry B1 refused: it is no longer waiting for a retry. Organize on mail was not tried again; text RETRY later."},
		{KernelRefused{Text: "kernel: the step cannot be sent again now: stopped: stop is in force"}, "Retry B1 refused: STOP is on. Organize on mail was not tried again; text RETRY later."},
		{KernelRefused{Text: "kernel: the step cannot be sent again now: revoked: x"}, "Retry B1 refused: my checks refused it. Organize on mail was not tried again; text RETRY later."},
		{ErrKernelLost, "Retry B1: I could not tell whether organize on mail will be tried again. Text STATUS to see; text RETRY to ask again."},
		{errors.New("unreachable"), "Retry B1 refused: it could not be started. Organize on mail was not tried again; text RETRY later."},
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
		{KernelStep{Verb: "organize", Clerk: "mail"}, low, ownerch.Low},
		{KernelStep{Verb: "organize", Clerk: "mail"}, ownerch.Limits{AmountLimit: 1 << 40, ExcludedVerbs: []string{"organize"}}, ownerch.High},
		{KernelStep{Verb: "send", Clerk: "mail", Recipient: "a@example.test"}, low, ownerch.High},
		{KernelStep{Verb: "pay", Clerk: "bank", Money: true, Amount: 5}, low, ownerch.High},
	} {
		it := kernelItem(c.s, "")
		if got := ownerch.Classify(it.Facts, c.lim, it.Facts.RecipientSince); got != c.want {
			t.Errorf("%+v: tier %v, want %v", c.s, got, c.want)
		}
	}
	if it := kernelItem(KernelStep{Verb: "pay", Clerk: "bank", Money: true, Amount: 1250}, ""); it.Amount != "1250 minor units" || it.Facts.Kind != ownerch.MoneyRetry {
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
	a := kernelAsk(s, "")
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

// Every verb's RETRY line takes at least its class's tier (KRN-4, CH-10):
// with no money and no recipient, only a reversible or low-class verb may
// be approved by a texted code; a high-class verb, or one key does not
// know, takes the code generator's, and a secret's is a SecretReveal as on
// the journal's path (#3080 Security blocker 1).
func TestEveryKernelVerbsRETRYTakesItsClasssTier(t *testing.T) {
	limits := ownerch.Limits{AmountLimit: 1 << 40}
	verbs := []key.Verb{key.Read, key.Fetch, key.Draft, key.Organize, key.Trash, key.Unsubscribe, key.Send, key.Post,
		key.Buy, key.Share, key.DeleteRemote, key.ChangeAccount, key.RevealOrCreateSecret, key.Actuate,
		key.ActuatePhysical, key.Present, "no-such-verb"}
	for _, v := range verbs {
		cls, known := key.ClassOf(v)
		want := ownerch.High
		if known && cls != key.IrreversibleHigh {
			want = ownerch.Low
		}
		it := kernelItem(KernelStep{Plan: "p", Verb: string(v), Clerk: "c", Phase: KernelParked, Retry: true}, "")
		if got := ownerch.Classify(it.Facts, limits, it.Facts.RecipientSince); got != want {
			t.Errorf("%s (class %d, known %v): tier %v, want %v", v, cls, known, got, want)
		}
		if (v == key.RevealOrCreateSecret) != (it.Facts.Kind == ownerch.SecretReveal) {
			t.Errorf("%s: kind %v", v, it.Facts.Kind)
		}
	}
}

// A parked kernel step's RETRY line names when it was first tried, as the
// journal's does (#3079, CH-12).
func TestAKernelRETRYLineNamesWhenTheStepWasFirstTried(t *testing.T) {
	steps := kernelSteps()
	steps[1].SentAt = time.Date(2026, 10, 13, 14, 2, 0, 0, time.Local).UnixMilli()
	k := &fakeKernel{steps: steps}
	d, phone := withKernelChannel(t, k)
	if got := d.Owner().Handle(context.Background(), owner, "RETRY"); len(got) != 0 {
		t.Fatalf("RETRY replies %q", got)
	}
	req := nextText(t, phone)
	if !regexp.MustCompile(`organize on mail,[^.]* may go twice, first tried \d\d:\d\d Oct 1[34]`).MatchString(req) ||
		strings.Count(req, "may go twice") != 1 {
		t.Fatalf("request %q", req)
	}
}

// A kernel step's amount reads in the household's currency, set in
// agentosd's config, not in minor units (#3079, card
// cmsg_01R91wiieBzMSvPKFsAJVvuKUgXeiUr5Cgukv7ac35d1X9).
func TestAKernelRETRYLineNamesItsAmountInTheHouseholdsCurrency(t *testing.T) {
	for _, c := range []struct {
		amount   int64
		currency string
		want     string
	}{
		{1250, "EUR", "12.50 EUR"}, {5, "USD", "0.05 USD"}, {0, "GBP", "0.00 GBP"}, {1250, "JPY", "1250 JPY"},
		{1250, "KWD", "1.250 KWD"}, {1250, "", "1250 minor units"}, {-1, "EUR", "-1 minor units"},
		{1250, "CLF", "1250 minor units"}, {1250, "XAU", "1250 minor units"},
	} {
		if got := amountText(c.amount, c.currency); got != c.want {
			t.Errorf("%d %q: %q, want %q", c.amount, c.currency, got, c.want)
		}
	}
	steps := kernelSteps()
	steps[1].Money, steps[1].Amount = true, 1250
	k := &fakeKernel{steps: steps}
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	carrier := modem.NewCarrier()
	phone := carrier.Line(owner)
	_, d := startWith(t, dir, func(c *Config) {
		c.Kernel, c.Auth, c.OwnerState, c.Modem = k, nil, filepath.Join(dir, "owner.json"), carrier.Line("+15550000009")
		c.Currency = "EUR"
	})
	if got := d.Owner().Handle(context.Background(), owner, "RETRY"); len(got) != 0 {
		t.Fatalf("RETRY replies %q", got)
	}
	if req := nextText(t, phone); !strings.Contains(req, "12.50 EUR") || strings.Contains(req, "minor units") {
		t.Fatalf("request %q", req)
	}
}

// A currency that is not an ISO 4217 code of a currency in circulation is
// refused at start: nothing else reaches the owner's texts, and no code
// whose minor unit is 4 or undefined (CLF, UYW, XAU, XDR) reads at the
// wrong scale (#3141 Security 1).
func TestABadCurrencyIsRefusedAtStart(t *testing.T) {
	for _, cur := range []string{"eur", "EURO", "E R", "€", "EUX", "CLF", "UYW", "XAU", "XDR", "XXX"} {
		if _, err := Run(context.Background(), Config{OwnerNumber: owner, Currency: cur}); err == nil || !strings.Contains(err.Error(), "ISO 4217") {
			t.Errorf("currency %q: %v", cur, err)
		}
	}
}
