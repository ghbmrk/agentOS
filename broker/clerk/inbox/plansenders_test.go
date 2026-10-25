package inbox

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// REQ: TN-account-plan-1, TN-account-plan-2

const planAuthServ = "mx.google.com"

// gmailAR is an Authentication-Results field in the shape Gmail writes:
// header.i and no header.d (#3189).
func gmailAR(dkim, i string) string {
	return "Authentication-Results: mx.google.com;\r\n       dkim=" + dkim + " header.i=@" + i +
		" header.s=s1 header.b=AbCd1234;\r\n       spf=pass (google.com: domain of bounce@" + i +
		" designates 192.0.2.1 as permitted sender) smtp.mailfrom=bounce@" + i +
		";\r\n       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=" + i + "\r\n"
}

// planMail is a mail whose header block is fields, then a From and Subject.
func planMail(from string, fields ...string) string {
	return strings.Join(fields, "") + "From: " + from + "\r\nTo: owner@gmail.test\r\nSubject: Welcome\r\n\r\nsynthetic body\r\n"
}

// TN-account-plan-1, with #2681 item 5's attack shapes.
func TestPlanSenderNeedsTopmostProviderDKIMPass(t *testing.T) {
	for _, c := range []struct {
		name, mail, authServ, want string
	}{
		{"gmail shape, header.i only", planMail("Bank <alerts@bank.test>", gmailAR("pass", "bank.test")), planAuthServ, "bank.test"},
		{"From under header.i's domain", planMail("alerts@news.bank.test", gmailAR("pass", "bank.test")), planAuthServ, "bank.test"},
		{"header.i with a local part", planMail("a@mail.bank.test",
			"Authentication-Results: mx.google.com; dkim=pass header.i=bot@mail.bank.test header.s=s\r\n"), planAuthServ, "mail.bank.test"},
		{"header.d", planMail("a@bank.test", "Authentication-Results: mx.google.com; dkim=pass header.d=bank.test header.s=s\r\n"), planAuthServ, "bank.test"},
		{"authserv-id in another case", planMail("a@bank.test", gmailAR("pass", "bank.test")), "MX.Google.com", "bank.test"},
		{"upper-case domains", planMail("a@BANK.test", gmailAR("pass", "Bank.TEST")), planAuthServ, "bank.test"},
		{"a second, passing pass beside a failing one", planMail("a@bank.test",
			"Authentication-Results: mx.google.com; dkim=fail header.i=@evil.test; dkim=pass header.i=@bank.test\r\n"), planAuthServ, "bank.test"},

		{"empty AuthServ fails closed", planMail("a@bank.test", gmailAR("pass", "bank.test")), "", ""},
		{"blank AuthServ fails closed", planMail("a@bank.test", gmailAR("pass", "bank.test")), "  ", ""},
		{"no Authentication-Results", planMail("a@bank.test"), planAuthServ, ""},
		{"dkim=fail", planMail("a@bank.test", gmailAR("fail", "bank.test")), planAuthServ, ""},
		{"dkim=neutral", planMail("a@bank.test", gmailAR("neutral", "bank.test")), planAuthServ, ""},
		{"a sender's pass below the provider's fail", planMail("a@bank.test",
			gmailAR("fail", "bank.test"), gmailAR("pass", "bank.test")), planAuthServ, ""},
		{"a sender's pass below with no provider field", planMail("a@bank.test",
			"X-Other: 1\r\n", gmailAR("pass", "bank.test")), planAuthServ, "bank.test"},
		{"another authserv-id on top", planMail("a@bank.test",
			"Authentication-Results: mx.evil.test; dkim=pass header.i=@bank.test\r\n", gmailAR("pass", "bank.test")), planAuthServ, ""},
		{"another authserv-id alone", planMail("a@bank.test",
			"Authentication-Results: mx.google.com.evil.test; dkim=pass header.i=@bank.test\r\n"), planAuthServ, ""},
		{"pass in a comment", planMail("a@bank.test",
			"Authentication-Results: mx.google.com; dkim=fail (dkim=pass header.i=@bank.test) header.i=@bank.test\r\n"), planAuthServ, ""},
		{"authserv-id in a comment", planMail("a@bank.test",
			"Authentication-Results: (mx.google.com) mx.evil.test; dkim=pass header.i=@bank.test\r\n"), planAuthServ, ""},
		{"pass in a quoted value", planMail("a@bank.test",
			"Authentication-Results: mx.google.com; dkim=fail header.b=\"x; dkim=pass header.i=@bank.test\"\r\n"), planAuthServ, ""},
		{"From outside header.i", planMail("a@evil.test", gmailAR("pass", "bank.test")), planAuthServ, ""},
		{"From a lookalike suffix", planMail("a@notbank.test", gmailAR("pass", "bank.test")), planAuthServ, ""},
		{"From above d", planMail("a@bank.test", gmailAR("pass", "mail.bank.test")), planAuthServ, ""},
		{"header.d mismatched, header.i matching", planMail("a@bank.test",
			"Authentication-Results: mx.google.com; dkim=pass header.d=evil.test header.i=@bank.test\r\n"), planAuthServ, ""},
		{"header.i with no domain", planMail("a@bank.test",
			"Authentication-Results: mx.google.com; dkim=pass header.i=bank.test\r\n"), planAuthServ, ""},
		{"two From fields", planMail("a@bank.test", gmailAR("pass", "bank.test"), "From: b@bank.test\r\n"), planAuthServ, ""},
		{"two addresses in From", planMail("a@bank.test, b@evil.test", gmailAR("pass", "bank.test")), planAuthServ, ""},
		{"no From", gmailAR("pass", "bank.test") + "\r\nbody\r\n", planAuthServ, ""},
	} {
		if got := PlanSender([]byte(c.mail), c.authServ); got != c.want {
			t.Errorf("%s: PlanSender = %q, want %q", c.name, got, c.want)
		}
	}
}

func planRequests(reqs []string) (lists, gets []string) {
	for _, r := range reqs {
		if strings.Contains(r, "/messages?") {
			lists = append(lists, r)
		} else {
			gets = append(gets, r)
		}
	}
	return lists, gets
}

// TN-account-plan-2: only the two declared plan calls reach the API, with
// no q and no full or raw get; spam and trash are not listed; reading stops
// at PlanMails, newest first.
func TestPlanReaderReadsOnlyDeclaredMetadata(t *testing.T) {
	for _, c := range GmailCalls(GmailBase, "s") {
		if strings.HasPrefix(c.Name, "messages.") && strings.Contains(c.Name, ".plan") &&
			(strings.Contains(c.URL, "q=") || strings.Contains(c.URL, "format=full") || strings.Contains(c.URL, "format=raw") ||
				strings.Contains(c.URL, "includeSpamTrash")) {
			t.Fatalf("plan call %s: %s", c.Name, c.URL)
		}
	}
	box, srv := newGmail(t)
	oldest := srv.Deliver([]byte(planMail("a@old.test", gmailAR("pass", "old.test"))))
	srv.Deliver([]byte(planMail("a@spam.test", gmailAR("pass", "spam.test"))), "SPAM")
	srv.Deliver([]byte(planMail("a@trash.test", gmailAR("pass", "trash.test"))), "TRASH")
	srv.Deliver([]byte(planMail("a@archived.test", gmailAR("pass", "archived.test"))))
	for i := 1; i < PlanMails; i++ {
		srv.Deliver([]byte(planMail("a@bank.test", gmailAR("pass", "bank.test"))), "INBOX")
	}
	got, err := box.PlanSenders(context.Background(), planAuthServ)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"archived.test", "bank.test"}) {
		t.Fatalf("PlanSenders = %v", got)
	}
	lists, gets := planRequests(srv.Requests())
	if len(gets) != PlanMails {
		t.Fatalf("%d gets, want %d", len(gets), PlanMails)
	}
	for _, r := range lists {
		if r != "GET /gmail/v1/users/me/messages?maxResults=500" && !strings.HasPrefix(r, "GET /gmail/v1/users/me/messages?maxResults=500&pageToken=") {
			t.Errorf("list request %s", r)
		}
	}
	for _, r := range gets {
		if !strings.HasSuffix(r, "?format=metadata&metadataHeaders=From&metadataHeaders=Authentication-Results") ||
			strings.Contains(r, "/"+oldest+"?") {
			t.Errorf("get request %s", r)
		}
	}
	if len(lists) != 2 {
		t.Fatalf("%d list pages, want 2: %v", len(lists), lists)
	}
}

// A listing that keeps naming a next page ends at gPlanPagesMax.
func TestPlanReaderStopsAtThePageCap(t *testing.T) {
	box, srv := newGmail(t)
	defer func(n int) { gPlanPagesMax = n }(gPlanPagesMax)
	gPlanPagesMax = 1
	for range 501 {
		srv.Deliver([]byte(planMail("a@bank.test", gmailAR("pass", "bank.test"))))
	}
	if _, err := box.PlanSenders(context.Background(), planAuthServ); err != nil {
		t.Fatal(err)
	}
	lists, gets := planRequests(srv.Requests())
	if len(lists) != 1 || len(gets) != 500 {
		t.Fatalf("%d lists and %d gets", len(lists), len(gets))
	}
}

func TestPlanReaderSkipsAMailGoneBetweenListAndGet(t *testing.T) {
	box, srv := newGmail(t)
	gone := srv.Deliver([]byte(planMail("a@gone.test", gmailAR("pass", "gone.test"))))
	srv.Deliver([]byte(planMail("a@bank.test", gmailAR("pass", "bank.test"))))
	srv.Fail("/messages/"+gone, 404)
	got, err := box.PlanSenders(context.Background(), planAuthServ)
	if err != nil || !slices.Equal(got, []string{"bank.test"}) {
		t.Fatalf("PlanSenders = %v, %v", got, err)
	}
}

// A refused refresh is grant death: no domains, the typed reason (A22).
func TestPlanReaderReportsGrantDeath(t *testing.T) {
	box, srv := newGmail(t)
	srv.Deliver([]byte(planMail("a@bank.test", gmailAR("pass", "bank.test"))))
	srv.RefuseGrant()
	got, err := box.PlanSenders(context.Background(), planAuthServ)
	if !errors.Is(err, ErrReconnect) || got != nil {
		t.Fatalf("PlanSenders = %v, %v; want nil, %v", got, err, ErrReconnect)
	}
}

// Only domains leave the reader: a canary display name, local part and
// subject reach nothing it returns.
func TestPlanReaderReturnsOnlyDomains(t *testing.T) {
	const canary = "canary4z"
	box, srv := newGmail(t)
	srv.Deliver([]byte(gmailAR("pass", "bank.test") + "From: \"" + canary + " Bank\" <" + canary + "@bank.test>\r\nSubject: " +
		canary + "\r\nDate: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\n" + canary + "\r\n"))
	got, err := box.PlanSenders(context.Background(), planAuthServ)
	if err != nil || !slices.Equal(got, []string{"bank.test"}) {
		t.Fatalf("PlanSenders = %v, %v", got, err)
	}
	if strings.Contains(strings.Join(got, " "), canary) {
		t.Fatal("a canary reached the result")
	}
}

// A misanswering provider (#3197 item 2): each defence on the listing and
// the get stops the answer it is for, so no test passes without it.
func TestPlanReaderRefusesAMisansweringProvider(t *testing.T) {
	t.Run("headers that name another mail", func(t *testing.T) {
		box, srv := newGmail(t)
		srv.Deliver([]byte(planMail("a@bank.test", gmailAR("pass", "bank.test"))))
		srv.OtherID(true)
		if got, err := box.PlanSenders(context.Background(), planAuthServ); err == nil || got != nil {
			t.Fatalf("PlanSenders = %v, %v; want an error", got, err)
		}
	})
	t.Run("an id outside Gmail's form", func(t *testing.T) {
		box, srv := newGmail(t)
		srv.Deliver([]byte(planMail("a@bank.test", gmailAR("pass", "bank.test"))))
		srv.Pad("bad.id")
		if got, err := box.PlanSenders(context.Background(), planAuthServ); err == nil || got != nil {
			t.Fatalf("PlanSenders = %v, %v; want an error", got, err)
		}
		for _, r := range srv.Requests() {
			if strings.Contains(r, "bad.id") {
				t.Fatalf("the malformed id reached the API: %s", r)
			}
		}
	})
	t.Run("a page larger than maxResults", func(t *testing.T) {
		box, srv := newGmail(t)
		id := srv.Deliver([]byte(planMail("a@bank.test", gmailAR("pass", "bank.test"))))
		srv.Pad(slices.Repeat([]string{id}, PlanMails)...)
		got, err := box.PlanSenders(context.Background(), planAuthServ)
		if err != nil || !slices.Equal(got, []string{"bank.test"}) {
			t.Fatalf("PlanSenders = %v, %v", got, err)
		}
		if lists, gets := planRequests(srv.Requests()); len(lists) != 1 || len(gets) != PlanMails {
			t.Fatalf("%d lists and %d gets, want 1 and %d", len(lists), len(gets), PlanMails)
		}
	})
}
