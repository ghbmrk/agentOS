package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-12, REC-4, CH-7

// apUpBox is a /var/lib/agentos with the card's network written, as
// agentosd's hand-off writes it.
func apUpBox(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ap-net.json")
	rotateWiFiFile(t, p, "QRST-UVWX-YZ23-4567")
	return p
}

func rotateWiFiFile(t *testing.T, p, password string) {
	t.Helper()
	m, err := apnet.Network{SSID: "AgentOS-AB2C", Password: password}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := durable.WriteFile(p, m, 0o600); err != nil {
		t.Fatal(err)
	}
}

// failUp counts n failures of the current network, as agentos-ap does
// once per failing restart.
func failUp(t *testing.T, p string, n int) {
	t.Helper()
	for range n {
		if _, err := apnet.RecordUpFailure(p); err != nil {
			t.Fatal(err)
		}
	}
}

type texts struct {
	sent []string
	err  error
}

func (x *texts) inform(s string) error {
	if x.err != nil {
		return x.err
	}
	x.sent = append(x.sent, s)
	return nil
}

func check(t *testing.T, p string, x *texts) error {
	t.Helper()
	return apUpCheck(p, x.inform)
}

// #1525 acceptance, agentosd's half: an access point whose Up keeps
// failing on the rotated network gets the owner exactly one fixed text
// past the bound, however often it is looked at, and none below it.
func TestAFailingUpTextsTheOwnerOnce(t *testing.T) {
	p := apUpBox(t)
	x := &texts{}
	failUp(t, p, apnet.UpFailureBound-1)
	for range 3 {
		if err := check(t, p, x); err != nil {
			t.Fatal(err)
		}
	}
	if len(x.sent) != 0 {
		t.Fatalf("texted below the bound: %q", x.sent)
	}
	failUp(t, p, 1)
	for range 3 {
		if err := check(t, p, x); err != nil {
			t.Fatal(err)
		}
	}
	failUp(t, p, 4)
	if err := check(t, p, x); err != nil {
		t.Fatal(err)
	}
	if len(x.sent) != 1 || x.sent[0] != apUpText {
		t.Fatalf("sent %q, want the fixed text once", x.sent)
	}
	fi, err := os.Stat(apUpNoticedPath(p))
	if err != nil || fi.Mode().Perm() != 0o600 || filepath.Dir(apUpNoticedPath(p)) != filepath.Dir(p) {
		t.Fatalf("notice record: %v %v", fi, err)
	}
}

// #1525: once per rotation. A new network that fails past the bound
// texts again; a record left from a network since replaced does not.
func TestEachRotationIsTextedOnceAndAStaleRecordIsNot(t *testing.T) {
	p := apUpBox(t)
	x := &texts{}
	failUp(t, p, apnet.UpFailureBound)
	if err := check(t, p, x); err != nil {
		t.Fatal(err)
	}
	rotateWiFiFile(t, p, "BCDF-GHJK-LMNP-QRST")
	if err := check(t, p, x); err != nil {
		t.Fatal(err)
	}
	if len(x.sent) != 1 {
		t.Fatalf("a record of the replaced network texted: %d", len(x.sent))
	}
	failUp(t, p, apnet.UpFailureBound)
	for range 2 {
		if err := check(t, p, x); err != nil {
			t.Fatal(err)
		}
	}
	if len(x.sent) != 2 {
		t.Fatalf("%d texts, want one per rotation", len(x.sent))
	}
}

// #1525: a text that does not go is tried again at the next look, and
// counts only once it went.
func TestAFailedTextIsTriedAgain(t *testing.T) {
	p := apUpBox(t)
	x := &texts{err: errors.New("no owner channel")}
	failUp(t, p, apnet.UpFailureBound)
	if err := check(t, p, x); err == nil {
		t.Fatal("a failed text was not reported")
	}
	if _, err := os.Stat(apUpNoticedPath(p)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("noted before it went: %v", err)
	}
	x.err = nil
	for range 2 {
		if err := check(t, p, x); err != nil {
			t.Fatal(err)
		}
	}
	if len(x.sent) != 1 {
		t.Fatalf("%d texts after the retry, want one", len(x.sent))
	}
}

// #1525: no network written (setup not done) and no record are quiet.
func TestNoRecordIsQuiet(t *testing.T) {
	x := &texts{}
	p := filepath.Join(t.TempDir(), "ap-net.json")
	if err := check(t, p, x); err != nil || len(x.sent) != 0 {
		t.Fatalf("%v %q", err, x.sent)
	}
	p = apUpBox(t)
	if err := check(t, p, x); err != nil || len(x.sent) != 0 {
		t.Fatalf("%v %q", err, x.sent)
	}
}

// CH-12: the text is GSM-7 in one segment, names the step, points only at
// the newest card (never the previous password), and names no internal
// part.
func TestTheAPUpTextIsPlain(t *testing.T) {
	if n, gsm := modem.Segments(apUpText); n != 1 || !gsm {
		t.Fatalf("%d segments, GSM-7 %v", n, gsm)
	}
	low := strings.ToLower(apUpText)
	for _, w := range []string{"restart the box", "newest owner card"} {
		if !strings.Contains(low, w) {
			t.Fatalf("missing %q", w)
		}
	}
	for _, w := range []string{"hostapd", "agentos-ap", "ap-net", "json", "old card", "previous", "error"} {
		if strings.Contains(low, w) {
			t.Fatalf("names %q", w)
		}
	}
}

// #1525: main starts the watch on the network file it writes, sending
// through the owner channel; without the channel the send fails, so the
// text stays owed.
func TestMainWatchesTheAccessPoint(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "go watchAPUp(ctx, apNetPath, informOwner(d.Owner))") {
		t.Fatal("main does not start the access point watch")
	}
	if err := informOwner(func() *owner.Channel { return nil })(apUpText); err == nil {
		t.Fatal("no owner channel, yet the text went")
	}
}
