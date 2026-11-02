package main

import (
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// REQ: HW-10, ONB-3. The console is a public CI log, so a diag quotes
// whole journal lines only from the units ASSUMPTIONS E8 names: the page,
// its claim move and the modem bridge. agentosd and the vault process hold
// what E8 never prints (G1-e2e-later #1740 item 2), so claimDiag and
// modemDiag give only their unit states, and journalTail refuses them.
func TestDiagsQuoteNoAgentosdOrVaultJournal(t *testing.T) {
	var calls [][]string
	defer func(o func(string, ...string) string) { output = o }(output)
	output = func(name string, args ...string) string {
		calls = append(calls, append([]string{name}, args...))
		if name == "journalctl" {
			return "a journal line\n"
		}
		return "active\nrunning\n"
	}
	journalUnits := func() (units []string) {
		for _, c := range calls {
			if c[0] != "journalctl" {
				continue
			}
			for i, a := range c {
				if a == "-u" && i+1 < len(c) {
					units = append(units, c[i+1])
				}
			}
		}
		return units
	}
	shown := func() (units []string) {
		for _, c := range calls {
			if c[0] == "systemctl" {
				for _, a := range c[1:] {
					if strings.HasSuffix(a, ".service") {
						units = append(units, a)
					}
				}
			}
		}
		return units
	}
	for _, tc := range []struct {
		name    string
		diag    func() string
		journal []string
		states  []string
	}{
		{"claim", func() string { return claimDiag("ABCD-EFGH") },
			[]string{"agentos-localui-claim.service", "agentos-localui.service"},
			[]string{"agentosd.service", "agentos-egress.service"}},
		{"modem", modemDiag, []string{"agentos-modem.service"}, []string{"agentosd.service"}},
	} {
		calls = nil
		got := tc.diag()
		if u := journalUnits(); !slices.Equal(u, tc.journal) {
			t.Errorf("%s diag quotes the journals of %v, want %v", tc.name, u, tc.journal)
		}
		for _, s := range tc.states {
			if !slices.Contains(shown(), s) {
				t.Errorf("%s diag does not give %s's unit state (shows %v)", tc.name, s, shown())
			}
		}
		if !strings.Contains(got, "a journal line") {
			t.Errorf("%s diag drops the quotable lines: %q", tc.name, got)
		}
	}
	for _, u := range []string{"agentosd.service", "agentos-egress.service", "agentos-egress-setup.service"} {
		calls = nil
		got := journalTail(20, "agentos-localui.service", u)
		if len(calls) != 0 || strings.Contains(got, "a journal line") {
			t.Errorf("journalTail read %s's journal: calls %v, got %q", u, calls, got)
		}
	}
}

type answer func(*http.Request) (*http.Response, error)

func (f answer) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// REQ: ONB-3. A request that setup answers with something other than the
// expected status says where setup stood: the page's step heading and its
// error line (G1-e2e-later #1740 item 1, G1-e2e-tidy #1715 item 3), never
// only the status; a request with no answer names its error.
func TestFailedRequestsSayWhereSetupStood(t *testing.T) {
	page := `<h2>4. Store your recovery key</h2><p class="err">Tick the box to say it is stored.</p>`
	d := &driver{phone: &http.Client{Transport: answer(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(page)), Header: http.Header{}, Request: r}, nil
	})}}
	err := d.recovery()
	want := `POST /setup/recovery 200 at "4. Store your recovery key" saying "Tick the box to say it is stored."`
	if err == nil || err.Error() != want {
		t.Fatalf("recovery error\n %v\nwant\n %s", err, want)
	}
	if got := answerErr("GET /status", 0, nil, errors.New("connection refused")).Error(); got != "GET /status 0: connection refused" {
		t.Fatalf("transport error line %q", got)
	}
}
