package accounts

import (
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// REQ: TN-account-plan-3, TN-account-plan-4, TN-account-plan-5

func household(t *testing.T) *Table {
	t.Helper()
	b, err := os.ReadFile("testdata/household.json")
	if err != nil {
		t.Fatal(err)
	}
	tab, err := Load(b)
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

// The shipped table loads under every rule, and no provider it names
// appears in the package's code: providers are data (TN-account-plan-3).
func TestKnownTableLoadsAndValidates(t *testing.T) {
	tab, err := Known()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(known); err != nil {
		t.Fatal(err)
	}
	srcs, _ := filepath.Glob("*.go")
	for _, f := range srcs {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range tab.Entries() {
			if e.Group != "account" {
				continue
			}
			for _, s := range append([]string{e.Name}, append(e.Domains, e.SignIn...)...) {
				if strings.Contains(string(b), s) {
					t.Errorf("%s names the provider %q outside the table", f, s)
				}
			}
		}
	}
}

// One bad table per rule, each refused; a good one beside them loads.
func TestKnownTableRefusesUnknownFieldsAndEachBrokenRule(t *testing.T) {
	const base = `{"id":"payment-card","name":"Card","kind":"money","group":"payment","route":"none"},
		{"id":"payment-wallet","name":"Wallet","kind":"money","group":"payment","route":"none"},
		{"id":"mailbox","name":"Mailbox","kind":"mail","group":"mailbox","route":"none"}`
	with := func(extra string) string { return "[" + base + extra + "]" }
	if _, err := Load([]byte(with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"oauth","narrower":true,"domains":["a.test","xn--bcher-kva.test"],"signin":["login.a.test"]}`))); err != nil {
		t.Fatalf("a good table: %v", err)
	}
	for name, table := range map[string]string{
		"unknown field":          with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"none","recovery":"x"}`),
		"duplicate id":           with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"none"},{"id":"a","name":"B","kind":"other","group":"account","route":"none"}`),
		"shared domain":          with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"none","domains":["a.test"]},{"id":"b","name":"B","kind":"other","group":"account","route":"none","domains":["a.test"]}`),
		"nested domain":          with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"none","domains":["a.test"]},{"id":"b","name":"B","kind":"other","group":"account","route":"none","domains":["x.a.test"]}`),
		"upper-case domain":      with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"none","domains":["A.test"]}`),
		"U-label domain":         with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"none","domains":["bücher.test"]}`),
		"one-label domain":       with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"none","domains":["test"]}`),
		"signin with scheme":     with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"oauth","signin":["https://a.test"]}`),
		"signin with port":       with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"oauth","signin":["a.test:443"]}`),
		"signin with path":       with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"oauth","signin":["a.test/login"]}`),
		"IMAP narrower":          with(`,{"id":"a","name":"A","kind":"mail","group":"account","route":"imap","narrower":true}`),
		"unknown kind":           with(`,{"id":"a","name":"A","kind":"bank","group":"account","route":"none"}`),
		"unknown group":          with(`,{"id":"a","name":"A","kind":"other","group":"extra","route":"none"}`),
		"unknown route":          with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"sms"}`),
		"no name":                with(`,{"id":"a","name":" ","kind":"other","group":"account","route":"none"}`),
		"bad device kind":        with(`,{"id":"a","name":"A","kind":"other","group":"account","route":"none","implied_by":["EV Charger"]}`),
		"trailing data":          with(``) + `[]`,
		"missing card":           strings.Replace(with(``), `"id":"payment-card"`, `"id":"card"`, 1),
		"missing wallet":         strings.Replace(with(``), `"id":"payment-wallet"`, `"id":"wallet"`, 1),
		"missing mailbox":        strings.Replace(with(``), `"id":"mailbox"`, `"id":"inbox"`, 1),
		"mailbox in wrong group": strings.Replace(with(``), `"group":"mailbox"`, `"group":"account"`, 1),
	} {
		if _, err := Load([]byte(table)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func ids(plan []Item) []string {
	var out []string
	for _, it := range plan {
		out = append(out, it.ID)
	}
	return out
}

// Order is card, wallet, mailbox, then table order, whatever the input
// order; only the card and at-home or ongoing items are preselected; IMAP is
// Full power and a narrower route carries the advice (TN-account-plan-4).
func TestBuildOrderPreselectAndLabels(t *testing.T) {
	tab := household(t)
	domains := []string{"router.test", "imapmail.test", "mail.shop.test", "bank.test", "unknown.test", "notbank.test"}
	plan := Build(tab, domains, nil)
	want := []string{CardID, WalletID, MailboxID, "bank", "shop", "mail-imap", "router"}
	if got := ids(plan); !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	rev := slices.Clone(domains)
	slices.Reverse(rev)
	if !reflect.DeepEqual(Build(tab, rev, nil), plan) {
		t.Fatal("the plan depends on the order of the domains")
	}
	pre := map[string]bool{CardID: true, WalletID: true, MailboxID: false, "bank": true, "shop": false, "mail-imap": false, "router": true}
	for _, it := range plan {
		if it.Preselected != pre[it.ID] {
			t.Errorf("%s preselected = %v, want %v", it.ID, it.Preselected, pre[it.ID])
		}
		wantLabel, wantAdvice := LabelFull, ""
		if it.ID == "bank" {
			wantLabel, wantAdvice = LabelNarrower, AdviceNarrower
		}
		if it.Label != wantLabel || it.Advice != wantAdvice {
			t.Errorf("%s label %q advice %q", it.ID, it.Label, it.Advice)
		}
		src := FromMail
		if slices.Contains([]string{CardID, WalletID, MailboxID}, it.ID) {
			src = Always
		}
		if it.Source != src {
			t.Errorf("%s source %q, want %q", it.ID, it.Source, src)
		}
	}
	// The A22 fence: an IMAP entry is Full power even if the struct says
	// narrower (the validator refuses that table; item must not trust it).
	if it := item(Entry{ID: "x", Route: "imap", Narrower: true}, FromMail); it.Label != LabelFull || it.Advice != "" {
		t.Fatalf("IMAP item labelled %q", it.Label)
	}
	if Build(nil, domains, nil) != nil {
		t.Fatal("a plan without a table")
	}
	// With no mail and no devices, the three fixed items only.
	if got := ids(Build(tab, nil, nil)); !slices.Equal(got, []string{CardID, WalletID, MailboxID}) {
		t.Fatalf("empty plan = %v", got)
	}
}

// A device-implied item appears once, tagged mail when mail found it too;
// an unknown kind implies nothing.
func TestBuildDeviceImpliedOnce(t *testing.T) {
	tab := household(t)
	plan := Build(tab, nil, []string{"thermostat", "ev-charger", "toaster"})
	if got := ids(plan); !slices.Equal(got, []string{CardID, WalletID, MailboxID, "power", "airline"}) {
		t.Fatalf("plan = %v", got)
	}
	for _, it := range plan[3:] {
		if it.Source != FromDevice {
			t.Errorf("%s source %q", it.ID, it.Source)
		}
	}
	plan = Build(tab, []string{"bills.power.test"}, []string{"ev-charger", "thermostat"})
	n := 0
	for _, it := range plan {
		if it.ID == "power" {
			n++
			if it.Source != FromMail {
				t.Errorf("power source %q, want mail", it.Source)
			}
		}
	}
	if n != 1 {
		t.Fatalf("power appears %d times", n)
	}
	if got := ids(Build(tab, nil, []string{"toaster"})); len(got) != 3 {
		t.Fatalf("an unknown kind implied %v", got)
	}
}

// strs is every string field of v.
func strs(v any) []string {
	var out []string
	rv := reflect.ValueOf(v)
	for i := range rv.NumField() {
		if rv.Field(i).Kind() == reflect.String {
			out = append(out, rv.Field(i).String())
		}
	}
	return out
}

// No plan string carries input bytes: a canary in an authenticated domain,
// under a known one or not, and in a device kind, reaches no item.
func TestPlanCarriesNoMailBytes(t *testing.T) {
	const canary = "canary7q"
	plan := Build(household(t), []string{canary + ".bank.test", canary + ".test", "x." + canary + ".shop.test"},
		[]string{canary, "thermostat"})
	if len(plan) < 5 {
		t.Fatalf("plan = %v", ids(plan))
	}
	known := map[string]bool{LabelFull: true, LabelNarrower: true, AdviceNarrower: true, "": true}
	for _, e := range household(t).Entries() {
		known[e.ID], known[e.Name], known[e.Kind], known[e.Group] = true, true, true, true
	}
	for _, s := range []Source{FromMail, FromDevice, Always} {
		known[string(s)] = true
	}
	for _, it := range plan {
		for _, s := range strs(it) {
			if strings.Contains(s, canary) || !known[s] {
				t.Errorf("item %s carries %q, not the table's or a constant", it.ID, s)
			}
		}
	}
}

// A Listing is exactly a service name and a kind; Unconnected lists the
// plan items not connected, and never an untaken card, wallet or mailbox
// offer (Source Always, PLN-7, #3237): connected or not, none is listed.
func TestUnconnectedCarriesOnlyNameAndKind(t *testing.T) {
	ty := reflect.TypeOf(Listing{})
	if ty.NumField() != 2 || ty.Field(0).Name != "Service" || ty.Field(1).Name != "Kind" {
		t.Fatalf("Listing has fields %v", reflect.VisibleFields(ty))
	}
	plan := Build(household(t), []string{"bank.test", "shop.test"}, nil)
	want := []Listing{{"Fake shop", "shopping"}}
	for _, connected := range [][]string{{CardID, "bank"}, {"bank"}} {
		if got := Unconnected(plan, connected); !reflect.DeepEqual(got, want) {
			t.Fatalf("Unconnected(%v) = %v, want %v", connected, got, want)
		}
	}
	var always int
	for _, it := range plan {
		if it.Source == Always {
			always++
		}
	}
	if always != 3 {
		t.Fatalf("the plan holds %d Always offers, want the card, wallet and mailbox", always)
	}
	if NotConnected != "exists, not connected" {
		t.Fatal("wording changed")
	}
}

func TestSignInAllowedRefusesUndeclaredHosts(t *testing.T) {
	bank, _ := household(t).Entry("bank")
	for raw, want := range map[string]bool{
		"https://login.bank.test/oauth?x=1":  true,
		"http://login.bank.test/oauth":       false,
		"https://bank.test/oauth":            false,
		"https://login.bank.test.evil.test/": false,
		"https://evil.test/login.bank.test":  false,
		"https://login.bank.test:8443/oauth": false,
		"https://login.bank.test:443/oauth":  false,
		"https://user@login.bank.test/oauth": false,
		"https://LOGIN.BANK.TEST/oauth":      false,
		"javascript:alert(1)":                false,
		"https:login.bank.test":              false,
		"//login.bank.test/oauth":            false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := bank.SignInAllowed(u); got != want {
			t.Errorf("SignInAllowed(%s) = %v, want %v", raw, got, want)
		}
	}
	if bank.SignInAllowed(nil) {
		t.Fatal("nil allowed")
	}
}
