package accounts

import (
	"strings"
	"testing"
)

// REQ: TN-account-plan-3, TN-account-plan-4

// fixedOnly is a table of the card, wallet and mailbox, the mailbox
// claiming mail.test, and one account.
const fixedOnly = `[{"id":"payment-card","name":"Card","kind":"money","group":"payment","route":"none"},
	{"id":"payment-wallet","name":"Wallet","kind":"money","group":"payment","route":"none"},
	{"id":"mailbox","name":"Mailbox","kind":"mail","group":"mailbox","route":"none","domains":["mail.test"]},
	{"id":"a","name":"A","kind":"other","group":"account","route":"none","domains":["a.test"]}]`

// A hostname of 253 characters is the longest a domain may be: it loads,
// and one of 254 is refused (RFC 1035 §2.3.4).
func TestHostnameIsAtMost253(t *testing.T) {
	l63 := strings.Repeat("a", 63)
	h253 := l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 61)
	if len(h253) != 253 || !hostname(h253) {
		t.Fatalf("a %d-character hostname is refused", len(h253))
	}
	if h254 := h253 + "b"; hostname(h254) {
		t.Fatalf("a %d-character hostname is accepted", len(h254))
	}
}

// Build lists the card, the wallet and the mailbox once, as always, even
// when the mail names a domain the mailbox's entry claims.
func TestBuildListsTheFixedItemsOnceWhateverTheMail(t *testing.T) {
	tab, err := Load([]byte(fixedOnly))
	if err != nil {
		t.Fatal(err)
	}
	plan := Build(tab, []string{"mail.test", "a.test"}, nil)
	var got []string
	for _, it := range plan {
		got = append(got, it.ID+"/"+string(it.Source))
	}
	want := []string{CardID + "/" + string(Always), WalletID + "/" + string(Always), MailboxID + "/" + string(Always), "a/" + string(FromMail)}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("Build = %v, want %v", got, want)
	}
}

// Facts with no table gives no node, whatever the plan; a plan item the
// table has no entry for gives no node either.
func TestFactsSkipsWhatTheTableLacks(t *testing.T) {
	plan := []Item{{ID: "a", Source: FromMail}, {ID: "nope", Source: FromMail}}
	if n, e := Facts(nil, plan, []string{"a"}, nil); n != nil || e != nil {
		t.Fatalf("Facts(nil) = %v, %v", n, e)
	}
	tab, err := Load([]byte(fixedOnly))
	if err != nil {
		t.Fatal(err)
	}
	nodes, _ := Facts(tab, plan, nil, nil)
	for _, n := range nodes {
		if !strings.HasSuffix(n.ID, ".a") {
			t.Fatalf("a node %q for an item outside the table: %v", n.ID, nodes)
		}
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes %v, want a's account and provider", nodes)
	}
}
