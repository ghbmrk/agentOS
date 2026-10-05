package secondline_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/secondline"
	"github.com/ghbmrk/agentos/broker/sendrules"
)

// REQ: ADP-12

// SR2-5 (ADP-12: recipients are full international numbers; a short or
// premium-rate code needs an owner-created contact): the tool refuses
// short codes, national forms and premium-rate numbers before the modem
// sees them, unless the owner made the number a contact, and never the
// owner's own number even then.
func TestOnlyFullNumbersOrOwnerContactsAreSentTo(t *testing.T) {
	c := modem.NewCarrier()
	owner := open(t, c, at.SIMCom, "SIMCOM_SIM7600G-H", boxNum)
	second := open(t, c, at.Quectel, "EG25", secondNum)
	contacts := map[string]bool{"72727": true, ownerNum: true, "5550000001": true}
	tool, err := secondline.New(secondline.Config{Owner: owner.m, Second: secondline.FromAT(second.m), Roles: roles(owner, second),
		Disclosure: disclosure(), OwnerPhone: ownerNum, CountryCode: "1", Contact: func(n string) bool { return contacts[n] }})
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{"72727x", "88888", "+1555123", "5550000777", "+19005550123", "+449098790123", ownerNum, "5550000001"} {
		if err := tool.Text(to, "STOP"); !errors.Is(err, secondline.ErrRecipient) {
			t.Errorf("Text to %s: %v", to, err)
		}
		if _, err := tool.Call(context.Background(), to); !errors.Is(err, secondline.ErrRecipient) {
			t.Errorf("Call to %s: %v", to, err)
		}
	}
	if n := dialed(second.dev); len(n) != 0 {
		t.Fatalf("the modem dialed %q", n)
	}
	for _, to := range []string{"72727", shopNum} {
		if err := tool.Text(to, "STOP"); err != nil {
			t.Errorf("Text to %s: %v", to, err)
		}
	}
}

// SR2-5: a second SIM's texts and calls spend one budget held by the
// tool; past it nothing reaches the modem.
func TestASecondSIMHasOneBudgetForTextsAndCalls(t *testing.T) {
	c := modem.NewCarrier()
	owner := open(t, c, at.SIMCom, "SIMCOM_SIM7600G-H", boxNum)
	second := open(t, c, at.Quectel, "EG25", secondNum)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	budget := &sendrules.Budget{}
	tool, err := secondline.New(secondline.Config{Owner: owner.m, Second: secondline.FromAT(second.m), Roles: roles(owner, second),
		Disclosure: disclosure(), OwnerPhone: ownerNum, CountryCode: "1", Budget: budget, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := tool.Text(shopNum, "Table for 2 at 7?"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < sendrules.PerHour; i++ {
		if err := budget.Take(fmt.Sprintf("+1555070%04d", i), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := tool.Text("+15550799999", "hi"); !errors.Is(err, secondline.ErrLimited) {
		t.Fatalf("text past the cap: %v", err)
	}
	if _, err := tool.Call(context.Background(), "+15550799999"); !errors.Is(err, secondline.ErrLimited) {
		t.Fatalf("call past the cap: %v", err)
	}
	if n := dialed(second.dev); len(n) != 0 {
		t.Fatalf("the modem dialed %q", n)
	}
	now = now.Add(time.Hour)
	if err := tool.Text("+15550799999", "hi"); err != nil {
		t.Fatalf("an hour later: %v", err)
	}
}
