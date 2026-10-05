package loops

import (
	"context"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: UPD-4, UPD-5
//
// The update channel and cadence are owner settings (UPD-4, UPD-5):
// texted like the loop settings, journaled like them, and read by Loop 3.

func TestUpdateTextsParse(t *testing.T) {
	for msg, want := range map[string]Request{
		"UPDATES STABLE":          {Kind: KindChannel, Channel: ChannelStable},
		"updates fast":            {Kind: KindChannel, Channel: ChannelFast},
		"Updates pinned.":         {Kind: KindChannel, Channel: ChannelPinned},
		"UPDATE SOAK 14":          {Kind: KindSoak, Days: 14},
		"update soak 30 days":     {Kind: KindSoak, Days: 30},
		"UPDATE SOAK 1 DAY":       {Kind: KindSoak, Days: 1},
		"UPDATE SOAK 99999999999": {Kind: KindSoak, Days: MaxSoakDays + 1},
		"SECURITY UPDATES ASK":    {Kind: KindSecurity},
		"security updates auto":   {Kind: KindSecurity, On: true},
		"HELP UPDATES":            {Kind: KindHelpUpdates},
		// UX-130-1: UPDATE and UPDATES alike.
		"UPDATE PINNED":   {Kind: KindChannel, Channel: ChannelPinned},
		"updates soak 14": {Kind: KindSoak, Days: 14},
	} {
		got, ok := ParseText(msg)
		if !ok || got != want {
			t.Fatalf("%q: %+v %v", msg, got, ok)
		}
	}
	for _, msg := range []string{"UPDATES", "UPDATES SLOW", "are updates fast", "UPDATE SOAK", "UPDATE SOAK X",
		"UPDATE SOAK 014", "UPDATE SOAK 14 WEEKS", "SECURITY UPDATES", "SECURITY UPDATES OFF"} {
		if r, ok := ParseText(msg); ok {
			t.Fatalf("%q read as %+v", msg, r)
		}
	}
}

func TestUpdateSettingsDefaultToTheSpec(t *testing.T) {
	var u UpdateSettings
	if u.ChannelName() != ChannelStable || u.Soak() != DefaultSoakDays || u.SecurityAsk {
		t.Fatalf("%+v", u)
	}
}

func TestOwnerTextsSetTheUpdateChannelAndCadence(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	for _, c := range []struct{ msg, reply string }{
		{"UPDATES FAST", "Updates: fast channel. New releases are offered as they come out. Reply UPDATES STABLE if this wasn't you."},
		{"UPDATES STABLE", "Updates: stable channel. Releases are offered after other boxes have tested them for 7 days."},
		{"UPDATE SOAK 14", "Stable releases now wait 14 days before the box offers them."},
		{"UPDATE SOAK 10 DAYS", "Stable releases now wait 10 days before the box offers them. Reply UPDATE SOAK 14 if this wasn't you."},
		{"SECURITY UPDATES ASK", "The box will ask you before it installs each security fix. Reply SECURITY UPDATES AUTO to undo."},
		{"SECURITY UPDATES AUTO", "Tested security fixes install on their own again. Reply SECURITY UPDATES ASK if this wasn't you."},
		{"UPDATES PINNED", "Updates: pinned. Nothing installs on its own; the box still tells you about security fixes. Reply UPDATES STABLE to undo."},
		// UX-130-3: a soak set off the stable channel says when it applies.
		{"UPDATES SOAK 9 DAYS", "Stable releases now wait 9 days before the box offers them. It applies once you're on UPDATES STABLE. Reply UPDATE SOAK 10 if this wasn't you."},
	} {
		if got, ok := r.s.Text(ctx, c.msg, true); !ok || got != c.reply {
			t.Fatalf("%s: %q %v", c.msg, got, ok)
		}
	}
	if u := r.s.Settings().Updates; u.ChannelName() != ChannelPinned || u.Soak() != 9 || u.SecurityAsk {
		t.Fatalf("%+v", u)
	}
	// Out of range: answered with the bound, nothing changes.
	for msg, reply := range map[string]string{
		"UPDATE SOAK 3":   "The shortest soak is 7 days; UPDATES FAST takes releases as they come out.",
		"UPDATE SOAK 120": "The longest soak is 60 days.",
	} {
		if got, ok := r.s.Text(ctx, msg, true); !ok || got != reply {
			t.Fatalf("%s: %q %v", msg, got, ok)
		}
	}
	if r.s.Settings().Updates.Soak() != 9 {
		t.Fatalf("%+v", r.s.Settings().Updates)
	}
	// Journaled like the loop settings, and kept across a restart.
	var ids []string
	for _, st := range r.eng.List() {
		if strings.Contains(st.Intent.ID, ":channel:") || strings.Contains(st.Intent.ID, ":soak:") || strings.Contains(st.Intent.ID, ":security:") {
			if st.Intent.Action != ActionUpdates || st.State != journal.Succeeded {
				t.Fatalf("%s: %s %s", st.Intent.ID, st.Intent.Action, st.State)
			}
			ids = append(ids, st.Intent.ID)
		}
	}
	if len(ids) != 8 {
		t.Fatalf("journaled %q", ids)
	}
	r.restart()
	if u := r.s.Settings().Updates; u.ChannelName() != ChannelPinned || u.Soak() != 9 {
		t.Fatalf("after restart: %+v", u)
	}
}

// In a locked session only changes that make updates slower or more
// cautious are taken, as for UPDATE CHECKS OFF: a later channel, a longer
// soak, asking before security fixes. The rest waits for the unlock.
func TestALockedSessionTakesOnlyMoreCautiousUpdates(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	for _, msg := range []string{"UPDATES FAST", "UPDATE SOAK 6", "SECURITY UPDATES AUTO"} {
		if _, ok := r.s.Text(ctx, msg, false); ok {
			t.Fatalf("%s taken in a locked session", msg)
		}
	}
	for _, msg := range []string{"UPDATE SOAK 21", "SECURITY UPDATES ASK", "UPDATES STABLE", "UPDATES PINNED", "HELP UPDATES", "UPDATE SOAK 200"} {
		if _, ok := r.s.Text(ctx, msg, false); !ok {
			t.Fatalf("%s not taken in a locked session", msg)
		}
		if !r.s.Narrows(msg) {
			t.Fatalf("%s does not narrow", msg)
		}
	}
	for _, msg := range []string{"UPDATES STABLE", "UPDATES FAST", "UPDATE SOAK 20"} {
		if r.s.Narrows(msg) {
			t.Fatalf("%s narrows from pinned with a 21-day soak", msg)
		}
	}
	if u := r.s.Settings().Updates; u.ChannelName() != ChannelPinned || u.Soak() != 21 || !u.SecurityAsk {
		t.Fatalf("%+v", u)
	}
}

func TestHelpUpdatesFitsOneSegment(t *testing.T) {
	r := newRig(t)
	got, ok := r.s.Text(context.Background(), "help updates", true)
	if !ok || got != HelpUpdates {
		t.Fatalf("%q %v", got, ok)
	}
	if !strings.Contains(HelpText, "HELP UPDATES") {
		t.Fatal("HELP LOOPS does not point to HELP UPDATES (UX-130 Q1)")
	}
	if len(HelpUpdates) > 153 || len(HelpText) > 153 {
		t.Fatalf("HELP UPDATES is %d characters", len(HelpUpdates))
	}
}

// Only the owner changes update settings, and the action must match.
func TestUpdateSettingIntentsAreOwnerOnly(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	ok := journal.Intent{ID: "loops:n9:channel:fast", Origin: OriginOwner, Account: journal.BrokerAccount, Action: ActionUpdates, Executor: Executor}
	if err := r.s.Check(ctx, journal.PhaseAuthorize, ok); err != nil {
		t.Fatal(err)
	}
	for _, in := range []journal.Intent{
		{ID: ok.ID, Origin: "loop:improve", Account: ok.Account, Action: ok.Action, Executor: ok.Executor},
		{ID: ok.ID, Origin: "guest:m1", Account: ok.Account, Action: ok.Action, Executor: ok.Executor},
		{ID: ok.ID, Origin: ok.Origin, Account: ok.Account, Action: ActionOn, Executor: ok.Executor},
		{ID: "loops:n9:on:all", Origin: ok.Origin, Account: ok.Account, Action: ActionUpdates, Executor: ok.Executor},
		{ID: "loops:n9:channel:slow", Origin: ok.Origin, Account: ok.Account, Action: ActionUpdates, Executor: ok.Executor},
		{ID: "loops:n9:soak:6", Origin: ok.Origin, Account: ok.Account, Action: ActionUpdates, Executor: ok.Executor},
		{ID: "loops:n9:soak:61", Origin: ok.Origin, Account: ok.Account, Action: ActionUpdates, Executor: ok.Executor},
		{ID: "loops:n9:soak:014", Origin: ok.Origin, Account: ok.Account, Action: ActionUpdates, Executor: ok.Executor},
		{ID: "loops:n9:security:maybe", Origin: ok.Origin, Account: ok.Account, Action: ActionUpdates, Executor: ok.Executor},
	} {
		if err := r.s.Check(ctx, journal.PhaseAuthorize, in); err == nil {
			t.Fatalf("%s from %s as %s allowed", in.ID, in.Origin, in.Action)
		}
	}
}
