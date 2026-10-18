package localui

// REQ: HW-1

import (
	"errors"
	"fmt"
	"html"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
)

// #2362: a card step rerun whose vault reset fails does not strand setup.
// The page goes back to the card step and says the card was not made; a
// reload retries the reset, and once it works the new card is shown and
// setup finishes, with no restart.
func TestAFailedCardResetIsRetriedWithoutARestart(t *testing.T) {
	cr := newCardRig(t)
	cr.toCard()
	cr.get("/setup/card")
	w, g := cr.answers()
	cr.post("/setup/card", url.Values{"word": {w}, "group": {g}})
	if cr.step.Hold() != nil {
		t.Fatal("first card not confirmed")
	}
	first := *cr.shown
	resets, reruns := 0, 0
	reset := func() error {
		resets++
		if resets <= 2 {
			return errors.New("vault busy")
		}
		return nil
	}
	cr.hooks.mu.Lock()
	cr.hooks.refuseFinish = func() error {
		if reruns > 0 {
			return nil
		}
		reruns++
		// CardFinish's answer when the rerun fails.
		if err := cr.step.Again(reset); err != nil {
			return fmt.Errorf("localui: making the Owner Card again: %w", err)
		}
		return ErrCardAgain
	}
	cr.hooks.connected = true
	cr.hooks.progress = Progress{Phase: "ready", Updated: true, Online: true}
	cr.hooks.mu.Unlock()
	cr.post("/setup/recovery", url.Values{"stored": {"1"}})
	cr.post("/setup/host", url.Values{}) // the last step's post runs the finish
	if cr.srv.setup.done() || reruns != 1 || resets != 1 {
		t.Fatalf("done %v, reruns %d, resets %d", cr.srv.setup.done(), reruns, resets)
	}
	page := html.UnescapeString(cr.get("/setup")) // retries; the reset fails again
	if resets != 2 || !strings.Contains(page, cardNotMade) || !strings.Contains(page, `href="/setup/card"`) {
		t.Fatalf("resets %d, not the card step with the message: %s", resets, page)
	}
	if strings.Contains(page, "Could not finish setup") || strings.Contains(page, errCardFirst.Error()) {
		t.Fatal("a dead-end message")
	}
	page = html.UnescapeString(cr.get("/setup")) // retries; the reset works
	if resets != 3 || !strings.Contains(page, cardAgain) || !strings.Contains(page, `href="/setup/card"`) {
		t.Fatalf("resets %d, not the new card's step: %s", resets, page)
	}
	cr.get("/setup/card")
	if cr.shown.RecoveryKey == first.RecoveryKey {
		t.Fatal("the same card shown again")
	}
	w, g = cr.answers()
	cr.post("/setup/card", url.Values{"word": {w}, "group": {g}})
	if cr.step.Hold() != nil || cr.made != 2 {
		t.Fatalf("new card: hold %v, provisions %d", cr.step.Hold(), cr.made)
	}
	cr.get("/setup")
	cr.post("/setup/recovery", url.Values{"stored": {"1"}})
	cr.srv.setup.maybeFinish()
	if !cr.srv.setup.done() || resets != 3 {
		t.Fatalf("done %v, resets %d", cr.srv.setup.done(), resets)
	}
	if _, gsm := modem.Segments(cardNotMade); !gsm {
		t.Fatalf("not GSM-7: %q", cardNotMade)
	}
}
