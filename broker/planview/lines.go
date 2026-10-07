// Package planview formats plan pool lines for STATUS and the Wi-Fi page (ONB-9).
package planview

import (
	"fmt"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/planquota"
)

// Line is one pool as the owner sees it.
func Line(plan string, p planquota.Pool, workerHeld bool) string {
	pct := int(p.Used*100 + 0.5)
	reset := ""
	if !p.Reset.IsZero() {
		reset = ", resets " + p.Reset.Local().Format("15:04")
	}
	s := fmt.Sprintf("%s: %d%% of the %s limit%s", plan, pct, humanPool(p.ID), reset)
	if workerHeld {
		s += " (as the provider reports; I keep to your reserve as closely as I can)"
	}
	return s
}

func humanPool(id string) string {
	switch id {
	case "five_hour", "5h":
		return "5-hour"
	case "seven_day", "7d", "week":
		return "week"
	default:
		return strings.ReplaceAll(id, "_", " ")
	}
}

// StatusLine when any pool is at the owner's reserve (ONB-9).
func StatusLine(plan string, p planquota.Pool, hasAPI bool) string {
	if p.Headroom(false) > 0 {
		return ""
	}
	when := "later"
	if !p.Reset.IsZero() {
		when = p.Reset.Local().Format("15:04")
	}
	if hasAPI {
		return fmt.Sprintf("%s plan: at your reserve until %s. Nothing to do; work uses the API meanwhile.", plan, when)
	}
	return fmt.Sprintf("%s plan: at your reserve until %s. Nothing to do; work waits until then.", plan, when)
}

// DigestFailover is the told-not-asked digest line after CAP-9 failover.
func DigestFailover(plan string, reset time.Time, apiSpend string) string {
	when := "later"
	if !reset.IsZero() {
		when = reset.Local().Format("15:04")
	}
	if apiSpend == "" {
		apiSpend = "$0.00"
	}
	return fmt.Sprintf("%s plan limit reached until %s. Used the API instead: %s today.", plan, when, apiSpend)
}
