package page

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/pairseal"
)

var funcs = template.FuncMap{
	"label":  labelWords,
	"lines":  func(b []byte) []string { return strings.Split(strings.TrimSpace(string(b)), "\n") },
	"ascii":  ascii,
	"sealed": sealedLine,
}

// when is a time as the page shows it: in the owner's zone, with the
// zone's name, so the owner converts nothing (NET-4). Every time on the
// page is drawn by it.
func (s *Server) when(ms int64) string {
	return clock(ms, s.cfg.Zone)
}

// clock is ms in zone, to the minute, with the zone's name.
func clock(ms int64, zone *time.Location) string {
	return time.UnixMilli(ms).In(zone).Format("Mon 2 Jan 2006 15:04 MST")
}

// shortLine is pairseal.Statement's line as the page shows it: the
// envelope's hash cut to pairseal.ShortHash characters, the whole hash
// beside it in a details element. The diff the owner signs keeps the
// whole line (UX on #4073).
type shortLine struct{ Text, Hash string }

// sealedLine is line shown short when it is pairseal.Statement's line,
// and nil for every other line, which the page shows as it is.
func sealedLine(line string) *shortLine {
	device, hash, ok := pairseal.ParseStatement(line)
	if !ok {
		return nil
	}
	return &shortLine{Text: pairseal.Statement(device, hash[:pairseal.ShortHash]+"…"), Hash: hash}
}

// confirm is the confirm screen for a proposal link: the change drawn by
// the enforcer from the link's document and the policy in force, and the
// challenge one tap signs for exactly that diff.
func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if !s.limit(&s.links) {
		s.mu.Unlock()
		http.Error(w, errLimited.Error(), http.StatusTooManyRequests)
		return
	}
	c, lines, err := s.draft(r)
	if err != nil {
		s.mu.Unlock()
		http.Error(w, errMalformed.Error(), http.StatusBadRequest)
		return
	}
	id, err := s.put(c)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}
	s.cfg.Lock.Lock()
	waiting := len(s.cfg.Policy.Pending()) > 0
	s.cfg.Lock.Unlock()
	s.render(w, "confirm.html", map[string]any{
		"Name":        s.cfg.Name,
		"Lines":       lines,
		"Consequence": consequence(c.class),
		"Blocked":     waiting && !c.class.Tightening,
		"ID":          id,
		"Challenge":   chal(c.msg),
		"Sealed":      c.secret != nil,
	})
}

// home is the page's status: the policy in force, the loosening waiting
// with its cancel, whether the passkey is synced, the channel's pause, each
// device's label from the signed policy, and NET-1's limits.
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	s.cfg.Lock.Lock()
	cur, pend := s.cfg.Policy.Current(), s.cfg.Policy.Pending()
	s.cfg.Lock.Unlock()
	s.mu.Lock()
	sync := s.sync
	s.mu.Unlock()
	channel := "not connected"
	if s.cfg.Channel != nil {
		channel = "open"
		if s.cfg.Channel.Paused() {
			channel = "paused"
		}
	}
	devs := plain(cur).Devices
	keep, recovery := false, ""
	if s.cfg.Enrol != nil {
		keep = !s.cfg.Enrol.Kept()
		if due, ok := s.cfg.Enrol.Recovery(); ok {
			recovery = s.when(due.UnixMilli())
		}
	}
	s.render(w, "home.html", map[string]any{
		"Keep":     keep,
		"Recovery": recovery,
		"Enrol":    s.cfg.Enrol != nil,
		"Name":     s.cfg.Name,
		"Version":  cur.Version,
		"Pending":  pend,
		"Sync":     sync,
		"Channel":  channel,
		"Devices":  devs,
		"Limits":   Limits,
	})
}

func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	var b strings.Builder
	if err := s.tmpl.ExecuteTemplate(&b, name, data); err != nil {
		http.Error(w, "page error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}
