package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"sync"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
)

// routing serves the active routing rule to agentosd on the routing socket
// (W3, potency PW4 on #90): the change pipeline reads the rule and the
// router's measured proposal, and sets the rule when it adopts or reverts
// a routing change (ADP-4). This process accepts only a reordering of the
// owner's configured routes (-rule): the same classes, each with the same
// routes, so no adoption adds a route, model, or provider here, whatever
// agentosd sends (CAP-9). The adopted rule is kept in a file beside the
// unlock state, so it survives a restart, and the evaluation price ceiling
// follows it (ev.setActive).
type routing struct {
	mu   sync.Mutex
	base route.Rule // -rule: the owner's configured routes
	rt   *route.Router
	ev   *evalRoute
	path string // the adopted rule's file; "" keeps none
}

// startRule is the rule to start with: the adopted rule saved at path when
// it is a reordering of base, else base. A missing file is no adoption; an
// unreadable or non-reordering one is logged by the caller and ignored.
func startRule(base route.Rule, path string) (route.Rule, error) {
	if path == "" {
		return base, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return base, nil
	}
	if err != nil {
		return base, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, modelroute.MaxRule+1))
	if err != nil {
		return base, err
	}
	if len(raw) > modelroute.MaxRule {
		return base, fmt.Errorf("adopted rule %s: over %d bytes", path, modelroute.MaxRule)
	}
	var r route.Rule
	if err := json.Unmarshal(raw, &r); err != nil {
		return base, fmt.Errorf("adopted rule %s: %w", path, err)
	}
	if err := reorders(base, r); err != nil {
		return base, fmt.Errorf("adopted rule %s: %w", path, err)
	}
	return r, nil
}

// reorders reports nil when next has exactly base's classes, each with
// exactly base's routes in some order. Its errors are refusals.
func reorders(base, next route.Rule) error {
	if len(next) != len(base) {
		return errors.New("a routing change may only reorder the configured routes: classes differ")
	}
	for class, routes := range base {
		got, ok := next[class]
		if !ok || len(got) != len(routes) {
			return fmt.Errorf("a routing change may only reorder the configured routes: class %q differs", class)
		}
		// Same length and every base route present: with no repeats in
		// base (route.New refuses them), got repeats none either.
		for _, r := range routes {
			if !slices.Contains(got, r) {
				return fmt.Errorf("a routing change may only reorder the configured routes: class %q lacks %s", class, r)
			}
		}
	}
	return nil
}

// set adopts next: checked, saved, then applied to the router and the
// evaluation ceiling. A failed save applies nothing. An empty rule is the
// owner's -rule: the change pipeline's record before any adoption.
func (ro *routing) set(next route.Rule) error {
	ro.mu.Lock()
	defer ro.mu.Unlock()
	if len(next) == 0 {
		next = ro.base
	}
	if err := reorders(ro.base, next); err != nil {
		return refusal{err}
	}
	if ro.path != "" {
		b, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(ro.path, b); err != nil {
			return err
		}
	}
	if err := ro.rt.SetRule(next); err != nil {
		return err
	}
	if ro.ev != nil {
		ro.ev.setActive(next)
	}
	return nil
}

// refusal is a rule set refuses: not a reordering of the owner's rule.
type refusal struct{ error }

// handler serves GET (the active rule and the router's proposal) and PUT
// (adopt a rule) on the routing socket, which admits agentosd's uid only.
func (ro *routing) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != modelroute.RoutingPath {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(modelroute.RoutingState{Rule: ro.rt.Rule(), Candidate: ro.rt.Candidate(), Owner: ro.base})
		case http.MethodPut:
			b, err := io.ReadAll(io.LimitReader(r.Body, modelroute.MaxRule+1))
			if err != nil || len(b) > modelroute.MaxRule {
				http.Error(w, "rule too large", http.StatusRequestEntityTooLarge)
				return
			}
			var next route.Rule
			if err := json.Unmarshal(b, &next); err != nil {
				http.Error(w, "unreadable rule", http.StatusBadRequest)
				return
			}
			if err := ro.set(next); err != nil {
				var no refusal
				if errors.As(err, &no) {
					http.Error(w, err.Error(), http.StatusConflict)
					return
				}
				// Not a refusal: the broker may retry (L3 M1 on #96).
				log.Printf("routing: adopting a rule: %v", err)
				http.Error(w, "the rule could not be kept", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
