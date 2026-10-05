package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return base, nil
	}
	if err != nil {
		return base, err
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
// exactly base's routes in some order.
func reorders(base, next route.Rule) error {
	if len(next) != len(base) {
		return errors.New("a routing change may only reorder the configured routes: classes differ")
	}
	for class, routes := range base {
		got, ok := next[class]
		if !ok || len(got) != len(routes) {
			return fmt.Errorf("a routing change may only reorder the configured routes: class %q differs", class)
		}
		for _, r := range routes {
			if !slices.Contains(got, r) {
				return fmt.Errorf("a routing change may only reorder the configured routes: class %q lacks %s", class, r)
			}
		}
		for i, r := range got {
			if slices.Contains(got[i+1:], r) {
				return fmt.Errorf("class %q repeats %s", class, r)
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
		return err
	}
	if ro.path != "" {
		if err := saveRule(ro.path, next); err != nil {
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

func saveRule(path string, r route.Rule) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".routing-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// The rename survives a power loss only once its directory is synced
	// (security R2 on PW4).
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

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
			json.NewEncoder(w).Encode(modelroute.RoutingState{Rule: ro.rt.Rule(), Candidate: ro.rt.Candidate()})
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
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
