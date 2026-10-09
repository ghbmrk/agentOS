// Command a11harness is the A11 loop 2 qualification harness (P3-4b-2).
// It reads the seed catalog, picks a seed with its own random source (or
// runs every seed), runs each through Loop 2's real chain, runs the
// mutation controls, and writes a JSON report. It exits 0 only on a pass.
//
// Run it through run.py, which builds it against the broker module.
package main

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
)

type control struct {
	Name   string `json:"name"`
	SeedID string `json:"seed_id"`
	Caught bool   `json:"caught"`
	Detail string `json:"detail"`
}

type report struct {
	CatalogSHA256 string      `json:"catalog_sha256"`
	Mode          string      `json:"mode"`
	RandomSeed    int64       `json:"random_seed"`
	Controls      []control   `json:"controls"`
	Runs          []runReport `json:"runs"`
	Pass          bool        `json:"pass"`
	Error         string      `json:"error,omitempty"`
}

func main() {
	cat := flag.String("catalog", "", "the seed catalog directory")
	all := flag.Bool("all", false, "run every seed, in a shuffled order")
	pick := flag.Bool("pick", false, "run one seed picked at random")
	rs := flag.Int64("random-seed", -1, "the random source's seed (default: from crypto/rand)")
	leak := flag.Bool("leak", false, "mutation: the fixer adapter leaks the held-back bytes")
	out := flag.String("report", "", "where to write the JSON report")
	flag.Parse()
	if *cat == "" || *out == "" || *all == *pick {
		fmt.Fprintln(os.Stderr, "usage: --catalog DIR --report FILE (--all | --pick) [--random-seed N] [--leak]")
		os.Exit(2)
	}
	r := report{Mode: "pick", RandomSeed: *rs, Controls: []control{}, Runs: []runReport{}}
	if *all {
		r.Mode = "all"
	}
	if r.RandomSeed < 0 {
		var b [8]byte
		if _, err := crand.Read(b[:]); err != nil {
			panic(err)
		}
		r.RandomSeed = int64(binary.LittleEndian.Uint64(b[:]) & (1<<53 - 1))
	}
	c, err := loadCatalog(*cat)
	if err != nil {
		r.Error = err.Error()
	} else {
		r.CatalogSHA256 = c.Digest
		execute(context.Background(), c, &r, *leak)
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, run := range r.Runs {
		status := "pass"
		if !run.Pass {
			status = "FAIL"
		}
		fmt.Printf("%s %s\n", status, run.SeedID)
		for _, f := range run.Failures {
			fmt.Printf("  %s\n", f)
		}
	}
	for _, ct := range r.Controls {
		fmt.Printf("control %s caught=%v %s\n", ct.Name, ct.Caught, ct.Detail)
	}
	if r.Error != "" {
		fmt.Println("error:", r.Error)
	}
	fmt.Printf("catalog %s random-seed %d pass=%v\n", r.CatalogSHA256, r.RandomSeed, r.Pass)
	if !r.Pass {
		os.Exit(1)
	}
}

func execute(ctx context.Context, c *catalog, r *report, leak bool) {
	if len(c.Seeds) == 0 {
		r.Error = "the catalog has no seeds"
		return
	}
	rng := rand.New(rand.NewPCG(uint64(r.RandomSeed), 0))
	order := c.Seeds
	if r.Mode == "pick" {
		order = []*seed{c.Seeds[rng.IntN(len(c.Seeds))]}
	} else {
		order = append([]*seed(nil), c.Seeds...)
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	}
	pass := true
	for _, s := range order {
		run := c.run(ctx, s, leak)
		pass = pass && run.Pass
		r.Runs = append(r.Runs, run)
	}
	r.Controls = controls(ctx, c)
	for _, ct := range r.Controls {
		pass = pass && ct.Caught
	}
	r.Pass = pass && len(r.Runs) > 0
}

// controls are the mutation controls, run on every invocation as
// canary_controls.py does: each breaks one thing the run depends on and
// must turn it red for the expected reason.
func controls(ctx context.Context, c *catalog) []control {
	var out []control
	// invalid-seed: the first seed with its held-back variant replaced by
	// the visible test's first clause, which already holds on the defect.
	s0 := c.Seeds[0]
	inv := *s0
	ct := control{Name: "invalid-seed", SeedID: s0.ID}
	if test, err := parseRule(s0.Test); err != nil || len(test.Clauses) == 0 {
		ct.Detail = "the first seed's test does not parse"
	} else {
		inv.Held = map[string][]byte{"v1": one(test.Clauses[0]).Encode()}
		run := c.run(ctx, &inv, false)
		for _, f := range run.Failures {
			if len(f) >= 12 && f[:12] == "invalid seed" {
				ct.Caught = true
				ct.Detail = f
				break
			}
		}
		if !ct.Caught {
			ct.Detail = fmt.Sprintf("the run did not refuse the seed: %v", run.Failures)
		}
	}
	out = append(out, ct)
	// leaking-adapter: a valid seed run with an adapter that hands the
	// held-back bytes to the fixer; the audit must catch it.
	ct = control{Name: "leaking-adapter"}
	for _, s := range c.Seeds {
		if len(c.validate(s)) > 0 {
			continue
		}
		ct.SeedID = s.ID
		run := c.run(ctx, s, true)
		ct.Caught = !run.Audit.Clean && !run.Pass
		ct.Detail = fmt.Sprintf("%d audit hits", len(run.Audit.Hits))
		break
	}
	if ct.SeedID == "" {
		ct.Detail = "no valid seed to run it on"
	}
	return append(out, ct)
}
