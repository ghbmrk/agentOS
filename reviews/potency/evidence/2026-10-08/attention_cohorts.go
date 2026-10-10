package main

import (
	"fmt"
	"github.com/ghbmrk/agentos/broker/attention"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/verb"
	"time"
)

func main() {
	for _, scenario := range []string{"one-template", "alternating-templates", "one-outlier-then-100-identical"} {
		o, err := attention.New(attention.Config{Store: &change.MemStore{}, UserContent: func(string) bool { return false }})
		if err != nil {
			panic(err)
		}
		n := 20
		if scenario == "alternating-templates" {
			n = 40
		}
		if scenario == "one-outlier-then-100-identical" {
			n = 111
		}
		for i := 0; i < n; i++ {
			template := "monthly"
			if scenario == "alternating-templates" && i%2 == 1 || scenario == "one-outlier-then-100-identical" && i == 10 {
				template = "quarterly"
			}
			err = o.Observe(attention.Decision{Account: "books", Action: "invoice.send", Verb: verb.Send, Approved: true, Verified: true, Params: map[string]any{"template": template, attention.Record: fmt.Sprintf("record-%d", i)}, Recipients: []string{"ap@client.test"}, At: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * 6 * time.Hour)})
			if err != nil {
				panic(err)
			}
		}
		s, err := o.Suggestions()
		if err != nil {
			panic(err)
		}
		necessary, avoidable := o.Split()
		fmt.Printf("%s: approvals=%d suggestions=%d counted_necessary=%d counted_avoidable=%d\n", scenario, n, len(s), necessary, avoidable)
	}
}
