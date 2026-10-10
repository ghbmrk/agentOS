package main

import (
	"fmt"
	"github.com/ghbmrk/agentos/broker/change"
)

func main() {
	expect := []byte(`{"subject":"Weekly note","body":"Synthetic fixture"}`)
	for _, outcome := range []change.Outcome{change.Accepted, change.Rejected} {
		c := change.Case{Outcome: outcome, Expect: expect}
		fmt.Printf("outcome=%s natural_reply=%t exact_params_json=%t\n", outcome,
			change.DefaultGrader(c, []byte("Done. I sent the weekly note.")),
			change.DefaultGrader(c, expect))
	}
}
