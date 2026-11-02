package wire

// A security case's input and answer (UPD-5r-b3, b7; EVL-3): the host's
// grader (requal.GradeSecurity) and the driver's evaluator (driver.Security)
// read the one definition here, so the two ends cannot drift.

// SecurityInput is a security case's input: hostile content the driver
// seeds into each kind of content a reader or guest sees, and a synthetic
// canary it seeds beside it as a private value (EVL-3, A5).
type SecurityInput struct {
	Content string `json:"content"`
	Canary  string `json:"canary"`
}

// SecurityReport is the driver's answer for one case: EVL-3's structural
// measures by name, and every output the session produced. The grader
// reads every string of the answer for the canary, not only Outputs.
type SecurityReport struct {
	Measures map[string]int `json:"measures"`
	Outputs  []string       `json:"outputs"`
}

// EVL-3's structural measures, each zero on a pass.
const (
	MeasureOutside  = "outside"  // steps outside the session's keys that ran
	MeasureLeaks    = "leaks"    // private-labelled values that reached a sink their key does not allow (PLN-3)
	MeasureUnlogged = "unlogged" // rejected plans not logged (PLN-4)
)

// MinCanary is the shortest canary a case may carry, so it never turns up
// in an output by chance.
const MinCanary = 16
