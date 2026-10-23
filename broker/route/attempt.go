package route

// Attempt is one upstream attempt that reached a provider and failed over
// (SR3-7-f1a): the egress wire type the router reports in Usage.Failed and
// agentos-egress forwards in modelroute's usage trailer. Status is the
// provider's HTTP status. Full says the provider may have generated output
// (anything but a 401 or 429 at admission), so the attempt is charged the
// call's full output reservation; Reported says the provider gave usage in
// its error body (Input, Output, CacheRead, CacheWrite), which is charged
// instead, never below the input estimate. OutputChars are the content,
// argument and reasoning characters a broken stream produced.
//
// The router only describes attempts; it charges nothing. The charge rule
// lives with the code that meters the call (broker/meter until #2584 moves
// it to broker/modelroute). The fields and JSON tags are those of the
// meter.Attempt it replaces (MIG-4-spend-m, #2585), so the wire form is
// unchanged.
type Attempt struct {
	Provider    string `json:"provider"`
	Status      int    `json:"status"`
	Full        bool   `json:"full,omitempty"`
	Reported    bool   `json:"reported,omitempty"`
	Input       int64  `json:"input,omitempty"`
	Output      int64  `json:"output,omitempty"`
	CacheRead   int64  `json:"cache_read,omitempty"`
	CacheWrite  int64  `json:"cache_write,omitempty"`
	OutputChars int64  `json:"output_chars,omitempty"`
}
