package egress

// DeniedHeader marks a response the proxy produced itself (a denial,
// including its own per-machine limits), as opposed to one a provider
// sent. A provider cannot set it: response headers are allowlisted. The
// model router uses it so that one machine's limits never cool a route for
// every machine.
const DeniedHeader = "X-Agentos-Egress-Denied"
