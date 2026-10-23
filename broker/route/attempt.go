package route

import "github.com/ghbmrk/agentos/broker/routerule"

// Attempt is one upstream attempt the router sent and failed over from,
// reported in Usage.Failed (SR3-7-f1a). It is an alias of routerule's, so
// modelroute reads the same type without linking the router (ARC-2).
type Attempt = routerule.Attempt
