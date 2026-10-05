// Package routerule holds the model router's rule types with no
// dependencies, so the deterministic parts that read or change a routing
// rule (the change pipeline, Loop 1) can link into agentosd without the
// router, its provider adapters, or an HTTP client (ARC-2; arbitrator,
// adopting potency PW1 on #56). The router (package route) aliases them.
package routerule

// Route is one way to serve a class: a provider and its model.
type Route struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

func (r Route) String() string { return r.Provider + "/" + r.Model }

// Rule maps each task class to its routes in preference order. ADP-3's
// default order puts API routes first; the order within a class is what
// Loop 1 improves (ADP-4).
type Rule map[string][]Route
