// Package skill is the compiled-skill format and its runner (SPEC CAP-5).
//
// A compiled skill is a fixed list of broker effects with typed inputs
// ("slots"), compiled by the broker from repeated successful trajectories
// (package compile) and adopted only through the change pipeline (§11) as
// a file skills/<id>.json in the managed tree. A procedure is the same
// format compiled from one trajectory with every value a slot, so it
// replays the recorded steps on new inputs.
//
// The runner is guest code. It runs inside the agent machine, in
// agentos-guest-bridge, which serves each skill as an MCP tool and sends
// each step to the broker as an ordinary effect_request. A skill therefore
// carries no authority of its own: every step is journaled, checked
// against grants, and approved exactly as if the guest had asked for it
// (ARC-7). The model is consulted once, to fill the inputs, and again only
// where an assumption fails: an input of the wrong type, or a step that
// did not succeed. The runner then stops and hands the remaining steps,
// with their bound values, back to the model.
//
// Assumptions are listed in broker/compile/ASSUMPTIONS.md.
package skill
