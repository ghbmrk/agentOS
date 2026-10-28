// Package enforcer is the home enforcer (SPEC NET-2 to NET-7, STO-4;
// briefs/ENF.md): the box between agentOS and the home's devices, which
// holds the network's configuration and the safety-list devices' secrets
// and changes a rule only on the owner's passkey at home.
//
// It shares no kernel, secret or update source with agentOS (NET-2
// Channel). Everything under broker/enforcer/ links nothing from agentOS
// except the key-check library broker/kernel/key (STO-4), broker/drone and
// broker/camwire, and the named third-party packages that
// broker/daemon/arc2_test.go lists (TestEnforcerImportsNothingFromAgentOS).
//
// The packages are laid out in the brief's code-layout table; policy/ is
// the owner-signed policy document, its versions and the tightening list.
package enforcer
