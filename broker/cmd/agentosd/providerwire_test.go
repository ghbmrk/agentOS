package main

// REQ: CAP-11, CRED-5

import (
	"context"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/provagent"
	"github.com/ghbmrk/agentos/broker/vm"
)

// The wired runner starts nothing until the rows that fill its inputs land:
// Codex's qualification record is empty (#809), Claude is an opt-in (#1380).
func TestProviderRunnerIsClosedByDefault(t *testing.T) {
	r := providerRunner(nil, nil)
	for provider, want := range map[string]provagent.Reason{"codex": provagent.Unqualified, "claude": provagent.OptInRequired} {
		_, err := r.Run(context.Background(), provagent.Request{Provider: provider, Brief: "b", TaskClass: "code",
			Label: vm.Public, Class: admission.Experiment, MemMB: 256})
		var ref *provagent.Refusal
		if !errors.As(err, &ref) || ref.Reason != want {
			t.Fatalf("%s = %v, want %s", provider, err, want)
		}
	}
	if r.Granted("codex") || r.PrivateOK("codex") || r.Consent("codex") {
		t.Fatal("an owner-side input is open before its row landed")
	}
}
