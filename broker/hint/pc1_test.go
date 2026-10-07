package hint

import "testing"

// REQ: OSS-2, OSS-5
func TestPC1AdapterGapLayoutHeld(t *testing.T) {
	r := newRig(t, Config{})
	for _, fail := range []string{"changed_api", "changed_layout"} {
		h := Hint{Kind: "adapter_gap", Fields: map[string]string{
			"service_class": "banking", "surface": "web", "failure": fail, "frequency": "sometimes",
		}}
		if res := emit(t, r.e, h); res.Outcome != Withheld {
			t.Fatalf("%s: %s", fail, res.Outcome)
		}
	}
	// Other adapter failures still queue when policy allows.
	ok := Hint{Kind: "adapter_gap", Fields: map[string]string{
		"service_class": "banking", "surface": "web", "failure": "authentication_flow", "frequency": "sometimes",
	}}
	if res := emit(t, r.e, ok); res.Outcome != Queued && res.Outcome != Asked {
		if res.Outcome == Withheld {
			t.Fatalf("authentication_flow wrongly held: %s", res.Outcome)
		}
	}
}
