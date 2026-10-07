package hint

import "testing"

// REQ: OSS-2, OSS-5
func TestPC1AdapterGapLayoutHeld(t *testing.T) {
	for _, fail := range []string{"changed_api", "changed_layout"} {
		h := Hint{Kind: "adapter_gap", Fields: map[string]string{
			"service_class": "banking", "surface": "web", "failure": fail, "frequency": "sometimes",
		}}
		if !holdAdapterGapPC1(h) {
			t.Fatalf("%s: not held", fail)
		}
	}
	ok := Hint{Kind: "adapter_gap", Fields: map[string]string{
		"service_class": "banking", "surface": "web", "failure": "authentication_flow", "frequency": "sometimes",
	}}
	if holdAdapterGapPC1(ok) {
		t.Fatal("authentication_flow wrongly held")
	}
	if holdAdapterGapPC1(Hint{Kind: "skill_gap"}) {
		t.Fatal("skill_gap wrongly held")
	}
}
