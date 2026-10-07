package hint

// holdAdapterGapPC1 is clean-room C13 PC1: until ARC-6 (d) uncredentialed
// egress lands, adapter_gap hints that need a live layout/API probe stay held.
func holdAdapterGapPC1(h Hint) bool {
	if h.Kind != "adapter_gap" {
		return false
	}
	switch h.Fields["failure"] {
	case "changed_api", "changed_layout":
		return true
	}
	return false
}
