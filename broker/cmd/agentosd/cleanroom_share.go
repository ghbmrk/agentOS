package main

import (
	"github.com/ghbmrk/agentos/broker/cleanroom"
	"github.com/ghbmrk/agentos/broker/meter"
)

// cleanroomShare is the clean-room machines' Max of the spare meter
// (W5c-ps2, loops L3 / potency PS2).
func cleanroomShare() meter.Share { return cleanroom.SpareShare() }
