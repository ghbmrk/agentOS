package cleanroom

import "github.com/ghbmrk/agentos/broker/meter"

// SpareShareMax is the most of the owner's spare budget clean-room
// machines may use (W5c PS2 / loops L3). Tune from A11.
const SpareShareMax = 0.25

// SpareShare is the spare meter's share for clean-room machines (Prefix).
// agentosd should pass it to meter.SetShares with EvalShare and the
// builder share (W5c-ps2).
func SpareShare() meter.Share {
	return meter.Share{Prefix: Prefix, Max: SpareShareMax}
}
