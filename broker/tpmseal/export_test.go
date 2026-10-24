package tpmseal

// PinsHandles and PinsPublic let the tests build indexes at the handles
// ReadPins probes; CounterHandles, the handles FindCounter probes.
var (
	PinsHandles    = pinsHandles
	PinsPublic     = pinsPublic
	CounterHandles = counterHandles
)

var CounterTag = counterTag
