package localapi

// HomeKit ops (DEV-homekit part b2a, #3891; DEV-3, DEV-8, DEV-10, CH-3,
// CH-6): the HomeKit page lists the HomeKit clerk's STATUS lines, its
// paired thermostats and the accessories the enforcer lists, and relays
// the owner's tier-4 steps (connect by HomeKit code, bounds, re-pin) and
// the disconnect. Each needs a session. A tier-4 step carries the
// code-generator code the owner typed on this page; agentosd checks it
// before it relays the step to the HomeKit clerk's owner socket (b2b). The
// HomeKit code crosses to the clerk once and is never stored or echoed.
const (
	// OpHomeKit (Auth) answers a HomeKitList.
	OpHomeKit = "page_homekit"
	// OpHomeKitChange (HomeKitChange) answers a HomeKitDone once the
	// clerk has saved the change.
	OpHomeKitChange = "page_homekit_change"
)

// HomeKitOps lists the HomeKit ops, for the disjointness test.
var HomeKitOps = []string{OpHomeKit, OpHomeKitChange}

// The HomeKit ops' fixed refusals, beside ErrUnauthorized, ErrBadArgs and
// ErrLimited. No clerk or accessory text reaches the page.
const (
	// ErrHomeKitApproval: the approval code is wrong or used (tier 4).
	ErrHomeKitApproval = "homekit approval"
	// ErrHomeKitCode: the accessory refused the HomeKit code.
	ErrHomeKitCode = "homekit code"
	// ErrHomeKitReset: the accessory is paired with another controller,
	// or takes no more tries, until HomeKit is reset on it.
	ErrHomeKitReset = "homekit reset"
	// ErrHomeKitRefused: the clerk refused the step: a name in use, an
	// accessory the enforcer does not list, bounds outside the
	// thermostat's range, or no room for another device.
	ErrHomeKitRefused = "homekit refused"
	// ErrHomeKitUnknown: no paired device has that name.
	ErrHomeKitUnknown = "homekit unknown"
	// ErrHomeKitUnavailable: the clerk or the accessory could not be
	// reached, or a STOP holds.
	ErrHomeKitUnavailable = "homekit unavailable"
)

// HomeKitCodes is the closed set the HomeKit ops refuse with past the
// session and argument checks.
var HomeKitCodes = []string{ErrHomeKitApproval, ErrHomeKitCode, ErrHomeKitReset, ErrHomeKitRefused, ErrHomeKitUnknown, ErrHomeKitUnavailable}

// The HomeKit steps a HomeKitChange names.
const (
	HomeKitConnect    = "connect"
	HomeKitBounds     = "bounds"
	HomeKitRepin      = "repin"
	HomeKitDisconnect = "disconnect"
)

// HomeKitTier4 says whether a step needs the approval code (CH-3:
// connecting, re-pinning and widening a setpoint's bounds are tier 4).
// Disconnecting narrows.
func HomeKitTier4(step string) bool { return step != HomeKitDisconnect }

// HomeKitDevice is one paired thermostat as the page shows it: the owner's
// name, its type and the first 8 characters of its pinned key's
// fingerprint, never a name the accessory sent (DEV-8, DEV-10).
type HomeKitDevice struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Key   string `json:"key"`
	State string `json:"state"` // "open", "connecting", "off" or "stopped"
	// Bounds are the confirmed setpoint bounds by HAP characteristic type,
	// in °C.
	Bounds map[string]HomeKitRange `json:"bounds,omitempty"`
}

// HomeKitRange is one setpoint's confirmed bounds, in °C.
type HomeKitRange struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// HomeKitListed is an accessory the enforcer lists that is not paired with
// the box: its device ID in the enforcer and its address.
type HomeKitListed struct {
	Device   string `json:"device"`
	Addr     string `json:"addr"`
	Unpaired bool   `json:"unpaired"`
}

// HomeKitList is the HomeKit page's list.
type HomeKitList struct {
	Lines   []string        `json:"lines"`
	Devices []HomeKitDevice `json:"devices"`
	Listed  []HomeKitListed `json:"listed"`
}

// HomeKitChange is one step on a thermostat. Device names the listed
// accessory a connect or re-pin takes; HomeKitCode is the accessory's
// 8-digit code (CH-6); Char, Min and Max are a bounds step's setpoint and
// range; Code is the approval code for a tier-4 step.
type HomeKitChange struct {
	Token       string  `json:"token"`
	Step        string  `json:"step"`
	Name        string  `json:"name"`
	Device      string  `json:"device"`
	HomeKitCode string  `json:"homekit_code"`
	Char        string  `json:"char"`
	Min         float64 `json:"min"`
	Max         float64 `json:"max"`
	Code        string  `json:"code"`
}

// HomeKitDone answers a change. Reset says a disconnect removed the device
// here only: the accessory was off or unreachable and keeps the box's
// pairing until HomeKit is reset on it.
type HomeKitDone struct {
	Reset bool `json:"reset"`
}
