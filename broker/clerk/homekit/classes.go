package homekit

import "github.com/ghbmrk/agentos/broker/kernel/key"

// The HomeKit Thermostat rows for the kernel-shipped class table (DEV-4).
// They are data the kernel table takes; this package never decides with
// them. Types are HAP short forms.
const (
	ServiceThermostat = "4A"

	CharCurrentHeatingCoolingState = "F"
	CharTargetHeatingCoolingState  = "33"
	CharCurrentTemperature         = "11"
	CharTargetTemperature          = "35"
	CharTemperatureDisplayUnits    = "36"
	CharCoolingThreshold           = "D"
	CharHeatingThreshold           = "12"
)

// Inverse names how an `actuate` write is undone.
type Inverse string

const (
	NoInverse  Inverse = ""
	PriorValue Inverse = "prior-value"
)

// ClassRow is one row: the verb of a read, of a write inside the owner's
// confirmed bounds, and of any other write.
type ClassRow struct {
	Service, Characteristic, Name string
	Read                          key.Verb
	InBounds                      key.Verb // the verb of a write within Bounds
	Otherwise                     key.Verb // every other write
	Inverse                       Inverse
}

// Bounds are the owner's confirmed bounds for a setpoint (part b confirms
// them on the local page). Unconfirmed bounds admit no value.
type Bounds struct {
	Min, Max  float64
	Confirmed bool
}

func (b Bounds) contain(v float64) bool { return b.Confirmed && v >= b.Min && v <= b.Max }

// WriteVerb is the row's verb for writing v under bounds b.
func (r ClassRow) WriteVerb(v float64, b Bounds) key.Verb {
	if r.InBounds != "" && b.contain(v) {
		return r.InBounds
	}
	return r.Otherwise
}

func setpoint(c, name string) ClassRow {
	return ClassRow{ServiceThermostat, c, name, key.Read, key.Actuate, key.ActuatePhysical, PriorValue}
}

func readOnly(c, name string) ClassRow {
	return ClassRow{ServiceThermostat, c, name, key.Read, "", key.ActuatePhysical, NoInverse}
}

// ThermostatRows: every value of target heating/cooling state is
// `actuate-physical`, stricter than DEV-5 (ASSUMPTIONS.md HK-7).
var ThermostatRows = []ClassRow{
	readOnly(CharCurrentTemperature, "current temperature"),
	readOnly(CharCurrentHeatingCoolingState, "current heating/cooling state"),
	setpoint(CharTargetTemperature, "target temperature"),
	setpoint(CharCoolingThreshold, "cooling threshold"),
	setpoint(CharHeatingThreshold, "heating threshold"),
	{ServiceThermostat, CharTargetHeatingCoolingState, "target heating/cooling state", key.Read, "", key.ActuatePhysical, NoInverse},
	{ServiceThermostat, CharTemperatureDisplayUnits, "display units", key.Read, "", key.ChangeAccount, NoInverse},
}

// AdminRows: pairing administration. The box is the only admin and this
// package implements neither (D-182 design point 3).
var AdminRows = map[string]key.Verb{
	"remove-pairing": key.DeleteRemote,
	"add-pairing":    key.RevealOrCreateSecret,
}

// ClassFor returns the row for a service and characteristic type, or DEV-4's
// conservative default: reads `read`, every write `actuate-physical`.
func ClassFor(service, char string) ClassRow {
	for _, r := range ThermostatRows {
		if r.Service == service && r.Characteristic == char {
			return r
		}
	}
	return ClassRow{service, char, "unmapped", key.Read, "", key.ActuatePhysical, NoInverse}
}
