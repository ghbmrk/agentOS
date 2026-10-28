package drone

import (
	"math"
	"sort"
)

// Param is one flight-controller parameter the policy sets.
type Param struct {
	Name  string
	Value float32
}

// Item is one fence or rally item, as the MAVLink mission protocol carries it.
type Item struct {
	Command uint16
	Param1  float32 // a fence vertex's polygon vertex count
	Lat     int32   // degrees * 1e7
	Lon     int32   // degrees * 1e7
	AltM    float32 // a rally point's altitude above home, whole metres
}

// MAVLink commands for fence and rally items (common.xml).
const (
	cmdFenceInclusion = 5001 // MAV_CMD_NAV_FENCE_POLYGON_VERTEX_INCLUSION
	cmdFenceExclusion = 5002 // MAV_CMD_NAV_FENCE_POLYGON_VERTEX_EXCLUSION
	cmdRallyPoint     = 5100 // MAV_CMD_NAV_RALLY_POINT
)

// Plan is what the aircraft must hold for a policy: its parameters, its
// fence (one inclusion polygon, then one exclusion polygon per no-fly zone)
// and one rally point at the dock (P3).
type Plan struct {
	Params []Param
	Fence  []Item
	Rally  []Item
}

// Parameter values at the pin (ArduPilot Copter-4.7.2, broker/drone/sitl/ardupilot.pin);
// names and value meanings are from that commit's parameter docs (ASSUMPTIONS.md).
const (
	fenceTypeAltMaxPolygon = 1 | 4  // FENCE_TYPE bits: 0 max altitude, 2 polygon
	fenceActionRTLOrLand   = 1      // FENCE_ACTION 1: RTL, or land if RTL is not possible
	battFSRTL              = 2      // BATT_FS_LOW_ACT 2: RTL
	gcsFSRTL               = 1      // FS_GCS_ENABLE 1: RTL
	ekfFSLand              = 1      // FS_EKF_ACTION 1: land
	skipRCChecks           = 1 << 6 // ARMING_SKIPCHK bit 6: RC channels (there is no receiver)
	gcsSysID               = 255    // MAV_GCS_SYSID: the key-holder's system id
)

// Derive is the one pure function from a policy to the aircraft's plan
// (brief decision 5). It is called only on a policy LoadPolicy returned.
func Derive(p *Policy) Plan {
	rtlAltM := math.Floor(p.CeilingM - 2*p.FenceMarginM)
	params := map[string]float64{
		"FENCE_ENABLE":     1,
		"FENCE_TYPE":       fenceTypeAltMaxPolygon,
		"FENCE_ACTION":     fenceActionRTLOrLand,
		"FENCE_ALT_MAX":    p.CeilingM,
		"FENCE_MARGIN":     p.FenceMarginM,
		"FENCE_AUTOENABLE": 0, // the fence is always on, never enabled by arming or take-off
		"BATT_LOW_VOLT":    p.LowBatteryV,
		"BATT_FS_LOW_ACT":  battFSRTL,
		"FS_GCS_ENABLE":    gcsFSRTL,
		"FS_GCS_TIMEOUT":   p.LostLinkS,
		"FS_EKF_ACTION":    ekfFSLand,
		"FS_THR_ENABLE":    0, // no receiver, so no radio failsafe; lost link is FS_GCS
		"RC_PROTOCOLS":     0, // no RC protocol is decoded: RC is an unsigned control path
		"ARMING_SKIPCHK":   skipRCChecks,
		"SCR_ENABLE":       0, // no Lua scripting: scripts are code the signature does not cover
		"RTL_ALT_M":        rtlAltM,
		"RALLY_INCL_HOME":  0, // return goes to the dock rally point, not to wherever it armed
		"RALLY_LIMIT_KM":   0,
		"MAV_SYSID":        targetSysID,
		"MAV_GCS_SYSID":    gcsSysID,
		"MAV_GCS_SYSID_HI": 0, // below MAV_GCS_SYSID: only MAV_GCS_SYSID is a ground station
		"MAV_OPTIONS":      1, // bit 0: accept MAVLink only from MAV_GCS_SYSID
		// MAVn_OPTIONS bit 0 turns signing off on a port. SITL has three MAVLink
		// ports; DRONE-enforcer sets the airframe's count (ASSUMPTIONS.md).
		"MAV1_OPTIONS": 0,
		"MAV2_OPTIONS": 0,
		"MAV3_OPTIONS": 0,
	}
	plan := Plan{}
	for name, v := range params {
		plan.Params = append(plan.Params, Param{name, float32(v)})
	}
	sort.Slice(plan.Params, func(i, j int) bool { return plan.Params[i].Name < plan.Params[j].Name })
	for _, q := range p.Boundary {
		plan.Fence = append(plan.Fence, Item{Command: cmdFenceInclusion, Param1: float32(len(p.Boundary)), Lat: e7(q.Lat), Lon: e7(q.Lon)})
	}
	for _, z := range p.NoFly {
		for _, q := range z {
			plan.Fence = append(plan.Fence, Item{Command: cmdFenceExclusion, Param1: float32(len(z)), Lat: e7(q.Lat), Lon: e7(q.Lon)})
		}
	}
	plan.Rally = []Item{{Command: cmdRallyPoint, Lat: e7(p.Dock.Lat), Lon: e7(p.Dock.Lon), AltM: float32(rtlAltM)}}
	return plan
}

func e7(deg float64) int32 { return int32(math.Round(deg * 1e7)) }

// ReadBackNames are the parameters read back after every load and at every
// boot: the plan's, which include SCR_ENABLE and RC_PROTOCOLS (brief decision 4).
func (pl Plan) ReadBackNames() []string {
	out := make([]string, len(pl.Params))
	for i, p := range pl.Params {
		out[i] = p.Name
	}
	return out
}
