package vision

import (
	"errors"
	"slices"
	"strings"
)

// A planner's asks of VIS-core (DEV-7, D-207; brief design point 4). A
// planner sees only track-level outputs: zone entries, dwell, counts and
// closed-vocabulary classes, which part (b) declares in PlannerOps. An Ask
// has no field that can hold a crop, a frame or an encoding: its camera
// and zone are ids from a closed alphabet and its class is from the
// closed list. Op is a free string, but CheckAsk passes only an exact
// member of PlannerOps, so no ask can carry a person's likeness
// in, and none is answered with one: crops and boxes go only to the
// owner's own page (brief points 2 and 4).

// Ask is one planner request of VIS-core.
type Ask struct {
	Op     string
	Camera string
	Zone   string
	Class  Class
}

// PlannerOps are the asks a planner may make. Part (c) declares none;
// part (b) adds its track-level outputs, none of which compares a person.
var PlannerOps = []string{}

// matchOps are the ops a planner would use to find or match a person
// across captures. None is ever offered, so asking for one gets its own
// closed reason, ErrNoMatch, not ErrNotOffered.
var matchOps = []string{"find", "match", "search", "identify", "reidentify", "compare", "lookup", "similar", "follow", "who"}

// The closed reasons an Ask is refused with.
var (
	ErrNoMatch    = errors.New("vision: finding or matching a person who isn't enrolled is not offered (DEV-7)")
	ErrNotOffered = errors.New("vision: that ask is not offered to a planner")
)

// CheckAsk refuses every ask that is not a declared planner op on a valid
// camera, zone and class, and an ask whose op has a word of matchOps
// ("find the man in the red jacket") with ErrNoMatch.
func CheckAsk(a Ask) error {
	words := strings.FieldsFunc(strings.ToLower(a.Op), func(r rune) bool { return r < 'a' || r > 'z' })
	for _, w := range words {
		if slices.Contains(matchOps, w) {
			return ErrNoMatch
		}
	}
	if !slices.Contains(PlannerOps, a.Op) || !validName(a.Camera) || a.Zone != "" && !validName(a.Zone) || a.Class != "" && !a.Class.Known() {
		return ErrNotOffered
	}
	return nil
}

// validName is a camera or zone id: as an enrolment id, 1 to 32 of
// [a-z0-9-], so no description fits in one.
func validName(s string) bool { return ValidEnrolledID(s) }
