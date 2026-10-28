package vision

// REQ: DEV-7

import (
	"errors"
	"reflect"
	"testing"
)

// A planner cannot ask VIS-core to find or match a person who isn't
// enrolled: not by crop or frame (an Ask has no field to hold one), not by
// description, and not by track; each is refused with a closed reason. A
// declared op still takes only ids and a class, so no description rides
// in on its camera or zone (DEV-7, D-207).
func TestPlannerCannotMatchUnknown(t *testing.T) {
	ty := reflect.TypeOf(Ask{})
	for i := range ty.NumField() {
		if k := ty.Field(i).Type.Kind(); k != reflect.String {
			t.Fatalf("Ask.%s is a %s: a field that could hold a crop or an encoding", ty.Field(i).Name, k)
		}
	}
	for _, a := range []Ask{
		{Op: "match", Camera: "front-door"},
		{Op: "find", Camera: "front-door", Class: Person},
		{Op: "Find the man in the red jacket"},
		{Op: "search-captures", Zone: "driveway"},
		{Op: "follow", Camera: "front-door"}, // a track, across cameras
		{Op: "who-is", Camera: "front-door"},
		{Op: "compare_faces"},
	} {
		if err := CheckAsk(a); !errors.Is(err, ErrNoMatch) {
			t.Errorf("%+v: %v", a, err)
		}
	}
	defer func(ops []string) { PlannerOps = ops }(PlannerOps)
	PlannerOps = []string{"zone-entries"}
	if err := CheckAsk(Ask{Op: "zone-entries", Camera: "front-door", Zone: "driveway", Class: Person}); err != nil {
		t.Fatalf("a declared ask: %v", err)
	}
	for _, a := range []Ask{
		{Op: "crops", Camera: "front-door"},
		{Op: "zone-entries", Camera: "man in a red jacket"},
		{Op: "zone-entries", Camera: "front-door", Zone: "near the tall man"},
		{Op: "zone-entries", Camera: "front-door", Class: "tall man"},
		{Op: "zone-entries"},
	} {
		if err := CheckAsk(a); !errors.Is(err, ErrNotOffered) {
			t.Errorf("%+v: %v", a, err)
		}
	}
}

// Part (c) offers planners nothing: every ask is refused until part (b)
// declares its track-level outputs.
func TestNoPlannerOpsYet(t *testing.T) {
	if len(PlannerOps) != 0 {
		t.Fatalf("planner ops %v, but none is built", PlannerOps)
	}
}
