package compile

// REQ: CAP-5

import (
	"encoding/json"
	"testing"
)

// CAP-5 (P3-6e, security R1 on #74): a skill or procedure file's own
// steps give back the shape it was compiled from, so Loop 1 can check a
// supersede against the file's content instead of its name.
func TestSkillShapeMatchesTrajectoryShape(t *testing.T) {
	num := func(s string) json.Number { return json.Number(s) }
	run := func(to, subject string, n json.Number, urgent bool) *Trajectory {
		return &Trajectory{Steps: []Step{
			{Account: "mail", Action: "draft", Params: map[string]any{
				"subject": subject,
				"body":    map[string]any{"text": "Weekly report", "size": n, "tags": []any{"a", "b"}},
				"urgent":  urgent,
				"cc":      nil,
			}, Recipients: []string{to}},
			{Account: "mail", Action: "send", Params: map[string]any{
				"draft": map[string]any{"ref": "d1", "opts": map[string]any{"Odd Key": 1}},
				"empty": map[string]any{},
			}},
		}}
	}
	ts := []*Trajectory{
		run("a@example.test", "Week 1", num("1"), true),
		run("b@example.test", "Week 2", num("2.5"), false),
		run("c@example.test", "Week 3", num("3"), true),
	}
	shape := Shape(ts[0])
	for _, tr := range ts[1:] {
		if Shape(tr) != shape {
			t.Fatal("fixture runs differ in shape")
		}
	}
	sk := Compile(shape, ts)
	if sk == nil {
		t.Fatal("fixture did not compile")
	}
	if got := sk.Shape(); got != shape {
		t.Errorf("skill shape %s, compiled from %s", got, shape)
	}
	// A procedure has no literal, so no null.
	for _, tr := range ts {
		delete(tr.Steps[0].Params, "cc")
	}
	shape = Shape(ts[0])
	pr := Procedure(shape, ts)
	if pr == nil {
		t.Fatal("fixture did not record a procedure")
	}
	if got := pr.Shape(); got != shape {
		t.Errorf("procedure shape %s, recorded from %s", got, shape)
	}

	// A different task (one more recipient) has a different shape.
	other := []*Trajectory{run("a@example.test", "x", num("1"), true)}
	other[0].Steps[0].Recipients = append(other[0].Steps[0].Recipients, "d@example.test")
	delete(other[0].Steps[0].Params, "cc")
	if op := Procedure(Shape(other[0]), other); op == nil || op.Shape() == shape {
		t.Error("a different task gave the same shape")
	}
}
