package planquota

import (
	"errors"
	"testing"
	"time"
)

// REQ: RES-5

func TestRES5AdmitRefusesPastReserve(t *testing.T) {
	g := New()
	g.Set(Pool{ID: "five_hour", Used: 0.9, Reserve: 0.2, Reset: time.Unix(2e9, 0)})
	if err := g.Admit([]string{"five_hour"}, false); err == nil {
		t.Fatal("admitted past reserve")
	} else if r, ok := err.(Refusal); !ok || r.Reason != "at_reserve" {
		t.Fatalf("want at_reserve, got %v", err)
	}
	g.Set(Pool{ID: "five_hour", Used: 0.7, Reserve: 0.2, Reset: time.Unix(2e9, 0)})
	if err := g.Admit([]string{"five_hour"}, false); err != nil {
		t.Fatal(err)
	}
	g.Release([]string{"five_hour"})
}

func TestRES5SpareRespectsForecast(t *testing.T) {
	g := New()
	g.Set(Pool{ID: "week", Used: 0.5, Reserve: 0, Forecast: 0.5, Reset: time.Unix(2e9, 0)})
	if err := g.Admit([]string{"week"}, true); !errors.As(err, new(Refusal)) {
		t.Fatalf("spare should wait on forecast: %v", err)
	}
	if err := g.Admit([]string{"week"}, false); err != nil {
		t.Fatal(err)
	}
	g.Release([]string{"week"})
}

func TestRES5ConcurrencyCapDefault2(t *testing.T) {
	g := New()
	g.Set(Pool{ID: "codex", Used: 0.1, Reserve: 0})
	if err := g.Admit([]string{"codex"}, false); err != nil {
		t.Fatal(err)
	}
	if err := g.Admit([]string{"codex"}, false); err != nil {
		t.Fatal(err)
	}
	err := g.Admit([]string{"codex"}, false)
	var r Refusal
	if !errors.As(err, &r) || r.Reason != "concurrency_full" {
		t.Fatalf("want concurrency_full, got %v", err)
	}
	g.Release([]string{"codex"})
	if err := g.Admit([]string{"codex"}, false); err != nil {
		t.Fatal(err)
	}
}

func TestRES5FailoverCooldownIsPoolReset(t *testing.T) {
	g := New()
	a := time.Unix(2e9, 0)
	b := a.Add(time.Hour)
	g.Set(Pool{ID: "a", Used: 1, Reserve: 0, Reset: b})
	g.Set(Pool{ID: "b", Used: 1, Reserve: 0, Reset: a})
	if got := g.Cooldown([]string{"a", "b"}); !got.Equal(a) {
		t.Fatalf("cooldown %v, want %v", got, a)
	}
}
