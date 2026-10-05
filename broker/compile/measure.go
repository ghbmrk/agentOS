package compile

import (
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/skill"
)

// Speedup is A10's second-run measure for one active skill: how long the
// model took for the task before the skill (model runs) against how long
// the skill took (skill runs). Spans run from the first effect's submit to
// the last effect's outcome, from journal timestamps.
type Speedup struct {
	Skill       string        `json:"skill"`
	ModelRuns   int           `json:"model_runs"`
	ModelMedian time.Duration `json:"model_median"`
	SkillRuns   int           `json:"skill_runs"` // runs that finished every step
	SkillMedian time.Duration `json:"skill_median"`
	// Stopped counts skill runs that handed back to the model (an
	// assumption failed); they are not in SkillRuns or SkillMedian.
	Stopped int `json:"stopped"`
	// Ratio is ModelMedian / SkillMedian; 0 until both sides have a run.
	Ratio float64 `json:"ratio"`
}

// Measure reports a Speedup for every skill in active (the active tree's
// skills namespace). Model runs are successful, owner-accepted
// trajectories of the skill's shape with no skill step in them, from any
// split (measuring builds nothing). Skill runs are grouped by the request
// IDs the runner gives its steps (skill.RequestID), so they need no goal.
func (c *Compiler) Measure(active change.Tree) []Speedup {
	byID := map[string]*Speedup{}
	steps := map[string]int{}
	for p, b := range active {
		if !strings.HasPrefix(p, skill.SkillsNS+"/") {
			continue
		}
		sk, err := skill.Decode(b)
		if err != nil || sk.Kind != skill.KindSkill {
			continue
		}
		byID[sk.ID] = &Speedup{Skill: sk.ID}
		steps[sk.ID] = len(sk.Steps)
	}
	model := map[string][]time.Duration{}
	for _, t := range trajectories(c.cfg.Journal, c.cfg.Group, c.cfg.OwnerSource, nil) {
		if !t.Succeeded || !t.Good || hasSkillStep(t.Intents) {
			continue
		}
		id := "k" + Shape(t)
		if byID[id] != nil {
			model[id] = append(model[id], t.Span())
		}
	}
	type run struct {
		start, end time.Time
		ok         map[int]bool
		bad        bool
	}
	runs := map[string]map[string]*run{}
	sts := map[string]journal.Status{}
	for _, s := range c.cfg.Journal.List() {
		sts[s.Intent.ID] = s
	}
	runOf := map[string]*run{}
	for _, r := range c.cfg.Journal.Trail() {
		switch r.Type {
		case journal.RecSubmitted:
			if r.Intent == nil {
				continue
			}
			sid, rid, n, ok := skill.ParseRequestID(r.ID[strings.LastIndex(r.ID, "/")+1:])
			if !ok || byID[sid] == nil {
				continue
			}
			if runs[sid] == nil {
				runs[sid] = map[string]*run{}
			}
			key := r.Intent.Origin + "\x00" + rid
			ru := runs[sid][key]
			if ru == nil {
				ru = &run{start: r.At, end: r.At, ok: map[int]bool{}}
				runs[sid][key] = ru
			}
			runOf[r.ID] = ru
			if st := sts[r.ID]; st.State == journal.Succeeded {
				ru.ok[n] = true
			} else {
				ru.bad = true
			}
		case journal.RecObserved, journal.RecDenied, journal.RecRecheckFailed:
			if ru := runOf[r.ID]; ru != nil && r.At.After(ru.end) {
				ru.end = r.At
			}
		}
	}
	var out []Speedup
	for id, sp := range byID {
		sp.ModelRuns = len(model[id])
		sp.ModelMedian = median(model[id])
		var spans []time.Duration
		for _, ru := range runs[id] {
			if ru.bad || len(ru.ok) != steps[id] {
				sp.Stopped++
				continue
			}
			spans = append(spans, ru.end.Sub(ru.start))
		}
		sp.SkillRuns = len(spans)
		sp.SkillMedian = median(spans)
		if sp.ModelRuns > 0 && sp.SkillRuns > 0 {
			sp.Ratio = float64(sp.ModelMedian) / float64(max(sp.SkillMedian, time.Millisecond))
		}
		out = append(out, *sp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Skill < out[j].Skill })
	return out
}

func hasSkillStep(ids []string) bool {
	for _, id := range ids {
		if _, _, _, ok := skill.ParseRequestID(id[strings.LastIndex(id, "/")+1:]); ok {
			return true
		}
	}
	return false
}

func median(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}
