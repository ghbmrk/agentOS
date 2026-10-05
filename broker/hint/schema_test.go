package hint

import (
	"errors"
	"strings"
	"testing"
)

// REQ: OSS-1, OSS-5

// TestOSS1PublicSchemaLoads: the schema the box ships is the embedded,
// public schema.json, and it passes every structural rule.
func TestOSS1PublicSchemaLoads(t *testing.T) {
	s := Default()
	if s.Version() != 1 {
		t.Fatalf("version %d", s.Version())
	}
	for _, k := range []string{"skill_gap", "vuln", "adapter_gap"} {
		if _, ok := s.kinds[k]; !ok {
			t.Fatalf("kind %s missing", k)
		}
	}
	if b := s.MaxBits(); b <= 0 || b > MaxBitsPerHint {
		t.Fatalf("max bits %v", b)
	}
}

// TestOSS5VulnHintsAreEmbargoed: security hints are marked for the
// embargoed path in the schema itself, so the private side cannot choose
// otherwise.
func TestOSS5VulnHintsAreEmbargoed(t *testing.T) {
	s := Default()
	if !s.kinds["vuln"].Embargo {
		t.Fatal("vuln is not embargoed")
	}
	if s.kinds["skill_gap"].Embargo {
		t.Fatal("skill_gap is embargoed")
	}
}

// TestOSS1SchemaRules: a schema that would let a hint carry a number, free
// text, an identifier-shaped value, a sensitive life domain, or more than
// MaxBitsPerHint bits is refused at load, so it can never be shipped.
func TestOSS1SchemaRules(t *testing.T) {
	ok := `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["aa","bb"]}}}}`
	if _, err := Parse([]byte(ok)); err != nil {
		t.Fatalf("minimal schema: %v", err)
	}
	many := make([]string, 0, 300)
	for i := 0; i < 300; i++ {
		many = append(many, `"v`+string(rune('a'+i%26))+string(rune('a'+i/26))+`"`)
	}
	bad := map[string]string{
		"digit in value":       `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["a1","bb"]}}}}`,
		"upper case":           `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["Aa","bb"]}}}}`,
		"space":                `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["a a","bb"]}}}}`,
		"empty value":          `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["","bb"]}}}}`,
		"long value":           `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["` + strings.Repeat("a", 33) + `","bb"]}}}}`,
		"trailing underscore":  `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["aa_","bb"]}}}}`,
		"one value":            `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["aa"]}}}}`,
		"duplicate value":      `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["aa","aa"]}}}}`,
		"no fields":            `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{}}}}`,
		"unknown category":     `{"version":1,"categories":["c"],"kinds":{"k":{"category":"d","fields":{"f":["aa","bb"]}}}}`,
		"bad kind name":        `{"version":1,"categories":["c"],"kinds":{"K9":{"category":"c","fields":{"f":["aa","bb"]}}}}`,
		"bad field name":       `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f 1":["aa","bb"]}}}}`,
		"bad category name":    `{"version":1,"categories":["C"],"kinds":{"k":{"category":"C","fields":{"f":["aa","bb"]}}}}`,
		"unknown key":          `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","note":"x","fields":{"f":["aa","bb"]}}}}`,
		"no kinds":             `{"version":1,"categories":["c"],"kinds":{}}`,
		"no version":           `{"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["aa","bb"]}}}}`,
		"too many bits":        `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":[` + strings.Join(many, ",") + `],"g":[` + strings.Join(many, ",") + `]}}}}`,
		"trailing data":        ok + `{}`,
		"duplicate category":   `{"version":1,"categories":["c","c"],"kinds":{"k":{"category":"c","fields":{"f":["aa","bb"]}}}}`,
		"unused category":      `{"version":1,"categories":["c","d"],"kinds":{"k":{"category":"c","fields":{"f":["aa","bb"]}}}}`,
		"duplicate kind (key)": `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["aa","bb"]}},"k":{"category":"c","fields":{"f":["aa","cc"]}}}}`,
	}
	for _, w := range []string{"medical", "health_portal", "legal", "religious_org", "benefits"} {
		bad["sensitive "+w] = `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"f":["aa","` + w + `"]}}}}`
	}
	for name, src := range bad {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestOSS1FrequencyIsComputed: the frequency value is computed by the
// broker from journaled counts with the bucket edges the public schema
// declares, never chosen by a machine (K1).
func TestOSS1FrequencyIsComputed(t *testing.T) {
	s := Default()
	for _, tc := range []struct {
		n, tasks int
		want     string
	}{
		{1, 1, "once"}, {1, 40, "once"}, {2, 40, "sometimes"}, {19, 40, "sometimes"},
		{20, 40, "most_tasks"}, {40, 40, "most_tasks"}, {2, 3, "most_tasks"},
	} {
		got, err := s.Frequency(tc.n, tc.tasks)
		if err != nil || got != tc.want {
			t.Errorf("Frequency(%d, %d) = %q, %v; want %q", tc.n, tc.tasks, got, err, tc.want)
		}
	}
	for _, tc := range [][2]int{{0, 5}, {6, 5}, {-1, 5}, {1, 0}} {
		if _, err := s.Frequency(tc[0], tc[1]); !errors.Is(err, ErrInvalid) {
			t.Errorf("Frequency(%d, %d): %v", tc[0], tc[1], err)
		}
	}
	// A frequency field needs the declared edges and exactly the three
	// bucket values; edges must be sane.
	for name, src := range map[string]string{
		"no edges":     `{"version":1,"categories":["c"],"kinds":{"k":{"category":"c","fields":{"frequency":["once","sometimes","most_tasks"]}}}}`,
		"other values": `{"version":1,"frequency_edges":{"once_max_count":1,"most_tasks_min_percent":50},"categories":["c"],"kinds":{"k":{"category":"c","fields":{"frequency":["rare","often"]}}}}`,
		"bad percent":  `{"version":1,"frequency_edges":{"once_max_count":1,"most_tasks_min_percent":101},"categories":["c"],"kinds":{"k":{"category":"c","fields":{"frequency":["once","sometimes","most_tasks"]}}}}`,
		"bad count":    `{"version":1,"frequency_edges":{"once_max_count":0,"most_tasks_min_percent":50},"categories":["c"],"kinds":{"k":{"category":"c","fields":{"frequency":["once","sometimes","most_tasks"]}}}}`,
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
