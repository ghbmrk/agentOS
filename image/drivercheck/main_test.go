package main

import (
	"strings"
	"testing"
)

// REQ: DEV-1, DEV-4
const decl = `{"Device":"scale","Link":"tcp","Channels":[{"Name":"stream","Port":8080}],` +
	`"Shapes":[{"Name":"get","Channel":"stream","Kind":"tcp-frame","Prefix":"AQ==","Min":1,"Max":1}],` +
	`"Operations":[{"Name":"weigh","Verb":"read","Shapes":["get"]}],"Readings":["mass"],"MaxRead":64,"MaxReadings":4}`

func TestCheckCanonical(t *testing.T) {
	out, err := check([]byte(`{"declaration":` + decl + `,"classes":{"weigh":"read"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"Prefix":"AQ=="`) || !strings.Contains(string(out), `"Service":""`) {
		t.Fatalf("not encoding/json's form of devslot.Declaration: %s", out)
	}
}

func TestCheckRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"verb outside DEV-4": `{"declaration":` + strings.Replace(decl, `"Verb":"read"`, `"Verb":"exec"`, 1) + `,"classes":{"weigh":"read"}}`,
		"unknown field":      `{"declaration":` + strings.Replace(decl, `"MaxRead"`, `"Host":"x","MaxRead"`, 1) + `,"classes":{"weigh":"read"}}`,
		"class not DEV-4":    `{"declaration":` + decl + `,"classes":{"weigh":"exec"}}`,
		"class row missing":  `{"declaration":` + decl + `,"classes":{}}`,
		"class row extra":    `{"declaration":` + decl + `,"classes":{"weigh":"read","other":"read"}}`,
		"class row other op": `{"declaration":` + decl + `,"classes":{"other":"read"}}`,
		"trailing data":      `{"declaration":` + decl + `,"classes":{"weigh":"read"}} {}`,
		"unknown link kind":  `{"declaration":` + strings.Replace(decl, `"Link":"tcp"`, `"Link":"udp"`, 1) + `,"classes":{"weigh":"read"}}`,
	} {
		if _, err := check([]byte(in)); err == nil {
			t.Errorf("%s: passed", name)
		}
	}
}
