package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// Synthetic canaries only: no real token appears here.
var (
	canaryJWT = b64(`{"alg":"RS256","typ":"JWT","kid":"CANARYKID0001"}`) + "." +
		b64(`{"email":"canary@example.invalid","sub":"CANARYSUB0001"}`) + ".CANARYSIGNATUREabcdefghijklmnop"
	canaryRT  = "rt_qzvwkxq0123456789zzqqvvkk.CANARYTAIL0001"
	canaryKey = "sk-proj-CANARYAPIKEY0123456789abcdefghij"
	canaryOdd = "CANARYOPAQUE0123456789abcdefghijklmn"
)

func sample() []byte {
	b, _ := json.Marshal(map[string]any{
		"auth_mode":      "chatgpt",
		"OPENAI_API_KEY": canaryKey,
		"last_refresh":   "2026-10-18T12:00:00Z",
		"tokens": map[string]any{"id_token": canaryJWT, "access_token": canaryJWT,
			"refresh_token": canaryRT, "account_id": canaryOdd, "spare": nil},
	})
	return b
}

// No value, and no 6-byte window of one past its public prefix, appears in the output.
func TestOutputHoldsNoValue(t *testing.T) {
	o, err := run(sample())
	if err != nil {
		t.Fatal(err)
	}
	out := string(o)
	for _, v := range []string{canaryJWT, canaryRT, canaryKey, canaryOdd, "canary@example.invalid", "CANARYKID0001", "2026-10-18T12"} {
		rest := v
		for _, p := range prefixes {
			rest = strings.TrimPrefix(rest, p)
		}
		for i := 0; i+6 <= len(rest); i++ {
			if strings.Contains(out, rest[i:i+6]) {
				t.Fatalf("output holds %q from a value", rest[i:i+6])
			}
		}
	}
}

func TestShapes(t *testing.T) {
	o, _ := run(sample())
	var r struct{ Fields map[string]json.RawMessage }
	json.Unmarshal(o, &r)
	var rt, key, at, odd Shape
	json.Unmarshal(r.Fields["tokens.refresh_token"], &rt)
	json.Unmarshal(r.Fields["OPENAI_API_KEY"], &key)
	json.Unmarshal(r.Fields["tokens.access_token"], &at)
	json.Unmarshal(r.Fields["tokens.account_id"], &odd)
	if rt.Prefix != "rt_" || rt.Formats["2"] != "full" || rt.Len != len(canaryRT) {
		t.Errorf("refresh shape %+v", rt)
	}
	if key.Prefix != "sk-proj-" || key.Formats["0"] != "full" {
		t.Errorf("key shape %+v", key)
	}
	if at.JWT == nil || at.JWT.Alg != "RS256" || at.JWT.Typ != "JWT" || at.Formats["1"] != "full" ||
		strings.Join(at.JWT.Claims, ",") != "email,sub" {
		t.Errorf("jwt shape %+v %+v", at, at.JWT)
	}
	if odd.Prefix != "none" || odd.Formats["0"] != "none" || odd.Formats["1"] != "none" || odd.Formats["2"] != "none" {
		t.Errorf("opaque shape %+v", odd)
	}
	if string(r.Fields["auth_mode"]) == "" || !strings.Contains(string(r.Fields["auth_mode"]), "chatgpt") {
		t.Errorf("auth_mode %s", r.Fields["auth_mode"])
	}
}

// The formats checked are the Codex declaration's, verbatim.
func TestFormatsMatchDeclaration(t *testing.T) {
	b, err := os.ReadFile("../../../broker/provagent/declare.go")
	if err != nil {
		t.Skip("declare.go not found")
	}
	for _, f := range formats {
		if !strings.Contains(string(b), "`"+f+"`") {
			t.Errorf("declare.go has no format %s", f)
		}
	}
}
