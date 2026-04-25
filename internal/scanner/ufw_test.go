package scanner

import (
	"testing"

	"secscore/internal/model"
)

func TestParseUFWOutput_Active(t *testing.T) {
	raw := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] Anywhere on lo             ALLOW IN    Anywhere
[ 2] Anywhere                   ALLOW OUT   Anywhere on lo             (out)
[ 3] 80/tcp                     ALLOW IN    Anywhere                   # HTTP
[ 4] 443/tcp                    ALLOW IN    Anywhere                   # HTTPS
[ 5] 7777/tcp                   ALLOW IN    Anywhere                   # tollgate
[ 6] 5353/udp                   DENY IN     Anywhere                   # block mDNS
[ 7] 22/tcp                     ALLOW IN    Anywhere                   # SSH
[ 8] 22/tcp (v6)                ALLOW IN    Anywhere (v6)              # SSH
`

	status, rules := parseUFWOutput(raw)

	if status != model.UFWActive {
		t.Errorf("expected active, got %q", status)
	}

	// Should parse numbered rules, skip header/loopback lines
	if len(rules) == 0 {
		t.Fatal("expected rules, got none")
	}

	// Find 22/tcp ALLOW
	found22 := false
	for _, r := range rules {
		if r.Port == 22 && r.Proto == "tcp" && r.Action == "ALLOW" {
			found22 = true
		}
	}
	if !found22 {
		t.Errorf("expected 22/tcp ALLOW rule, rules: %+v", rules)
	}

	// Find 5353/udp DENY
	found5353 := false
	for _, r := range rules {
		if r.Port == 5353 && r.Proto == "udp" && r.Action == "DENY" {
			found5353 = true
		}
	}
	if !found5353 {
		t.Errorf("expected 5353/udp DENY rule, rules: %+v", rules)
	}
}

func TestParseUFWOutput_Inactive(t *testing.T) {
	raw := "Status: inactive\n"
	status, rules := parseUFWOutput(raw)

	if status != model.UFWInactive {
		t.Errorf("expected inactive, got %q", status)
	}
	if len(rules) != 0 {
		t.Errorf("expected no rules for inactive ufw, got %d", len(rules))
	}
}

func TestParseUFWOutput_EmptyBody(t *testing.T) {
	raw := "Status: active\n"
	status, rules := parseUFWOutput(raw)

	if status != model.UFWActive {
		t.Errorf("expected active, got %q", status)
	}
	if len(rules) != 0 {
		t.Errorf("expected no rules, got %d", len(rules))
	}
}

func TestParseUFWToField(t *testing.T) {
	cases := []struct {
		input     string
		wantPort  int
		wantProto string
	}{
		{"22/tcp", 22, "tcp"},
		{"443/tcp", 443, "tcp"},
		{"5353/udp", 5353, "udp"},
		{"80", 80, "any"},
		{"Anywhere", 0, "any"},
		{"8080/tcp", 8080, "tcp"},
	}

	for _, c := range cases {
		port, proto := parseUFWToField(c.input)
		if port != c.wantPort || proto != c.wantProto {
			t.Errorf("parseUFWToField(%q): got port=%d proto=%q, want port=%d proto=%q",
				c.input, port, proto, c.wantPort, c.wantProto)
		}
	}
}

func TestUFWAllowsPort(t *testing.T) {
	rules := []model.UFWRule{
		{Port: 22, Proto: "tcp", Action: "ALLOW", From: "Anywhere"},
		{Port: 443, Proto: "tcp", Action: "ALLOW", From: "Anywhere"},
		{Port: 5353, Proto: "udp", Action: "DENY", From: "Anywhere"},
	}

	if !UFWAllowsPort(rules, 22, "tcp") {
		t.Error("expected port 22/tcp to be allowed")
	}
	if UFWAllowsPort(rules, 5353, "udp") {
		t.Error("expected port 5353/udp to NOT be allowed (DENY rule)")
	}
	if UFWAllowsPort(rules, 9999, "tcp") {
		t.Error("expected port 9999/tcp to NOT be allowed (no rule)")
	}
}
